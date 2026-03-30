# Subir logs WatchGuard a S3 manualmente

Guía para analistas de EGS cuando el ZIP de logs pesa más de lo que permite la interfaz web (típicamente >200 MB).

---

## Prerequisitos

- AWS CLI instalado (`aws --version`)
- Credenciales AWS configuradas con acceso al bucket `egslatam-cai-dev`:
  ```bash
  aws configure
  # o variables de entorno:
  export AWS_ACCESS_KEY_ID=...
  export AWS_SECRET_ACCESS_KEY=...
  export AWS_DEFAULT_REGION=us-east-2
  ```
- El ZIP de logs exportado desde SharePoint (ej. `8011029C760FA_20251013_20251022.zip`)

---

## Convención de nombres

El `workspace_id` identifica al cliente/período y se usa en toda la investigación. Se extrae del nombre del archivo:

| Archivo | workspace_id |
|---|---|
| `8011029C760FA_20251013_20251022.zip` | `8011029C760FA_20251013_20251022` |
| `PFALIMENTOS_oct2025.zip` | `PFALIMENTOS_oct2025` |

Usar un nombre descriptivo — el agente lo usará en el informe final.

---

## Pasos

### 1. Subir el ZIP

```bash
# Variables
WORKSPACE_ID="8011029C760FA_20251013_20251022"    # <-- editar
ZIP_FILE="/ruta/al/archivo.zip"                    # <-- editar
BUCKET="egslatam-cai-dev"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Subir
aws s3 cp "$ZIP_FILE" \
  "s3://${BUCKET}/workspaces/${WORKSPACE_ID}/input/uploads/${TIMESTAMP}/raw.zip" \
  --region us-east-2

echo "Upload completado:"
echo "s3://${BUCKET}/workspaces/${WORKSPACE_ID}/input/uploads/${TIMESTAMP}/raw.zip"
```

Guardar el URI que imprime el `echo` — lo vas a necesitar en el paso siguiente.

### 2. Verificar que quedó bien

```bash
aws s3 ls "s3://${BUCKET}/workspaces/${WORKSPACE_ID}/input/uploads/" \
  --recursive --human-readable
```

Debería aparecer el archivo con su tamaño real (ej. `1.2 GB`).

### 3. Lanzar la investigación

Una vez subido el ZIP, la investigación se inicia desde la UI o el CLI con el `workspace_id`:

**Desde la UI (Streamlit):**
- Tab "WatchGuard S3 Investigation"
- Escribir el `workspace_id` en el campo correspondiente (no subir archivo)
- Click en Investigar

**Desde el CLI:**
```bash
python3 -m cai_orchestrator run-cai-terminal \
  --client-id "nombre-cliente" \
  --model "bedrock/us.anthropic.claude-haiku-4-5-20251001" \
  --prompt "Analiza el workspace ${WORKSPACE_ID}. Encontrá el ZIP más reciente, creá el caso, stagéalo y generá el informe de incidente."
```

**Desde la terminal CAI interactiva:**
```bash
python3 -m cai_orchestrator run-cai-terminal \
  --client-id "nombre-cliente"
# Luego escribir:
# > Analiza el workspace 8011029C760FA_20251013_20251022
```

---

## Estructura en S3 después del upload

```
s3://egslatam-cai-dev/
└── workspaces/
    └── {workspace_id}/
        └── input/
            └── uploads/
                └── {timestamp}/
                    └── raw.zip        ← lo que subiste
```

Después de que el agente corre staging:
```
s3://egslatam-cai-dev/
└── workspaces/
    └── {workspace_id}/
        ├── input/uploads/{timestamp}/raw.zip
        └── staging/{staging_timestamp}/
            ├── _manifest.json
            ├── traffic/{fecha}/*.csv
            ├── event/{fecha}/*.csv
            └── alarm/{fecha}/*.csv
```

---

## Makefile shortcut

También podés usar el target existente para uploads:

```bash
make upload-workspace \
  ZIP=/ruta/al/archivo.zip \
  WORKSPACE=8011029C760FA_20251013_20251022
```

Esto hace exactamente lo mismo que el paso 1 de arriba.

---

## Troubleshooting

**Error `AccessDenied`:** Verificar que las credenciales AWS tienen `s3:PutObject` sobre `egslatam-cai-dev`.

**El agente dice "no encontró uploads":** El workspace_id que le pasás al agente debe coincidir exactamente con el usado al subir. Verificar con `aws s3 ls s3://egslatam-cai-dev/workspaces/`.

**El staging falla con timeout:** Los ZIPs >3 GB pueden tardar más de 2 minutos en el staging (límite de ECS task). Si falla, verificar los logs del task en CloudWatch: `make ecs-logs`.
