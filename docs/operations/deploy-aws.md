# Guía de despliegue en AWS

Esta guía cubre el despliegue completo de `cai-platform` en una cuenta AWS desde cero usando Terraform. Está dirigida al ingeniero de infraestructura responsable del deploy.

---

## Tabla de contenidos

1. [Prerequisitos](#1-prerequisitos)
2. [Arquitectura desplegada](#2-arquitectura-desplegada)
3. [Paso 1 — Configurar credenciales AWS](#paso-1--configurar-credenciales-aws)
4. [Paso 2 — Habilitar Amazon Bedrock](#paso-2--habilitar-amazon-bedrock)
5. [Paso 3 — Bootstrap (bucket S3 + tabla DynamoDB)](#paso-3--bootstrap-bucket-s3--tabla-dynamodb)
6. [Paso 4 — Configurar Terraform](#paso-4--configurar-terraform)
7. [Paso 5 — Aplicar la infraestructura](#paso-5--aplicar-la-infraestructura)
8. [Paso 6 — Configurar CI/CD (GitHub Actions)](#paso-6--configurar-cicd-github-actions)
9. [Paso 7 — Verificar el despliegue](#paso-7--verificar-el-despliegue)
10. [Referencia de variables](#referencia-de-variables)
11. [Troubleshooting](#troubleshooting)

---

## 1. Prerequisitos

### Herramientas locales

| Herramienta | Versión mínima | Verificar |
|---|---|---|
| Terraform | 1.6+ | `terraform -version` |
| AWS CLI | 2.x | `aws --version` |
| Docker | 24+ | `docker --version` |
| Make | cualquiera | `make --version` |

### Cuenta AWS

- Cuenta AWS activa con acceso de administrador (para el deploy inicial)
- Credenciales configuradas localmente (`~/.aws/credentials` o variables de entorno)
- Amazon Bedrock habilitado en la región destino (ver Paso 2)

---

## 2. Arquitectura desplegada

```
Internet
    │
    ▼
ALB (HTTP:80, security group: cai-platform-alb-sg)
    │  path-based routing
    ├─ /          → platform-api  (ECS Fargate, 0.5 vCPU / 2 GB)
    ├─ /ui/*      → platform-ui   (ECS Fargate, 0.25 vCPU / 512 MB)
    ├─ /staging/* → platform-api-staging  (0 tasks en reposo; CI sube a 1)
    └─ /staging-ui/* → platform-ui-staging (ídem)

ECS Fargate (cluster: cai-platform)
    ├─ platform-api          (puerto 8000) — FastAPI, in-memory store
    ├─ platform-ui           (puerto 8501) — Next.js
    ├─ platform-api-staging  (puerto 8000) — réplica efímera para CI/CD
    └─ platform-ui-staging   (puerto 8501) — réplica efímera para CI/CD

S3 (bucket configurable)
    └─ workspaces/{client_id}/... → logs WatchGuard, artefactos de investigación

ECR
    ├─ {name_prefix}/platform-api
    └─ {name_prefix}/platform-ui

Amazon Bedrock
    └─ Claude 3.5 Haiku (us.anthropic.claude-3-5-haiku-20241022-v1:0)
```

**Lo que Terraform crea automáticamente:**
- VPC default (data source — no se crea, se reutiliza la existente)
- Security groups (`cai-platform-alb-sg`, `cai-platform-api-sg`)
- ALB + listener + 4 target groups (prod y staging, api y ui)
- ECR repos + lifecycle policies
- IAM execution role, task role, usuario `github-ci`
- ECS cluster + log group + task definitions + 4 servicios (prod + staging)
- S3 bucket + public access block + lifecycle de staging
- SNS topic + suscripción email + alarmas CloudWatch + dashboard

**Lo que Terraform NO crea (prerequisitos manuales):**
- El bucket S3 de estado Terraform y la tabla DynamoDB de locks (Paso 3)
- El acceso a Amazon Bedrock (requiere activación en consola)

---

## Paso 1 — Configurar credenciales AWS

```bash
export AWS_ACCESS_KEY_ID=<tu-key>
export AWS_SECRET_ACCESS_KEY=<tu-secret>
export AWS_DEFAULT_REGION=us-east-2   # o la región que elijas

# Verificar
aws sts get-caller-identity
```

El usuario necesita permisos de administrador para el deploy inicial. Después del primer apply, las operaciones de CI/CD usan el usuario `github-ci` con permisos mínimos.

---

## Paso 2 — Habilitar Amazon Bedrock

Bedrock **no se activa automáticamente con Terraform**.

1. Ir a AWS Console → Amazon Bedrock → Model access
2. Seleccionar la región destino (ej. `us-east-2`)
3. Buscar **Anthropic Claude 3.5 Haiku** → "Request access"
4. Aceptar los términos de Anthropic
5. Esperar aprobación (normalmente instantánea)

Modelo usado por la plataforma:
```
bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0
```

---

## Paso 3 — Bootstrap (bucket S3 + tabla DynamoDB)

El bucket S3 y la tabla DynamoDB deben existir **antes** de `terraform init` porque son el propio backend de Terraform.

```bash
# Ajustar WATCHGUARD_S3_BUCKET y WATCHGUARD_S3_REGION según la nueva cuenta
make tf-bootstrap \
  WATCHGUARD_S3_BUCKET=mi-bucket-nuevo \
  WATCHGUARD_S3_REGION=us-east-2
```

Esto crea:
- El bucket S3 (con versionado y cifrado habilitados)
- La tabla DynamoDB `cai-platform-tf-locks` para state locking

> El mismo bucket sirve como backend de Terraform **y** como almacén de workspaces WatchGuard.

---

## Paso 4 — Configurar Terraform

### 4.1 Editar `versions.tf` (backend)

El bloque `backend "s3"` no acepta variables — editar directamente:

```hcl
# infrastructure/terraform/versions.tf
backend "s3" {
  bucket         = "mi-bucket-nuevo"      # ← mismo bucket del Paso 3
  key            = "terraform/cai-platform.tfstate"
  region         = "us-east-2"            # ← región del bucket
  dynamodb_table = "cai-platform-tf-locks"
  encrypt        = true
}
```

### 4.2 Editar `terraform.tfvars`

```hcl
# infrastructure/terraform/terraform.tfvars
environment       = "prod"
aws_region        = "us-east-2"
name_prefix       = "cai-platform"
s3_bucket         = "mi-bucket-nuevo"       # ← mismo bucket del Paso 3
ecr_image_tag     = "latest"
api_desired_count = 1
ui_desired_count  = 1
alert_email       = "ops@tuempresa.com"     # ← email para alarmas CloudWatch
```

---

## Paso 5 — Aplicar la infraestructura

```bash
# Inicializar (descarga providers, conecta al backend S3)
make tf-init

# Previsualizar (sin aplicar)
make tf-plan

# Aplicar
make tf-apply
```

El apply tarda aprox. **3-5 minutos** en su primera ejecución.

### Outputs importantes

Al terminar, Terraform imprime:

```
alb_dns                  = "cai-platform-alb-XXXXXXXX.us-east-2.elb.amazonaws.com"
ecr_platform_api_uri     = "ACCOUNT_ID.dkr.ecr.us-east-2.amazonaws.com/cai-platform/platform-api"
ecr_platform_ui_uri      = "ACCOUNT_ID.dkr.ecr.us-east-2.amazonaws.com/cai-platform/platform-ui"
cloudwatch_dashboard_url = "https://us-east-2.console.aws.amazon.com/cloudwatch/..."
```

Los servicios ECS arrancan con `desired_count = 0` hasta que el CI/CD suba las imágenes (Paso 6). Esto es normal.

---

## Paso 6 — Configurar CI/CD (GitHub Actions)

El workflow `.github/workflows/deploy.yml` automatiza el build, push y deploy en cada push a `main`.

### 6.1 Crear access key para el usuario `github-ci`

Terraform crea el usuario IAM `github-ci` pero no genera la access key (por seguridad). Crearla manualmente:

```bash
aws iam create-access-key --user-name github-ci
```

Guardar `AccessKeyId` y `SecretAccessKey` — solo se muestran una vez.

### 6.2 Configurar GitHub Secrets

GitHub → Settings → Secrets and variables → Actions → New repository secret:

| Secret | Valor |
|---|---|
| `CI_AWS_ACCESS_KEY_ID` | AccessKeyId del paso anterior |
| `CI_AWS_SECRET_ACCESS_KEY` | SecretAccessKey del paso anterior |

### 6.3 Primer deploy

```bash
git push origin main
```

El workflow:
1. Corre los tests Python
2. Build y push de imágenes a ECR (tag: SHA del commit + `latest`)
3. Deploy a staging (`platform-api-staging`, `platform-ui-staging`) → smoke test → scale down
4. Deploy a prod (`platform-api`, `platform-ui`) → smoke test

> **Nota:** Los ECR URIs y el ALB DNS se resuelven dinámicamente en el workflow — no hay valores hardcodeados de cuenta.

---

## Paso 7 — Verificar el despliegue

```bash
ALB=$(terraform -chdir=infrastructure/terraform output -raw alb_dns)

# Health check del API
curl http://$ALB/health
# Esperado: {"status":"ok",...}

# Health check de la UI (Next.js)
curl http://$ALB/ui/api/health
# Esperado: {"status":"ok"}

# Abrir la UI en el navegador
echo "UI: http://$ALB/ui"
```

### Verificar servicios ECS

```bash
aws ecs describe-services \
  --cluster cai-platform \
  --services platform-api platform-ui \
  --query 'services[*].{name:serviceName,running:runningCount,desired:desiredCount}' \
  --output table
```

Ambos deben tener `running == desired`.

### Confirmar suscripción SNS

Llega un email de AWS SNS al `alert_email` configurado con un link "Confirm subscription". Hacer click para activar las alarmas.

---

## Referencia de variables

### `terraform.tfvars` (editar por cuenta)

| Variable | Descripción | Ejemplo |
|---|---|---|
| `name_prefix` | Prefix para todos los recursos AWS | `cai-platform` |
| `environment` | `prod` | `prod` |
| `aws_region` | Región AWS (debe tener Bedrock disponible) | `us-east-2` |
| `s3_bucket` | Bucket S3 para estado Terraform y workspaces | `mi-bucket` |
| `alert_email` | Email para alarmas CloudWatch | `ops@empresa.com` |
| `ecr_image_tag` | Tag de imagen inicial (`latest` siempre funciona) | `latest` |
| `api_desired_count` | Tasks del API en prod | `1` |
| `ui_desired_count` | Tasks de la UI en prod | `1` |

### `versions.tf` (editar el bloque backend)

| Campo | Descripción |
|---|---|
| `bucket` | Nombre del bucket S3 de estado (creado en Paso 3) |
| `region` | Región del bucket |
| `dynamodb_table` | Nombre de la tabla DynamoDB (por defecto `cai-platform-tf-locks`) |

### GitHub Secrets (configurar en el repo)

| Secret | Descripción |
|---|---|
| `CI_AWS_ACCESS_KEY_ID` | Access key del usuario IAM `github-ci` |
| `CI_AWS_SECRET_ACCESS_KEY` | Secret key del usuario IAM `github-ci` |

---

## Troubleshooting

### Los tasks de ECS no arrancan

```bash
# Ver eventos del servicio
aws ecs describe-services \
  --cluster cai-platform --services platform-api \
  --query 'services[0].events[:5]' --output json

# Ver logs del task fallido
aws logs tail /ecs/cai-platform-api --follow
```

**Causas comunes:**
- La imagen ECR no existe todavía → hacer push manualmente o triggear el CI/CD
- Bedrock no está habilitado → ver Paso 2
- El security group no tiene el puerto correcto abierto

### Health check de la UI falla

Verificar que el health check del target group apunte a `/ui/api/health`:
```bash
aws elbv2 describe-target-groups \
  --names cai-platform-ui-tg \
  --query 'TargetGroups[0].HealthCheckPath'
# Esperado: "/ui/api/health"
```

Si aparece `/ui/_stcore/health` (path legacy de Streamlit), corregirlo:
```bash
TG_ARN=$(aws elbv2 describe-target-groups --names cai-platform-ui-tg \
  --query 'TargetGroups[0].TargetGroupArn' --output text)
aws elbv2 modify-target-group --target-group-arn $TG_ARN \
  --health-check-path /ui/api/health
```

### Bedrock devuelve `AccessDeniedException`

El task role tiene el permiso `bedrock:InvokeModel` pero si el modelo no está habilitado en la cuenta, el error persiste. Verificar en la consola que Claude 3.5 Haiku tiene acceso en la región correcta.

### `terraform init` falla: bucket o tabla no encontrados

El bucket S3 y la tabla DynamoDB deben existir antes de `terraform init`. Ejecutar primero `make tf-bootstrap`.

### Alarma `cai-platform-api-task-down` en ALARM sin razón

Container Insights puede no estar habilitado:
```bash
aws ecs update-cluster-settings \
  --cluster cai-platform \
  --settings name=containerInsights,value=enabled \
  --region us-east-2
```

Sin Container Insights la métrica `RunningTaskCount` no existe y la alarma usa `treat_missing_data = breaching`.

### Costos — apagar servicios cuando no se usan

Los servicios ECS cuestan ~$0.30-0.40/día cada uno. Apagarlos:
```bash
make ecs-stop   # scale a 0 (no corre ninguna task)
make ecs-start  # volver a 1
```

El ALB tiene un costo fijo de ~$18/mes independientemente del tráfico.
