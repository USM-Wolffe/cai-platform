# Guía de despliegue en AWS

Esta guía cubre el despliegue completo de `cai-platform` en una cuenta AWS desde cero usando Terraform. Está dirigida al ingeniero de infraestructura responsable del deploy.

---

## Tabla de contenidos

1. [Prerequisitos](#1-prerequisitos)
2. [Arquitectura que se desplegará](#2-arquitectura-que-se-desplegará)
3. [Paso 1 — Configurar credenciales AWS](#paso-1--configurar-credenciales-aws)
4. [Paso 2 — Habilitar Amazon Bedrock](#paso-2--habilitar-amazon-bedrock)
5. [Paso 3 — Crear recursos de bootstrap](#paso-3--crear-recursos-de-bootstrap)
6. [Paso 4 — Configurar Terraform](#paso-4--configurar-terraform)
7. [Paso 5 — Aplicar la infraestructura](#paso-5--aplicar-la-infraestructura)
8. [Paso 6 — Construir y subir las imágenes Docker](#paso-6--construir-y-subir-las-imágenes-docker)
9. [Paso 7 — Poblar Secrets Manager](#paso-7--poblar-secrets-manager)
10. [Paso 8 — Verificar el despliegue](#paso-8--verificar-el-despliegue)
11. [Paso 9 — Configurar CI/CD (GitHub Actions)](#paso-9--configurar-cicd-github-actions)
12. [Referencia de variables](#referencia-de-variables)
13. [Troubleshooting](#troubleshooting)

---

## 1. Prerequisitos

### Herramientas locales

| Herramienta | Versión mínima | Verificar |
|---|---|---|
| AWS CLI | 2.x | `aws --version` |
| Terraform | 1.6+ | `terraform -version` |
| Docker | 24+ | `docker --version` |
| Python | 3.11+ | `python3 --version` |
| Make | cualquiera | `make --version` |

### Cuenta AWS

- Cuenta AWS activa con acceso de administrador (para el deploy inicial)
- Credenciales configuradas localmente (`~/.aws/credentials` o variables de entorno)
- Bedrock habilitado en la región destino (ver Paso 2)

### Acceso al repositorio

- Acceso de lectura al repositorio `cai-platform` (para clonar y construir imágenes)
- Si se usa CI/CD: acceso de administrador al repositorio GitHub para configurar Secrets

---

## 2. Arquitectura que se desplegará

```
Internet
    │
    ▼
ALB (HTTP:80)
    │  path-based routing
    ├─ /          → platform-api  (ECS Fargate, puerto 8000)
    └─ /ui/*      → platform-ui   (ECS Fargate, puerto 8501)

ECS Fargate (cluster cai-platform)
    ├─ platform-api   (512 CPU, 1024 MB) — FastAPI + PostgreSQL
    └─ platform-ui    (1024 CPU, 2048 MB) — Streamlit + CAI agents

RDS PostgreSQL (db.t3.micro, cifrado KMS)
    └─ base de datos: caiplatform

Secrets Manager
    └─ {name_prefix}/db-credentials → DATABASE_URL para el API

S3 (bucket configurable)
    └─ workspaces/{client_id}/... → logs WatchGuard, artefactos

ECR
    ├─ {name_prefix}/platform-api
    └─ {name_prefix}/platform-ui

Amazon Bedrock
    └─ Claude 3.5 Haiku (us.anthropic.claude-3-5-haiku-20241022-v1:0)
```

**Lo que Terraform crea automáticamente:**
- Security group (puertos 8000 y 8501)
- IAM roles (execution role, task role con permisos Bedrock+S3)
- IAM user `github-ci` con política acotada para CI/CD
- CloudWatch log group + dashboard + alarmas SNS
- Todo lo listado arriba

**Lo que Terraform NO crea (prerequisitos):**
- La cuenta AWS y sus credenciales
- La VPC (usa la VPC default de la cuenta)
- El bucket S3 de estado de Terraform
- La tabla DynamoDB de locks de Terraform
- El acceso a Bedrock (requiere activación manual en consola)

---

## Paso 1 — Configurar credenciales AWS

```bash
# Opción A: variables de entorno (recomendado para CI)
export AWS_ACCESS_KEY_ID=<tu-key>
export AWS_SECRET_ACCESS_KEY=<tu-secret>
export AWS_DEFAULT_REGION=us-east-2   # o la región que elijas

# Opción B: perfil nombrado
aws configure --profile cai-platform
export AWS_PROFILE=cai-platform

# Verificar que las credenciales funcionan
aws sts get-caller-identity
```

El usuario IAM que ejecuta el deploy necesita permisos amplios (administrador o equivalente) para crear los recursos por primera vez. Una vez desplegado, las operaciones del día a día usan el usuario `github-ci` con permisos mínimos.

---

## Paso 2 — Habilitar Amazon Bedrock

Bedrock requiere activación manual en la consola AWS. **No es automático con Terraform.**

1. Ir a [AWS Console → Amazon Bedrock → Model access](https://console.aws.amazon.com/bedrock/home#/modelaccess)
2. Seleccionar la región destino (ej. `us-east-2`)
3. Buscar **Anthropic Claude 3.5 Haiku** y hacer click en "Request access"
4. Aprobar los términos de uso de Anthropic
5. Esperar la aprobación (normalmente instantánea para cuentas verificadas)

El modelo que usa la plataforma es:
```
bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0
```

> **Nota:** Si la región destino no tiene este modelo disponible, cambiar `CAI_MODEL` en `terraform.tfvars` por el modelo equivalente disponible. Verificar en [Supported models by region](https://docs.aws.amazon.com/bedrock/latest/userguide/models-regions.html).

---

## Paso 3 — Crear recursos de bootstrap

Estos recursos deben existir antes de ejecutar `terraform init`. No puede crearlos Terraform porque son su propio backend.

### 3.1 Bucket S3 para estado de Terraform

```bash
# Reemplazar <region> y <nombre-bucket> según la cuenta
aws s3 mb s3://<nombre-bucket> --region <region>

# Habilitar versionado (recomendado para estado de Terraform)
aws s3api put-bucket-versioning \
  --bucket <nombre-bucket> \
  --versioning-configuration Status=Enabled

# Ejemplo para la cuenta EGS:
# aws s3 mb s3://egslatam-cai-dev --region us-east-2
```

El bucket también se usará para los workspaces de WatchGuard. El mismo bucket sirve para ambos propósitos.

### 3.2 Tabla DynamoDB para locks de Terraform

```bash
# El Makefile incluye este comando como target
make tf-locks-table

# Equivalente manual:
aws dynamodb create-table \
  --table-name cai-platform-tf-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region <region>
```

> Si el `name_prefix` de la instalación es diferente a `cai-platform`, el nombre de la tabla puede ser cualquiera — lo importante es que coincida con lo que se ponga en `backend.tf`.

---

## Paso 4 — Configurar Terraform

### 4.1 Editar `backend.tf`

El backend de Terraform **no acepta variables** — estos valores son literales y deben editarse directamente.

```hcl
# infrastructure/terraform/backend.tf
backend "s3" {
  bucket         = "<nombre-bucket-del-paso-3>"   # ← editar
  key            = "terraform/cai-platform.tfstate"
  region         = "<region>"                      # ← editar
  dynamodb_table = "cai-platform-tf-locks"         # ← editar si cambió el nombre
  encrypt        = true
}
```

### 4.2 Crear/editar `terraform.tfvars`

Crear el archivo de variables para el entorno prod:

```bash
cp infrastructure/terraform/environments/prod/terraform.tfvars \
   infrastructure/terraform/environments/prod/terraform.tfvars.bak
```

Editar `infrastructure/terraform/environments/prod/terraform.tfvars`:

```hcl
name_prefix       = "cai-platform"          # Prefix de todos los recursos AWS
environment       = "prod"
aws_region        = "us-east-2"             # Región destino
ecr_image_tag     = "latest"
api_desired_count = 1
ui_desired_count  = 1
alert_email       = "ops@tuempresa.com"     # ← email para alarmas CloudWatch
s3_bucket         = "nombre-de-tu-bucket"  # ← bucket del paso 3
```

#### Referencia completa de variables

| Variable | Descripción | Ejemplo |
|---|---|---|
| `name_prefix` | Prefix para todos los recursos. Cambiar si hay múltiples instancias en la misma cuenta. | `cai-platform` |
| `environment` | `prod` o `staging` | `prod` |
| `aws_region` | Región AWS. Debe coincidir con donde está habilitado Bedrock. | `us-east-2` |
| `ecr_image_tag` | Tag de imagen Docker a desplegar. Al inicio usar `latest`. | `latest` |
| `api_desired_count` | Número de tasks del API. `0` para apagar, `1` para encender. | `1` |
| `ui_desired_count` | Número de tasks de la UI. | `1` |
| `alert_email` | Email que recibe alarmas de CloudWatch (cpu alto, errores 5xx, api down). Requiere confirmar suscripción SNS. | `ops@empresa.com` |
| `s3_bucket` | Bucket S3 para workspaces y artefactos. | `mi-bucket-cai` |

---

## Paso 5 — Aplicar la infraestructura

```bash
# Inicializar Terraform (descarga providers, conecta al backend S3)
make tf-init TF_ENV=prod

# Previsualizar qué se va a crear (sin aplicar cambios)
make tf-plan TF_ENV=prod

# Revisar el plan. Verificar que no haya destrucciones inesperadas.
# Si todo se ve bien, aplicar:
make tf-apply TF_ENV=prod
```

El apply tarda aprox. **10-15 minutos** en su primera ejecución (RDS tarda más que el resto).

### Outputs importantes

Al terminar, Terraform imprime los valores clave:

```
alb_dns                = "cai-platform-alb-XXXXXXXXX.us-east-2.elb.amazonaws.com"
ecr_platform_api_uri   = "ACCOUNT_ID.dkr.ecr.us-east-2.amazonaws.com/cai-platform/platform-api"
ecr_platform_ui_uri    = "ACCOUNT_ID.dkr.ecr.us-east-2.amazonaws.com/cai-platform/platform-ui"
cloudwatch_dashboard_url = "https://us-east-2.console.aws.amazon.com/cloudwatch/..."
```

Guardar estos valores — se usan en los pasos siguientes.

### Si se importan recursos existentes

Si la cuenta ya tiene recursos creados manualmente (no por Terraform), primero importarlos al estado:

```bash
make tf-import TF_ENV=prod
```

Luego ejecutar `tf-plan` para verificar que no haya drift antes de aplicar.

---

## Paso 6 — Construir y subir las imágenes Docker

Las imágenes deben estar en ECR antes de que ECS pueda arrancar los servicios.

```bash
# Obtener los URIs de ECR del output de Terraform
API_URI=$(terraform -chdir=infrastructure/terraform output -raw ecr_platform_api_uri)
UI_URI=$(terraform -chdir=infrastructure/terraform output -raw ecr_platform_ui_uri)
REGION=us-east-2   # ajustar

# Autenticar Docker contra ECR
aws ecr get-login-password --region $REGION | \
  docker login --username AWS --password-stdin \
  $(echo $API_URI | cut -d/ -f1)

# Construir y subir platform-api
docker build -t $API_URI:latest -f apps/platform-api/Dockerfile .
docker push $API_URI:latest

# Construir y subir platform-ui
docker build -t $UI_URI:latest -f apps/platform-ui/Dockerfile .
docker push $UI_URI:latest
```

> **Nota sobre `cai-framework`:** la imagen de `platform-ui` requiere el paquete `cai-framework` que está en PyPI público (v0.5.10+). El build descarga automáticamente. No se necesita acceso especial.

### Primer arranque de ECS

Después de subir las imágenes, forzar el deploy:

```bash
REGION=us-east-2
NAME_PREFIX=cai-platform   # ajustar si se cambió

aws ecs update-service \
  --cluster $NAME_PREFIX \
  --service platform-api \
  --force-new-deployment \
  --region $REGION

aws ecs update-service \
  --cluster $NAME_PREFIX \
  --service platform-ui \
  --force-new-deployment \
  --region $REGION
```

---

## Paso 7 — Poblar Secrets Manager

Terraform crea el secreto de RDS automáticamente con `manage_master_user_password = true` (AWS genera y rota la contraseña). Sin embargo, la clave `DATABASE_URL` que usa el API **debe escribirse manualmente** la primera vez con el formato correcto.

### 7.1 Obtener el endpoint y contraseña de RDS

```bash
# Endpoint (sin puerto)
aws rds describe-db-instances \
  --db-instance-identifier cai-platform-db \
  --region us-east-2 \
  --query 'DBInstances[0].Endpoint.Address' \
  --output text

# ARN del secreto con la contraseña generada por AWS
aws rds describe-db-instances \
  --db-instance-identifier cai-platform-db \
  --region us-east-2 \
  --query 'DBInstances[0].MasterUserSecret.SecretArn' \
  --output text

# Leer la contraseña
aws secretsmanager get-secret-value \
  --secret-id <arn-del-secreto-de-rds> \
  --region us-east-2 \
  --query 'SecretString' \
  --output text
```

### 7.2 Escribir DATABASE_URL en el secreto de la plataforma

```bash
ENDPOINT=<endpoint-rds>      # ej. cai-platform-db.abc123.us-east-2.rds.amazonaws.com
PASSWORD=<password-de-rds>

aws secretsmanager put-secret-value \
  --secret-id cai-platform/db-credentials \
  --region us-east-2 \
  --secret-string "{\"DATABASE_URL\": \"postgresql://caiplatform:${PASSWORD}@${ENDPOINT}:5432/caiplatform\"}"
```

### 7.3 Crear las tablas de la base de datos

Las tablas no se crean automáticamente. Ejecutar las migraciones desde el API:

```bash
# Opción A: correr desde el API local apuntando a la RDS (requiere acceso de red a la RDS)
DATABASE_URL="postgresql://caiplatform:<password>@<endpoint>:5432/caiplatform" \
  python3 -m platform_api --migrate-only

# Opción B: forzar un task ECS one-off que ejecute la migración
# (más seguro porque la RDS no está expuesta públicamente)
aws ecs run-task \
  --cluster cai-platform \
  --task-definition cai-platform-api \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[<subnet-id>],securityGroups=[<sg-id>],assignPublicIp=ENABLED}" \
  --overrides '{"containerOverrides":[{"name":"platform-api","command":["python3","-m","platform_api","--migrate-only"]}]}' \
  --region us-east-2
```

> **Nota:** Si el API no tiene un flag `--migrate-only`, simplemente arrancar el servicio — el API crea las tablas automáticamente al primer arranque si `DATABASE_URL` está definido y es válido (ver `packages/platform-core/src/platform_core/wiring.py`).

---

## Paso 8 — Verificar el despliegue

```bash
ALB_DNS=$(terraform -chdir=infrastructure/terraform output -raw alb_dns)

# Health check del API
curl http://$ALB_DNS/health
# Esperado: {"status": "ok", ...}

# Health check de la UI
curl http://$ALB_DNS/ui/_stcore/health
# Esperado: ok

# Ver la UI en el navegador
echo "UI: http://$ALB_DNS/ui"
```

### Verificar ECS

```bash
aws ecs describe-services \
  --cluster cai-platform \
  --services platform-api platform-ui \
  --region us-east-2 \
  --query 'services[*].{name:serviceName, running:runningCount, desired:desiredCount}' \
  --output table
```

Ambos servicios deben tener `running == desired`.

### CloudWatch

El dashboard de monitoreo está disponible en la URL del output `cloudwatch_dashboard_url`. Muestra:
- ECS: tasks corriendo, CPU, memoria
- ALB: requests, latencia, errores 5xx
- RDS: CPU, storage libre, conexiones

Confirmar la suscripción al email de alarmas: llega un email de AWS SNS con un link "Confirm subscription" que hay que hacer click.

---

## Paso 9 — Configurar CI/CD (GitHub Actions)

El workflow `.github/workflows/deploy.yml` automatiza el build y deploy en cada push a `main` y cada release.

### 9.1 Crear access key para el usuario `github-ci`

Terraform crea el usuario IAM `github-ci` pero no genera la key (por seguridad). Crearla manualmente:

```bash
aws iam create-access-key --user-name github-ci --region us-east-2
```

Guardar `AccessKeyId` y `SecretAccessKey` — solo se muestran una vez.

### 9.2 Configurar GitHub Secrets

En el repositorio GitHub → Settings → Secrets and variables → Actions → New repository secret:

| Secret | Valor |
|---|---|
| `CI_AWS_ACCESS_KEY_ID` | AccessKeyId del paso anterior |
| `CI_AWS_SECRET_ACCESS_KEY` | SecretAccessKey del paso anterior |

### 9.3 Verificar el workflow

Hacer un push a `main` o trigger manual desde GitHub Actions. El workflow:
1. Corre los tests
2. Build y push de imágenes a ECR (etiquetadas con el SHA del commit)
3. Deploy a staging (si existe)
4. Smoke test de staging
5. En releases (`v*`): deploy a prod + smoke test de prod

---

## Referencia de variables

### Variables en `terraform.tfvars` (editar por cuenta)

| Variable | Descripción | Quién lo cambia |
|---|---|---|
| `name_prefix` | Prefix de todos los recursos | Por instalación |
| `aws_region` | Región AWS | Por instalación |
| `s3_bucket` | Bucket de workspaces | Por instalación |
| `alert_email` | Email de alarmas | Por instalación |
| `environment` | `prod` o `staging` | Por entorno |
| `api_desired_count` | Tasks del API (0 = apagado) | Operaciones |
| `ui_desired_count` | Tasks de la UI (0 = apagado) | Operaciones |
| `ecr_image_tag` | Tag de imagen a desplegar | CI/CD |

### Lo que hay que editar manualmente (no variables)

| Archivo | Campo | Descripción |
|---|---|---|
| `backend.tf` | `bucket` | Bucket S3 de estado Terraform |
| `backend.tf` | `region` | Región del bucket de estado |
| `backend.tf` | `dynamodb_table` | Tabla DynamoDB de locks |

---

## Troubleshooting

### Los tasks de ECS no arrancan

```bash
# Ver eventos recientes del servicio
aws ecs describe-services \
  --cluster cai-platform --services platform-api \
  --query 'services[0].events[:5]' --output json

# Ver logs del último task fallido
aws ecs list-tasks --cluster cai-platform \
  --service-name platform-api --desired-status STOPPED \
  --query 'taskArns[0]' --output text | xargs \
  aws ecs describe-tasks --cluster cai-platform \
  --query 'tasks[0].{reason:stoppedReason,containers:containers[*].{exit:exitCode,reason:reason}}'
```

**Causas comunes:**
- `DATABASE_URL` no está en Secrets Manager → ver Paso 7
- La imagen ECR no existe o el tag no coincide → ver Paso 6
- La RDS aún está inicializando (tarda ~5 min en el primer apply)

### Health check de la UI falla (`Request timed out`)

Verificar que el security group tenga el puerto 8501 abierto:
```bash
aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=cai-platform-ecs" \
  --query 'SecurityGroups[0].IpPermissions'
```

Verificar que el health check del target group sea `/ui/_stcore/health` (no `/_stcore/health`):
```bash
aws elbv2 describe-target-groups \
  --names cai-platform-ui-tg \
  --query 'TargetGroups[0].HealthCheckPath'
```

### Bedrock devuelve `AccessDeniedException`

El task role necesita `bedrock:InvokeModel`. Terraform lo crea, pero si la cuenta no tiene Bedrock habilitado para el modelo, el error persiste. Verificar en la consola que el modelo Claude 3.5 Haiku tiene acceso en la región correcta.

### `terraform init` falla: bucket o tabla no encontrados

El bucket S3 y la tabla DynamoDB deben existir antes de `terraform init`. Ver Paso 3.

### Alarma `cai-api-task-down` en ALARM sin razón aparente

Container Insights puede no estar habilitado:
```bash
aws ecs update-cluster-settings \
  --cluster cai-platform \
  --settings name=containerInsights,value=enabled \
  --region us-east-2
```

Sin Container Insights, la métrica `RunningTaskCount` no existe y la alarma usa `treat_missing_data = breaching`.

### Costos inesperados

Los servicios ECS cuestan ~$0.59/día cada uno. Para apagarlos cuando no haya investigaciones:
```bash
make ecs-stop   # scale a 0
make ecs-start  # volver a 1
```
