# platform-adapters

Capa de traducción entre fuentes externas y el formato interno de la plataforma.

## Responsabilidad

- Normalizar y validar payloads de entrada antes de que lleguen a los backends.
- Aislar el conocimiento de formatos vendor-específicos (WatchGuard CSV, email SMTP) del dominio central.

**No debe contener**: lógica de casos, ciclo de vida de runs, código CAI, ni persistencia.

## Slices implementados

### `platform_adapters.watchguard`

Normaliza logs de firewall WatchGuard exportados desde el portal.

| Módulo | Descripción |
|---|---|
| `platform_adapters.watchguard.types` | Tipos: `WatchGuardRecord`, `WatchGuardNormalizedLog` |
| `platform_adapters.watchguard.normalize` | Parser CSV → records normalizados. Acepta `{"log_type": "traffic", "csv_rows": [...]}` (preferido) y `{"records": [...]}` (compatibilidad) |
| `platform_adapters.watchguard.errors` | `WatchGuardAdapterError` |

También provee `parse_workspace_s3_zip_reference()` para parsear el payload de tipo `workspace_s3_zip` que apunta a un ZIP en S3.

### `platform_adapters.phishing_email`

Valida y normaliza el payload de análisis de phishing.

| Módulo | Descripción |
|---|---|
| `platform_adapters.phishing_email.types` | Tipos: `PhishingEmailInput`, `SenderInfo`, `AttachmentInfo` |
| `platform_adapters.phishing_email.normalize` | Lowercasea emails/dominios, preserva URLs y metadata de adjuntos |
| `platform_adapters.phishing_email.errors` | `PhishingEmailAdapterError` |

## Regla de dependencias

Solo puede depender de `platform-contracts`. Los backends importan desde aquí, no al revés.
