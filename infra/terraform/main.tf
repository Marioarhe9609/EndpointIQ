terraform {
  required_version = ">= 1.3.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.50.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ══════════════════════════════════════════════════════════════
# CUENTAS DE SERVICIO SEGURAS (Least Privilege)
# ══════════════════════════════════════════════════════════════

# Cuenta de servicio para el ambiente DEV
resource "google_service_account" "run_sa_dev" {
  account_id   = "onyx-run-sa-dev"
  display_name = "Onyx Cloud Run Runtime SA - Desarrollo"
}

# Cuenta de servicio para el ambiente TEST
resource "google_service_account" "run_sa_test" {
  account_id   = "onyx-run-sa-test"
  display_name = "Onyx Cloud Run Runtime SA - Pruebas"
}

# Cuenta de servicio para el ambiente PROD
resource "google_service_account" "run_sa_prod" {
  account_id   = "onyx-run-sa-prod"
  display_name = "Onyx Cloud Run Runtime SA - Producción"
}

# Cuenta de servicio para GitHub Actions (CI/CD)
resource "google_service_account" "github_sa" {
  account_id   = "onyx-github-sa"
  display_name = "Onyx GitHub Actions Deployer SA"
}

# ══════════════════════════════════════════════════════════════
# DATASETS DE BIGQUERY SEGREGADOS
# ══════════════════════════════════════════════════════════════

# Dataset DEV
resource "google_bigquery_dataset" "dataset_dev" {
  dataset_id                  = "onyx_dev"
  friendly_name               = "Onyx Dataset Desarrollo"
  description                 = "Almacén de datos para el ambiente de desarrollo"
  location                    = "us-central1"
  default_table_expiration_ms = 2592000000 # 30 días de retención para DEV
}

# Dataset TEST
resource "google_bigquery_dataset" "dataset_test" {
  dataset_id                  = "onyx_test"
  friendly_name               = "Onyx Dataset Pruebas"
  description                 = "Almacén de datos para el ambiente de pruebas (QA)"
  location                    = "us-central1"
  default_table_expiration_ms = 7776000000 # 90 días de retención para TEST
}

# Dataset PROD
resource "google_bigquery_dataset" "dataset_prod" {
  dataset_id    = "onyx_prod"
  friendly_name = "Onyx Dataset Producción"
  description   = "Almacén de datos para el ambiente de producción"
  location      = "us-central1"
}

# ══════════════════════════════════════════════════════════════
# PERMISOS DE ACCESO A DATASETS (IAM)
# ══════════════════════════════════════════════════════════════

# Permisos para el SA de DEV en onyx_dev
resource "google_bigquery_dataset_iam_member" "dev_data_editor" {
  dataset_id = google_bigquery_dataset.dataset_dev.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.run_sa_dev.email}"
}

resource "google_bigquery_dataset_iam_member" "dev_user" {
  dataset_id = google_bigquery_dataset.dataset_dev.dataset_id
  role       = "roles/bigquery.user"
  member     = "serviceAccount:${google_service_account.run_sa_dev.email}"
}

# Permisos para el SA de TEST en onyx_test
resource "google_bigquery_dataset_iam_member" "test_data_editor" {
  dataset_id = google_bigquery_dataset.dataset_test.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.run_sa_test.email}"
}

resource "google_bigquery_dataset_iam_member" "test_user" {
  dataset_id = google_bigquery_dataset.dataset_test.dataset_id
  role       = "roles/bigquery.user"
  member     = "serviceAccount:${google_service_account.run_sa_test.email}"
}

# Permisos para el SA de PROD en onyx_prod
resource "google_bigquery_dataset_iam_member" "prod_data_editor" {
  dataset_id = google_bigquery_dataset.dataset_prod.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.run_sa_prod.email}"
}

resource "google_bigquery_dataset_iam_member" "prod_user" {
  dataset_id = google_bigquery_dataset.dataset_prod.dataset_id
  role       = "roles/bigquery.user"
  member     = "serviceAccount:${google_service_account.run_sa_prod.email}"
}

# Permisos para GitHub Actions SA (requiere BigQuery Admin para crear esquemas)
resource "google_project_iam_member" "github_sa_bq" {
  project = var.project_id
  role    = "roles/bigquery.admin"
  member  = "serviceAccount:${google_service_account.github_sa.email}"
}

# ══════════════════════════════════════════════════════════════
# CREACIÓN DE LAS 6 TABLAS POR DATASET
# ══════════════════════════════════════════════════════════════

locals {
  datasets = ["onyx_dev", "onyx_test", "onyx_prod"]

  # Esquemas en JSON
  schema_eq_users = <<EOF
[
  {"name": "user_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "email", "type": "STRING", "mode": "REQUIRED"},
  {"name": "password_hash", "type": "STRING", "mode": "REQUIRED"},
  {"name": "salt", "type": "STRING", "mode": "REQUIRED"},
  {"name": "full_name", "type": "STRING", "mode": "NULLABLE"},
  {"name": "role", "type": "STRING", "mode": "REQUIRED"},
  {"name": "avatar", "type": "STRING", "mode": "NULLABLE"},
  {"name": "created_at", "type": "STRING", "mode": "NULLABLE"},
  {"name": "last_login", "type": "STRING", "mode": "NULLABLE"},
  {"name": "is_active", "type": "BOOLEAN", "mode": "NULLABLE"}
]
EOF

  schema_eq_sync_status = <<EOF
[
  {"name": "device_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "last_ip", "type": "STRING", "mode": "NULLABLE"},
  {"name": "status", "type": "STRING", "mode": "NULLABLE"},
  {"name": "last_sync", "type": "STRING", "mode": "NULLABLE"},
  {"name": "timestamp", "type": "STRING", "mode": "NULLABLE"}
]
EOF

  schema_eq_hardware_metrics = <<EOF
[
  {"name": "timestamp", "type": "STRING", "mode": "REQUIRED"},
  {"name": "device_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "cpu_usage", "type": "FLOAT", "mode": "NULLABLE"},
  {"name": "ram_usage", "type": "FLOAT", "mode": "NULLABLE"},
  {"name": "disk_free_gb", "type": "FLOAT", "mode": "NULLABLE"},
  {"name": "network_latency_ms", "type": "FLOAT", "mode": "NULLABLE"},
  {"name": "cause_root", "type": "STRING", "mode": "NULLABLE"},
  {"name": "cause_process", "type": "STRING", "mode": "NULLABLE"},
  {"name": "device_type", "type": "STRING", "mode": "NULLABLE"},
  {"name": "battery_percent", "type": "INTEGER", "mode": "NULLABLE"},
  {"name": "battery_status", "type": "STRING", "mode": "NULLABLE"},
  {"name": "top_processes", "type": "STRING", "mode": "NULLABLE"},
  {"name": "browser_history", "type": "STRING", "mode": "NULLABLE"},
  {"name": "network_info", "type": "STRING", "mode": "NULLABLE"},
  {"name": "usb_ports", "type": "STRING", "mode": "NULLABLE"},
  {"name": "event_logs", "type": "STRING", "mode": "NULLABLE"}
]
EOF

  schema_eq_security_events = <<EOF
[
  {"name": "timestamp", "type": "STRING", "mode": "REQUIRED"},
  {"name": "device_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "event_type", "type": "STRING", "mode": "REQUIRED"},
  {"name": "details", "type": "STRING", "mode": "NULLABLE"},
  {"name": "severity", "type": "STRING", "mode": "NULLABLE"}
]
EOF

  schema_eq_kpi_definitions = <<EOF
[
  {"name": "kpi_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "kpi_name", "type": "STRING", "mode": "NULLABLE"},
  {"name": "formula", "type": "STRING", "mode": "NULLABLE"},
  {"name": "target_value", "type": "FLOAT", "mode": "NULLABLE"},
  {"name": "created_by", "type": "STRING", "mode": "NULLABLE"},
  {"name": "created_at", "type": "STRING", "mode": "NULLABLE"}
]
EOF

  schema_eq_whatsapp_interactions = <<EOF
[
  {"name": "timestamp", "type": "STRING", "mode": "REQUIRED"},
  {"name": "phone_number", "type": "STRING", "mode": "NULLABLE"},
  {"name": "user_query", "type": "STRING", "mode": "NULLABLE"},
  {"name": "bot_response", "type": "STRING", "mode": "NULLABLE"},
  {"name": "intent_detected", "type": "STRING", "mode": "NULLABLE"},
  {"name": "tokens_used", "type": "INTEGER", "mode": "NULLABLE"}
]
EOF
}

# 1. Tabla eq_users por cada dataset
resource "google_bigquery_table" "eq_users" {
  for_each   = toset(local.datasets)
  dataset_id = each.key
  table_id   = "eq_users"
  schema     = local.schema_eq_users
  deletion_protection = false
}

# 2. Tabla eq_sync_status por cada dataset
resource "google_bigquery_table" "eq_sync_status" {
  for_each   = toset(local.datasets)
  dataset_id = each.key
  table_id   = "eq_sync_status"
  schema     = local.schema_eq_sync_status
  deletion_protection = false
}

# 3. Tabla eq_hardware_metrics por cada dataset
resource "google_bigquery_table" "eq_hardware_metrics" {
  for_each   = toset(local.datasets)
  dataset_id = each.key
  table_id   = "eq_hardware_metrics"
  schema     = local.schema_eq_hardware_metrics
  deletion_protection = false
}

# 4. Tabla eq_security_events por cada dataset
resource "google_bigquery_table" "eq_security_events" {
  for_each   = toset(local.datasets)
  dataset_id = each.key
  table_id   = "eq_security_events"
  schema     = local.schema_eq_security_events
  deletion_protection = false
}

# 5. Tabla eq_kpi_definitions por cada dataset
resource "google_bigquery_table" "eq_kpi_definitions" {
  for_each   = toset(local.datasets)
  dataset_id = each.key
  table_id   = "eq_kpi_definitions"
  schema     = local.schema_eq_kpi_definitions
  deletion_protection = false
}

# 6. Tabla eq_whatsapp_interactions por cada dataset
resource "google_bigquery_table" "eq_whatsapp_interactions" {
  for_each   = toset(local.datasets)
  dataset_id = each.key
  table_id   = "eq_whatsapp_interactions"
  schema     = local.schema_eq_whatsapp_interactions
  deletion_protection = false
}

# ══════════════════════════════════════════════════════════════
# REGISTRO DE ARTEFACTOS (Container Registry)
# ══════════════════════════════════════════════════════════════

resource "google_artifact_registry_repository" "onyx_repo" {
  location      = var.region
  repository_id = "onyx-server-repo"
  description   = "Repositorio Docker para Onyx"
  format        = "DOCKER"
}

# Permisos para GitHub Actions SA en Artifact Registry (para empujar imágenes)
resource "google_artifact_registry_repository_iam_member" "github_registry_writer" {
  location   = google_artifact_registry_repository.onyx_repo.location
  repository = google_artifact_registry_repository.onyx_repo.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.github_sa.email}"
}

# ══════════════════════════════════════════════════════════════
# WORKLOAD IDENTITY FEDERATION (OIDC para GitHub Actions)
# ══════════════════════════════════════════════════════════════

# Pool de Identidad de Carga de Trabajo (Workload Identity Pool)
resource "google_iam_workload_identity_pool" "github_pool" {
  workload_identity_pool_id = "onyx-github-pool"
  display_name              = "Onyx GitHub Actions Pool"
  description               = "Workload Identity Pool para desplegar desde GitHub Actions"
}

# Proveedor de Identidad (Workload Identity Provider)
resource "google_iam_workload_identity_pool_provider" "github_provider" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "onyx-github-provider"
  display_name                       = "Onyx GitHub Provider"
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.repository" = "assertion.repository"
  }
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# Permitir a GitHub Actions impersonar el SA de despliegue
resource "google_service_account_iam_member" "github_sa_impersonation" {
  service_account_id = google_service_account.github_sa.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.repository/${var.github_repository}"
}

# Permisos para GitHub Actions en Cloud Run (Deployer)
resource "google_project_iam_member" "github_sa_run_admin" {
  project = var.project_id
  role    = "roles/run.admin"
  member  = "serviceAccount:${google_service_account.github_sa.email}"
}

# Permitir a GitHub Actions usar cuentas de servicio de ejecución (Service Account User)
resource "google_service_account_iam_member" "github_sa_user_dev" {
  service_account_id = google_service_account.run_sa_dev.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.github_sa.email}"
}

resource "google_service_account_iam_member" "github_sa_user_test" {
  service_account_id = google_service_account.run_sa_test.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.github_sa.email}"
}

resource "google_service_account_iam_member" "github_sa_user_prod" {
  service_account_id = google_service_account.run_sa_prod.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.github_sa.email}"
}

# ══════════════════════════════════════════════════════════════
# SERVICIOS GOOGLE CLOUD RUN (All Ingress / Públicos)
# ══════════════════════════════════════════════════════════════

# NOTA: Usamos una imagen de marcador de posición (hello) inicialmente,
# GitHub Actions actualizará esto con la imagen real de Onyx construida.

# Servicio de Cloud Run: DESARROLLO (DEV)
resource "google_cloud_run_v2_service" "onyx_dev" {
  name     = "onyx-server-dev"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL" # Totalmente abierto al público

  template {
    service_account = google_service_account.run_sa_dev.email
    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello" # Marcador de posición inicial
      ports {
        container_port = 8080
      }
      env {
        name  = "BQ_DATASET"
        value = "onyx_dev"
      }
      env {
        name  = "PORT"
        value = "8080"
      }
    }
  }
  lifecycle {
    ignore_changes = [
      template[0].containers[0].image
    ]
  }
}

# Servicio de Cloud Run: PRUEBAS (TEST)
resource "google_cloud_run_v2_service" "onyx_test" {
  name     = "onyx-server-test"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL" # Totalmente abierto al público (solicitado por el usuario)

  template {
    service_account = google_service_account.run_sa_test.email
    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello" # Marcador de posición inicial
      ports {
        container_port = 8080
      }
      env {
        name  = "BQ_DATASET"
        value = "onyx_test"
      }
      env {
        name  = "PORT"
        value = "8080"
      }
    }
  }
  lifecycle {
    ignore_changes = [
      template[0].containers[0].image
    ]
  }
}

# Servicio de Cloud Run: PRODUCCIÓN (PROD)
resource "google_cloud_run_v2_service" "onyx_prod" {
  name     = "onyx-server-prod"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL" # Totalmente abierto al público

  template {
    service_account = google_service_account.run_sa_prod.email
    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello" # Marcador de posición inicial
      ports {
        container_port = 8080
      }
      env {
        name  = "BQ_DATASET"
        value = "onyx_prod"
      }
      env {
        name  = "PORT"
        value = "8080"
      }
    }
  }
  lifecycle {
    ignore_changes = [
      template[0].containers[0].image
    ]
  }
}

# Permisos para que cualquier persona pueda invocar el servicio Cloud Run (Acceso Público)
resource "google_cloud_run_v2_service_iam_member" "dev_public_access" {
  name     = google_cloud_run_v2_service.onyx_dev.name
  location = google_cloud_run_v2_service.onyx_dev.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "test_public_access" {
  name     = google_cloud_run_v2_service.onyx_test.name
  location = google_cloud_run_v2_service.onyx_test.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "prod_public_access" {
  name     = google_cloud_run_v2_service.onyx_prod.name
  location = google_cloud_run_v2_service.onyx_prod.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}
