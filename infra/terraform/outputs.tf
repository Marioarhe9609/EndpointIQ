output "onyx_dev_url" {
  value       = google_cloud_run_v2_service.onyx_dev.uri
  description = "La URL del servidor de Onyx en el ambiente de Desarrollo"
}

output "onyx_test_url" {
  value       = google_cloud_run_v2_service.onyx_test.uri
  description = "La URL del servidor de Onyx en el ambiente de Pruebas (QA)"
}

output "onyx_prod_url" {
  value       = google_cloud_run_v2_service.onyx_prod.uri
  description = "La URL del servidor de Onyx en el ambiente de Producción"
}

output "workload_identity_provider" {
  value       = "projects/${data.google_project.project.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.github_pool.workload_identity_pool_id}/providers/${google_iam_workload_identity_pool_provider.github_provider.workload_identity_pool_provider_id}"
  description = "La ruta completa del proveedor de Workload Identity para configurar en GitHub Actions"
}

output "github_actions_sa_email" {
  value       = google_service_account.github_sa.email
  description = "El email de la cuenta de servicio que utilizará GitHub Actions"
}

# Obtener número de proyecto para el output
data "google_project" "project" {}
