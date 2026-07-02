variable "project_id" {
  type        = string
  description = "El ID del proyecto de Google Cloud (por defecto: proy-anla-poc)"
  default     = "proy-anla-poc"
}

variable "region" {
  type        = string
  description = "La región de Google Cloud donde se desplegarán los servicios"
  default     = "us-central1"
}

variable "github_repository" {
  type        = string
  description = "El repositorio de GitHub en formato 'usuario/repo' para la configuración de Workload Identity Federation"
  default     = "jhoan-ingramirez/Onyx"
}
