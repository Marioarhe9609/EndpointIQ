#!/usr/bin/env bash
# ==============================================================================
# setup_gcp_scale.sh — Onyx Infrastructure Setup para 10,000+ dispositivos
# ==============================================================================
# Ejecutar UNA SOLA VEZ desde Cloud Shell o con gcloud autenticado.
# Prerequisito: gcloud auth login && gcloud config set project endpointiq
# ==============================================================================

set -euo pipefail

PROJECT="endpointiq"
REGION="us-central1"
DATASET="endpointiq"
TOPIC="onyx-metrics"
SUBSCRIPTION="onyx-metrics-push"
CR_SERVICE="endpointiq"
CR_URL="https://endpointiq-175647544738.us-central1.run.app"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   Onyx GCP Setup — Arquitectura para 10K dispositivos   ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── 1. Pub/Sub Topic ──────────────────────────────────────────────────────────
echo "▶ [1/6] Creando Pub/Sub topic '$TOPIC'..."
gcloud pubsub topics create "$TOPIC" \
  --project="$PROJECT" 2>/dev/null || echo "  → Topic ya existe, omitiendo."

# ── 2. Pub/Sub Push Subscription → Cloud Run /api/internal/ingest ─────────────
echo "▶ [2/6] Creando suscripción push → Cloud Run..."
# Obtener la SA de Cloud Run para autenticar el push
CR_SA=$(gcloud run services describe "$CR_SERVICE" \
  --region="$REGION" --project="$PROJECT" \
  --format="value(spec.template.spec.serviceAccountName)" 2>/dev/null \
  || echo "${PROJECT}@appspot.gserviceaccount.com")

gcloud pubsub subscriptions create "$SUBSCRIPTION" \
  --topic="$TOPIC" \
  --project="$PROJECT" \
  --push-endpoint="${CR_URL}/api/internal/ingest" \
  --push-auth-service-account="$CR_SA" \
  --ack-deadline=60 \
  --max-delivery-attempts=5 \
  --dead-letter-topic="${TOPIC}-dlq" 2>/dev/null || echo "  → Suscripción ya existe, omitiendo."

# ── 3. Dead Letter Topic (para mensajes fallidos) ─────────────────────────────
echo "▶ [3/6] Creando Dead Letter Topic (mensajes que fallan 5 veces)..."
gcloud pubsub topics create "${TOPIC}-dlq" \
  --project="$PROJECT" 2>/dev/null || echo "  → DLQ ya existe, omitiendo."

# ── 4. BigQuery — Tabla particionada eq_hardware_metrics_v2 ──────────────────
echo "▶ [4/6] Creando tabla BigQuery particionada..."
bq query --project_id="$PROJECT" --use_legacy_sql=false \
  --location=US << 'EOF'
  CREATE TABLE IF NOT EXISTS endpointiq.eq_hardware_metrics_partitioned
  PARTITION BY DATE(timestamp)
  CLUSTER BY device_id
  OPTIONS (
    partition_expiration_days = 90,
    description = "Métricas de hardware particionadas por día. Reemplaza eq_hardware_metrics para escala 10K+"
  )
  AS SELECT * FROM endpointiq.eq_hardware_metrics WHERE FALSE;
EOF
echo "  → Tabla eq_hardware_metrics_partitioned creada."
echo "  ⚠ Migrar datos: INSERT INTO ...partitioned SELECT * FROM ...eq_hardware_metrics"

# ── 5. Service Account para Pub/Sub Publisher (agentes) ───────────────────────
echo "▶ [5/6] Configurando Service Account para agentes (publisher only)..."
AGENT_SA="onyx-agent-publisher@${PROJECT}.iam.gserviceaccount.com"

gcloud iam service-accounts create onyx-agent-publisher \
  --display-name="Onyx Agent — Solo Pub/Sub Publisher" \
  --project="$PROJECT" 2>/dev/null || echo "  → SA ya existe."

# Solo permiso de publicar en el topic (no BQ, no nada más)
gcloud pubsub topics add-iam-policy-binding "$TOPIC" \
  --project="$PROJECT" \
  --member="serviceAccount:${AGENT_SA}" \
  --role="roles/pubsub.publisher"

echo "  ✓ SA '$AGENT_SA' con permiso pubsub.publisher en '$TOPIC'"
echo "  → Generar nueva clave: gcloud iam service-accounts keys create"
echo "    eiq_credentials_pubsub.json --iam-account=$AGENT_SA"

# ── 6. Cloud Run — Dar permisos de BQ al servidor ─────────────────────────────
echo "▶ [6/6] Dando permisos BigQuery al servidor Cloud Run..."
CR_SA_FULL="${PROJECT}@appspot.gserviceaccount.com"

gcloud projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:${CR_SA_FULL}" \
  --role="roles/bigquery.dataEditor" 2>/dev/null || true

gcloud projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:${CR_SA_FULL}" \
  --role="roles/bigquery.jobUser" 2>/dev/null || true

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                    ✅ Setup completado                   ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Topic Pub/Sub:   onyx-metrics                          ║"
echo "║  Subscription:    onyx-metrics-push → /api/ingest       ║"
echo "║  Dead Letter:     onyx-metrics-dlq                      ║"
echo "║  Tabla BQ:        eq_hardware_metrics_partitioned       ║"
echo "║  Agent SA:        onyx-agent-publisher (solo publisher) ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  PRÓXIMO PASO: Generar credenciales Pub/Sub para agentes║"
echo "║  y distribuir eiq_credentials_pubsub.json               ║"
echo "╚══════════════════════════════════════════════════════════╝"
