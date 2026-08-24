---
trigger: always_on
---
# Protocolo de Desarrollo Seguro Multi-Agente (Gemini 3.7 + Claude Code) con Blindaje Anti-Regresión

Cuando se requiera desarrollar funcionalidades siguiendo el proceso de desarrollo seguro, Antigravity (Gemini 3.7) coordinará con Claude Code usando el script global:
python C:\Users\ASUS\.gemini\config\skills\claude-secure-pipeline\scripts\claude_gate.py

Fases y Puntos de Control Obligatorios (Cero Regresiones):
1. Requerimientos: Claude genera el prompt -> Gemini genera implementation_plan.md con análisis de impacto y preservación de contratos/APIs preexistentes -> Claude audita (review-plan). Bloquear hasta APPROVED.
2. Implementación: Gemini genera código manteniendo estricta retrocompatibilidad (esquemas BQ, endpoints, firmas HMAC) -> Claude audita (audit-code). Bloquear hasta APPROVED.
3. Pruebas:
   - Ejecución obligatoria de la suite completa de pruebas preexistentes (tolerancia: 0 fallos).
   - Claude genera matriz de los 7 pilares (generate-test-matrix) -> Gemini implementa nuevos tests -> Claude valida cumplimiento de nuevos tests y no-regresión (verify-tests). Bloquear hasta zero_regressions: true y ready_for_human_review: true.
4. HITL: Presentar reporte en walkthrough.md con Smoke Test de flujos críticos (Login/2FA, Ingesta, Dashboard, BigQuery) y guiar al usuario en la validación unitaria y pruebas E2E.
