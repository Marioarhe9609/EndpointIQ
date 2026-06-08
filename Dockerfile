FROM python:3.11-slim

WORKDIR /app

# Instalar SDK de BigQuery para Python
RUN pip install --no-cache-dir google-cloud-bigquery

# Copiar todos los archivos de la aplicacion
COPY . .

# Puerto por defecto (Cloud Run inyecta PORT como variable de entorno)
EXPOSE 8080

# Comando de arranque
CMD ["python", "server.py"]
