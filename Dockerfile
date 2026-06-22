FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias del servidor
RUN pip install --no-cache-dir \
    google-cloud-bigquery \
    google-cloud-pubsub

# Copiar todos los archivos
COPY . .

# Puerto Cloud Run
EXPOSE 8080

# Comando de arranque
CMD ["python", "server.py"]
