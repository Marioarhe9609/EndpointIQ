FROM python:3.11-slim AS builder

WORKDIR /app

# Instalar SDK de BigQuery para Python en la etapa de compilación
RUN pip install --no-cache-dir google-cloud-bigquery pyotp qrcode[pil] ldap3

FROM python:3.11-slim AS runner

WORKDIR /app

# Copiar las dependencias instaladas desde la etapa de compilación
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copiar los archivos de la aplicación
COPY . .

# Crear un usuario y grupo no raíz con privilegios mínimos para ejecutar el contenedor
RUN groupadd -g 10001 onyxgroup && \
    useradd -r -u 10001 -g onyxgroup -d /home/onyxuser -m onyxuser

# Asegurar que las salidas de Python se flasheen en tiempo real
ENV PYTHONUNBUFFERED=1

# Cambiar la propiedad de la carpeta de la aplicación al usuario no raíz
RUN chown -R onyxuser:onyxgroup /app /home/onyxuser

# Ejecutar como el usuario no raíz seguro
USER onyxuser

# Puerto por defecto (Cloud Run inyecta PORT como variable de entorno)
EXPOSE 8080

# Comando de arranque
CMD ["python", "server.py"]

