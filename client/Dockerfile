FROM python:3.9-alpine

WORKDIR /app

COPY ntp-cli.py .

# Instalar herramientas adicionales para comandos
RUN apk add --no-cache \
    iproute2 \
    && rm -rf /var/cache/apk/*

# Por defecto, intervalo de 10 segundos
CMD ["python", "-u", "ntp-cli.py", "cliente-linux-01", "ntp-servidor", "3"]