FROM mcr.microsoft.com/powershell:lts-alpine-3.17
 
WORKDIR /app
 
COPY ntp-client.ps1 .
 
CMD ["pwsh", "-NoProfile", "-NonInteractive", "-File", "ntp-client.ps1", "-Servidor", "ntp-servidor", "-Intervalo", "3"]

