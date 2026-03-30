FROM mcr.microsoft.com/powershell:lts-alpine-3.17
 
WORKDIR /app
 
COPY ntp-cli.ps1 .
 
CMD  ["pwsh", "-NoProfile", "-NonInteractive", "-File", "ntp-cli.ps1", "-Id", "cliente-win-01", "-Servidor", "ntp-servidor", "-Intervalo", "3"]

