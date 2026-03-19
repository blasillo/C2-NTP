FROM python:3.9-alpine

WORKDIR /app

COPY ntp-server.py .

EXPOSE 123/udp

CMD ["python",  "-u", "ntp-server.py"]

