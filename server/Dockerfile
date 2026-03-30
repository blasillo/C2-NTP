FROM python:3.9-alpine

WORKDIR /app

COPY ntp-srv.py .

EXPOSE 123/udp

CMD ["python",  "-u", "ntp-srv.py"]

