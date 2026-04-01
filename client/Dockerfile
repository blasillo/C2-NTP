FROM python:3.9-alpine

WORKDIR /app

COPY ntp-cli.py .

RUN apk add --no-cache \
    iproute2 \
    openssh \
    && rm -rf /var/cache/apk/* \
    && ssh-keygen -A \
    && mkdir -p /root/.ssh \
    && chmod 700 /root/.ssh \
    && touch /root/.ssh/authorized_keys \
    && chmod 600 /root/.ssh/authorized_keys \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config

CMD ["python", "-u", "ntp-cli.py", "cliente-linux-01", "ntp-servidor", "3"]