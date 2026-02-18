FROM ubuntu:22.04
RUN apt-get update && apt-get install -y rsyslog python3 && rm -rf /var/lib/apt/lists/*
COPY rsyslog-detection.conf /etc/rsyslog.d/10-receiver.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 514/tcp
CMD ["/entrypoint.sh"]
