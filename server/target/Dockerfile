FROM ubuntu:22.04
RUN apt-get update && apt-get install -y openssh-server rsyslog && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /run/sshd

# 테스트 계정
RUN useradd -m -s /bin/bash testuser && echo "testuser:testpass" | chpasswd

COPY sshd_config /etc/ssh/sshd_config
COPY rsyslog-target.conf /etc/rsyslog.d/10-forward.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
CMD ["/entrypoint.sh"]
