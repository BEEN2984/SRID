#!/usr/bin/env bash
set -e
rsyslogd
ssh-keygen -A

USER_COUNT=${USER_COUNT:-20}            # docker-composer 에서 변경 가능
USER_PREFIX=${USER_PREFIX:-srid_user}
DEFAULT_FAIL_PW=${DEFAULT_FAIL_PW:-1234}

# 일반 계정
for i in $(seq 1 "$USER_COUNT"); do
    user="${USER_PREFIX}${i}"

    if ! id "$user" >/dev/null 2>&1; then
        useradd -m "$user"
        echo "$user:$DEFAULT_FAIL_PW" | chpasswd
        echo "[ok] created $user"
    fi
done

# 성공 로그 생성용 계정 
SUCCESS_USER=${SUCCESS_USER:-srid_ok}
SUCCESS_PW=${SUCCESS_PW:-sridpass}

if ! id "$SUCCESS_USER" >/dev/null 2>&1; then
    useradd -m "$SUCCESS_USER"
fi

echo "$SUCCESS_USER:$SUCCESS_PW" | chpasswd
echo "[ok] ensured $SUCCESS_USER (success account)"

exec /usr/sbin/sshd -D