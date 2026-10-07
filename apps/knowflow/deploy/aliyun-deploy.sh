#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing command: $1" >&2
    exit 1
  fi
}

generate_password() {
  openssl rand -base64 24 | tr -d '\n'
}

require_command openssl
require_command docker

if ! docker compose version >/dev/null 2>&1; then
  echo "docker compose is not available. Please enable Docker Compose first." >&2
  exit 1
fi

mkdir -p backend/config/keys
if [ ! -f backend/config/keys/private.pem ] || [ ! -f backend/config/keys/public.pem ]; then
  echo "Generating local JWT RSA key pair..."
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out backend/config/keys/private.pem
  openssl rsa -pubout -in backend/config/keys/private.pem -out backend/config/keys/public.pem
fi

if [ ! -f .env ]; then
  echo "Creating .env with generated MySQL passwords..."
  MYSQL_ROOT_PASSWORD="$(generate_password)"
  MYSQL_PASSWORD="$(generate_password)"
  cat > .env <<EOF
MYSQL_DATABASE=knowflow
MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD}
MYSQL_USER=knowflow
MYSQL_PASSWORD=${MYSQL_PASSWORD}

KIMI_API_KEY=replace-me
KIMI_BASE_URL=https://api.moonshot.cn
KIMI_CHAT_MODEL=moonshot-v1-8k

JWT_ISSUER=knowflow
JWT_KEY_ID=knowflow-key

OSS_MODE=local
OSS_LOCAL_ROOT=/app/data/uploads
OSS_LOCAL_PUBLIC_PREFIX=/api/v1/storage/local-files
EOF
  chmod 600 .env
else
  echo ".env already exists; keeping existing passwords and API keys."
fi

if grep -q '^KIMI_API_KEY=replace-me$' .env; then
  echo "WARNING: .env still contains KIMI_API_KEY=replace-me."
  echo "Edit .env and replace it with your real Kimi API key before using AI features."
fi

COMPOSE="docker compose --env-file .env -f deploy/docker-compose.yml"

$COMPOSE down
$COMPOSE up -d --build
$COMPOSE ps
