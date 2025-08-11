#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/bin:/usr/bin:/bin"
cd /home/louis/apps/wemprss-mailer
mkdir -p logs
# 建议预先编译：go build -o bin/wemprss-mailer ./cmd/wemprss-mailer
exec ./bin/wemprss-mailer "${1:-send}"