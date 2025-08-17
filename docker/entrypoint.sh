#!/usr/bin/env bash
set -euo pipefail

# Se quiser lógica extra de bootstrap, você pode usar este script como ENTRYPOINT.
# Ex.: validar se o secret existe ou gerar logs iniciais, etc.

exec "$@"
