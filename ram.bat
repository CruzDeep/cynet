#!/usr/bin/env bash
set -euo pipefail
 
# Dominios que quieres permitir
DOMAINS=(
  "github.com"
  "api.github.com"
)
 
TABLE="inet"
FWTABLE="filter"
SETNAME="github_v4"
 
# Evita ejecuciones simultáneas (cron/systemd)
LOCK="/run/update_github_ips.lock"
exec 9>"$LOCK"
flock -n 9 || exit 0
 
# Recolecta IPv4s (A records)
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
 
for d in "${DOMAINS[@]}"; do
  # +time/+tries para evitar colgarse
  dig +short +time=2 +tries=2 A "$d" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >> "$TMP" || true
done
 
# Uniques
mapfile -t IPS < <(sort -u "$TMP" | grep -v '^$' || true)
 
if [[ ${#IPS[@]} -eq 0 ]]; then
  echo "[ERROR] No se resolvieron IPs. No toco el set."
  exit 1
fi
 
# Crea el set si no existe (por si se ejecuta antes de preparar nft)
if ! sudo nft list set "$TABLE" "$FWTABLE" "$SETNAME" >/dev/null 2>&1; then
  sudo nft add table "$TABLE" "$FWTABLE" 2>/dev/null || true
  sudo nft add set "$TABLE" "$FWTABLE" "$SETNAME" '{ type ipv4_addr; flags interval; }'
fi
 
# Construye un "replace" atómico del set
ELEMENTS=""
for ip in "${IPS[@]}"; do
  ELEMENTS+="$ip, "
done
ELEMENTS="${ELEMENTS%, }"
 
# Actualiza el set completo (más limpio que add/del uno por uno)
sudo nft -f - <<EOF
flush set $TABLE $FWTABLE $SETNAME
add element $TABLE $FWTABLE $SETNAME { $ELEMENTS }
EOF
 
echo "[OK] Set $SETNAME actualizado con: ${IPS[*]}"