#!/usr/bin/env bash
set -euo pipefail

############################################
# IDENTIFICACIÓN Y ARCHIVO DE SALIDA
############################################
FECHA="$(date '+%Y-%m-%d_%H-%M-%S')"
HOST="$(hostname)"
HASH_ID="$(echo "$HOST-$FECHA-GITHUB-IP-UPDATE" | sha256sum | awk '{print $1}')"

echo "==========================================="
echo " Validación y actualización de IPs GitHub"
echo " Host: $HOST"
echo " Fecha: $FECHA"
echo " Hash:  $HASH_ID"
echo "==========================================="

############################################
# VARIABLES
############################################
DOMAINS=(
  "github.com"
  "api.github.com"
)

TABLE="inet"
FWTABLE="filter"
SETNAME="github_v4"

############################################
# LOCK
############################################
echo "[1] Validación de ejecución simultánea"
LOCK="/run/update_github_ips.lock"
exec 9>"$LOCK"
flock -n 9 || {
  echo "[INFO] Script ya en ejecución. Saliendo."
  exit 0
}

############################################
# DNS
############################################
echo "==========================================="
echo "[2] Resolución DNS de dominios GitHub (IPv4)"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

for d in "${DOMAINS[@]}"; do
  echo "-------------------------------------------"
  echo "Dominio: $d"
  echo "Comando: dig +short +time=2 +tries=2 A $d"
  dig +short +time=2 +tries=2 A "$d"

  dig +short +time=2 +tries=2 A "$d" \
    | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >> "$TMP" || true
done

############################################
# PROCESAMIENTO IPs
############################################
echo "==========================================="
echo "[3] Limpieza y deduplicación de IPs"
echo "Comando: sort -u"

sort -u "$TMP" | grep -v '^$' || true

mapfile -t IPS < <(sort -u "$TMP" | grep -v '^$' || true)

if [[ ${#IPS[@]} -eq 0 ]]; then
  echo "[ERROR] No se resolvieron IPs. No se modifica nftables."
  exit 1
fi

############################################
# NFTABLES – SET
############################################
echo "==========================================="
echo "[4] Validación / creación del set nftables"
echo "Comando: nft list set $TABLE $FWTABLE $SETNAME"

sudo nft list set "$TABLE" "$FWTABLE" "$SETNAME" || echo "Set no existe"

if ! sudo nft list set "$TABLE" "$FWTABLE" "$SETNAME" >/dev/null 2>&1; then
  echo "Comando: nft add table $TABLE $FWTABLE"
  sudo nft add table "$TABLE" "$FWTABLE" 2>/dev/null || true

  echo "Comando: nft add set $TABLE $FWTABLE $SETNAME"
  sudo nft add set "$TABLE" "$FWTABLE" "$SETNAME" '{ type ipv4_addr; flags interval; }'
fi

############################################
# ACTUALIZACIÓN SET
############################################
echo "==========================================="
echo "[5] Actualización del set nftables"

ELEMENTS=""
for ip in "${IPS[@]}"; do
  ELEMENTS+="$ip, "
done
ELEMENTS="${ELEMENTS%, }"

echo "Comando: nft flush set $TABLE $FWTABLE $SETNAME"
sudo nft flush set "$TABLE" "$FWTABLE" "$SETNAME"

echo "Comando: nft add element $TABLE $FWTABLE $SETNAME { $ELEMENTS }"
sudo nft add element "$TABLE" "$FWTABLE" "$SETNAME" { $ELEMENTS }

############################################
# VALIDACIÓN FINAL
############################################
echo "==========================================="
echo "[6] Validación final"
echo "Comando: nft list set $TABLE $FWTABLE $SETNAME"
sudo nft list set "$TABLE" "$FWTABLE" "$SETNAME"

echo "==========================================="
echo "[OK] Proceso finalizado correctamente"
echo "[OK] Set $SETNAME actualizado con: ${IPS[*]}"
echo "==========================================="
exit 0