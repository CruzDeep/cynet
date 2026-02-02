#!/usr/bin/env bash
set -euo pipefail

############################################
# CONFIG / PRECHECKS
############################################
# Debe correr como root (para nftables, lock y evitar sudo interactivo)
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[ERROR] Este script debe ejecutarse como root. Saliendo."
  exit 1
fi

# Dependencias mínimas
command -v nft >/dev/null 2>&1 || { echo "[ERROR] Falta 'nft' (instala nftables)"; exit 1; }

RESOLVE_WITH_DIG=true
if ! command -v dig >/dev/null 2>&1; then
  echo "[WARN] 'dig' no está disponible, usaré 'getent ahostsv4' como fallback."
  RESOLVE_WITH_DIG=false
fi

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
LOCK="/tmp/update_github_ips.lock"
exec 9>"$LOCK"
# flock viene en util-linux; si no está, usa un lockfile simple
if command -v flock >/dev/null 2>&1; then
  flock -n 9 || { echo "[INFO] Script ya en ejecución. Saliendo."; exit 0; }
else
  # Lockfile simple (no perfecto, pero evita ejecuciones simultáneas en la práctica)
  if ! mkdir "/tmp/.update_github_ips.lockdir" 2>/dev/null; then
    echo "[INFO] Script ya en ejecución (lockdir). Saliendo."
    exit 0
  fi
  trap 'rmdir "/tmp/.update_github_ips.lockdir" >/dev/null 2>&1 || true' EXIT
fi

############################################
# DNS
############################################
echo "==========================================="
echo "[2] Resolución DNS de dominios GitHub (IPv4)"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' RETURN

for d in "${DOMAINS[@]}"; do
  echo "-------------------------------------------"
  echo "Dominio: $d"
  if $RESOLVE_WITH_DIG; then
    echo "Comando: dig +short +time=2 +tries=2 A $d"
    dig +short +time=2 +tries=2 A "$d" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >>"$TMP" || true
  else
    echo "Comando: getent ahostsv4 $d | awk '{print \$1}'"
    getent ahostsv4 "$d" | awk '{print $1}' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >>"$TMP" || true
  fi
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
echo "[4] Validación / creación de tabla y set nftables"

# Asegurar tabla
if ! nft list table "$TABLE" "$FWTABLE" >/dev/null 2>&1; then
  echo "Comando: nft add table $TABLE $FWTABLE"
  nft add table "$TABLE" "$FWTABLE"
fi

# Asegurar set
if ! nft list set "$TABLE" "$FWTABLE" "$SETNAME" >/dev/null 2>&1; then
  echo "Comando: nft add set $TABLE $FWTABLE $SETNAME"
  nft add set "$TABLE" "$FWTABLE" "$SETNAME" '{ type ipv4_addr; flags interval; }'
fi

############################################
# ACTUALIZACIÓN SET
############################################
echo "==========================================="
echo "[5] Actualización del set nftables"

echo "Comando: nft flush set $TABLE $FWTABLE $SETNAME"
nft flush set "$TABLE" "$FWTABLE" "$SETNAME" || true

# Construir elementos "ip1, ip2, ip3"
ELEMENTS=""
printf -v ELEMENTS '%s, ' "${IPS[@]}"
ELEMENTS="${ELEMENTS%, }"

echo "Comando: nft add element $TABLE $FWTABLE $SETNAME { $ELEMENTS }"
# shellcheck disable=SC2086
nft add element "$TABLE" "$FWTABLE" "$SETNAME" { $ELEMENTS }

############################################
# VALIDACIÓN FINAL
############################################
echo "==========================================="
echo "[6] Validación final"
echo "Comando: nft list set $TABLE $FWTABLE $SETNAME"
nft list set "$TABLE" "$FWTABLE" "$SETNAME"

echo "==========================================="
echo "[OK] Proceso finalizado correctamente"
echo "[OK] Set $SETNAME actualizado con: ${IPS[*]}"
echo "==========================================="
exit 0