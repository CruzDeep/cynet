#!/bin/bash
set -e

echo "------------------------------------------------------------"
echo " [INFO] Script para eliminar reglas de iptables"
echo "        Solo borra reglas existentes, no agrega ninguna nueva."
echo "------------------------------------------------------------"
echo

echo "[PASO 1] Descargando IPs oficiales de GitHub Actions..."
echo " Comando ejecutado: curl -s https://api.github.com/meta | jq -r '.actions[]'"

TMPFILE="/tmp/github_actions_ips.txt"
curl -s https://api.github.com/meta | jq -r '.actions[]' > "$TMPFILE"

if [ ! -s "$TMPFILE" ]; then
  echo "[ERROR] No se pudieron obtener IPs desde la API de GitHub."
  exit 1
fi

echo "[OK] IPs descargadas y guardadas temporalmente en: $TMPFILE"
echo

echo "[PASO 2] Eliminando reglas de iptables..."
echo " Nota: Si la regla no existe, no se muestra error."

while read ip; do
    echo " - Procesando IP: $ip"

    echo "   Comando que se enviará para comprobar si existe:"
    echo "     iptables -C INPUT -p tcp -s $ip --dport 22 -j ACCEPT"

    if iptables -C INPUT -p tcp -s "$ip" --dport 22 -j ACCEPT 2>/dev/null; then
        echo "   Comando que se enviará para eliminar la regla:"
        echo "     iptables -D INPUT -p tcp -s $ip --dport 22 -j ACCEPT"
        iptables -D INPUT -p tcp -s "$ip" --dport 22 -j ACCEPT
        echo "     - Regla eliminada."
    else
        echo "     = La regla NO existía, nada que borrar."
    fi
done < "$TMPFILE"

echo
echo "[PASO 3] Guardando reglas persistentes..."

if command -v netfilter-persistent &>/dev/null; then
    echo " Comando ejecutado: netfilter-persistent save"
    netfilter-persistent save
elif command -v iptables-save &>/dev/null; then
    echo " Comando ejecutado: iptables-save > /etc/iptables/rules.v4"
    iptables-save > /etc/iptables/rules.v4
else
    echo "[ADVERTENCIA] No se encontró un método para guardar reglas."
fi

echo
echo "------------------------------------------------------------"
echo "[OK] Script terminado correctamente."
echo "------------------------------------------------------------"
