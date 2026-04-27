#!/bin/bash

LOGFILE="$(pwd)/reporte.log"

# Forzar bash y manejar errores
set -o pipefail

# Redirección correcta
exec > >(tee -a "$LOGFILE") 2>&1

echo "================================================="
echo " HEALTH CHECK UBUNTU - CYNET / KERNEL ANALYSIS"
echo " Fecha     : $(date)"
echo " Host      : $(hostname)"
echo " Usuario   : $(whoami)"
echo "================================================="
echo

########################
# 1. VERSION KERNEL / SISTEMA
########################
echo "=== 1. VERSION DE SISTEMA / KERNEL ==="
uname -a
echo "Uptime: $(uptime -p)"
echo

########################
# 2. DRIVERS / MODULOS
########################
echo "=== 2. DRIVERS / KERNEL MODULES (Top 20) ==="
lsmod | head -n 20
echo

########################
# 3. CONSUMO DE DISCO
########################
echo "=== 3. CONSUMO DE DISCO (GB) ==="
df -h --total | grep -E 'Filesystem|total'
echo

########################
# 4. USO DE MEMORIA
########################
echo "=== 4. USO DE MEMORIA (RAM) ==="
free -h
echo

########################
# 5. TOP 10 PROCESOS MEMORIA
########################
echo "=== 5. TOP 10 PROCESOS QUE MÁS MEMORIA CONSUMEN ==="
ps aux --sort=-%mem | head -n 11
echo

########################
# 6. I/O WAIT
########################
echo "=== 6. CPU - I/O WAIT ==="
top -bn1 | grep "Cpu(s)" | awk '{print "Carga de espera (I/O Wait): " $10 "%"}'
echo

########################
# 7. KERNEL ERRORS (journalctl general)
########################
echo "=== 7. ERRORES DEL KERNEL (journalctl -p err) ==="
journalctl -k -p err --no-pager | tail -n 50
echo

########################
# 8. KERNEL LOGS FILTRADOS (panic, oom, cynet, segfault)
########################
echo "=== 8. KERNEL LOGS CRÍTICOS (panic | oom | cynet | segfault) ==="
journalctl -t kernel -n 100 --no-pager | grep -iE "panic|out of memory|killed|tainted|cynet|segfault"
echo

########################
# 9. KERNEL TAINT CHECK
########################
echo "=== 9. KERNEL TAINT STATUS ==="
TAINT=$(cat /proc/sys/kernel/tainted)

if [ "$TAINT" -eq "0" ]; then
    echo "Kernel Limpio (0) - No módulos externos problemáticos"
else
    echo "Kernel TAINTED ($TAINT) - Un driver externo alteró el núcleo"
fi
echo

########################
# 10. DMESG - BLACK BOX / STACK TRACE
########################
echo "=== 10. DMESG STACK TRACE (err / crit) ==="
dmesg -T --level=err,crit | tail -n 20
echo

########################
# 11. DMESG - WARNINGS
########################
echo "=== 11. DMESG WARNINGS ==="
dmesg -T --level=warn | tail -n 20
echo

echo "================================================="
echo " FIN DEL REPORTE"
echo "================================================="