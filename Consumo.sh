#!/bin/bash

echo "=============================="
echo " HEALTH CHECK UBUNTU"
echo " Fecha: $(date)"
echo " Host: $(hostname)"
echo "=============================="
echo

###############
# DRIVERS / MÓDULOS
###############
echo "=== DRIVERS (Kernel Modules cargados) ==="
lsmod | head -n 20
echo

###############
# CONSUMO DE DISCO
###############
echo "=== CONSUMO DE DISCO (GB) ==="
df -h --total | grep -E 'Filesystem|total'
echo

###############
# USO DE MEMORIA
###############
echo "=== USO DE MEMORIA (RAM) ==="
free -h
echo

###############
# TOP 10 PROCESOS POR MEMORIA
###############
echo "=== TOP 10 PROCESOS QUE MÁS MEMORIA CONSUMEN ==="
ps aux --sort=-%mem | head -n 11
echo

###############
# ERRORES DEL KERNEL
###############
echo "=== ERRORES DEL KERNEL (journalctl) ==="
journalctl -k -p err --no-pager | tail -n 50
echo

echo "=== ERRORES DEL KERNEL (dmesg) ==="
dmesg --level=err,warn | tail -n 50
echo

echo "=============================="
echo " FIN DEL REPORTE"
echo "=============================="