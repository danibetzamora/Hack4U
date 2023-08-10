#!/bin/bash

function ctrl_c(){
  echo -e "\n\n[!] Saliendo...\n"
  tput cnorm
  exit 1
}

tput civis

# Ctrl + C
trap ctrl_c SIGINT

for i in $(seq 1 254); do
  timeout 1 bash -c "ping -c 1 192.168.1.$i" &>/dev/null && echo "[+] Host 192.168.1.$i - ACTIVE" &
done

wait

tput cnorm
