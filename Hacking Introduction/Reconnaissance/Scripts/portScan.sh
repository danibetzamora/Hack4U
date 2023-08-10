#!/bin/bash

function ctrl_c(){
	echo -e "\n\n[!] Saliendo...\n"
  tput cnorm
  exit 1
}

# Ctrl + C
trap ctrl_c SIGINT

declare -a ports=( $(seq 1 65535) )

# Uso de descriptores de archivo y código de error
function checkPort(){
  (exec 3<> /dev/tcp/$1/$2) 2>/dev/null
  
  if [ $? -eq 0 ]; then
    echo "[+] Host $1 - Port $2 (OPEN)"
  fi

  exec 3<&-
  exec 3>&-
}

tput civis # Ocultar el cursor

# Iteración sobre todos los puertos 
if [ $1 ]; then
  for port in ${ports[@]}; do
    checkPort $1 $port &
  done
else
  echo -e "\n[!] Uso: $0 <ip-address>\n"
fi

wait

tput cnorm # Devolver cursor
