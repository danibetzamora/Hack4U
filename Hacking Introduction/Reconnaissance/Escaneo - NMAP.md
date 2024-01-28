## Comandos Generales NMAP

**Información acerca de la red (router, network ID, netmask...)**

	route -n

**Escaneo de los puertos más comunes de la IP indicada**

	nmap 192.168.1.1

**Escaneo de un puerto concreto**

	nmap -p22 192.168.1.1

**Escaneo del rango de los 100 primeros puertos**

	nmap -p1-100 192.168.1.1

**Escaneo del rango de puertos entero**

	nmap -p- 192.168.1.1

**Escaneo de los 500 puertos más comunes**

	nmap --top-ports 500 192.168.1.1

**Escaneo de todos los puertos abiertos**

	nmap -p- --open 192.168.1.1

**Escaneo sin resolución DNS para agilizar escaneo (parámetro `-n`)**

	nmap -p- --open 192.168.1.1 -v -n

**Modos de escaneo**

	nmap -p- --open -T5 192.168.1.1 -v -n 

- El parámetro `-T` hace uso de 6 plantillas distintas de escaneo.

**Con el parámetro `-Pn` damos por hecho que el host está activo (sin resolución ARP)**

	nmap -p- --open -T5 192.168.1.1 -v -n -Pn

**Análisis de los activo existentes en la red**

	nmap -sn 192.168.1.0/24

**REGEX para obtener solo las IP**

	nmap -sn 192.168.1.0/24 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

**Información sobre el Sistema Operativo y las versiones del host**

	nmap -O 192.168.1.64

**Obtener información sobre la versión y el servicio que corre por un puerto**

	nmap -p22,80 -sV 192.168.1.1

### Tipos de Escaneo (algunos de ellos)

**Escaneo TCP Connect:** Completa la conexión TCP

	nmap -p22 -sT --open 192.168.1.1 -v -n

**Escaneo SYN:** No termina la conexión (manda un SYN, recibe un SYN/ACK, y manda RST)

	nmap -p22 -sS --open --min-rate 5000 192.168.1.1 -v -n

- Es más sigiloso y no deja rastro.
- Los Firewalls no almacenan los logs
- `--min-rate` sive para indicarle que queremos tramitar paquetes a una velocidad no más lenta que 5000 paquetes por segundo

### Evasión de Firewalls

**Fragmentación de paquetes enviados**

	nmap -p22 192.168.1.1 -f

**Spoofing de Dirección IP para que también envíe paquetes**

	nmap -p22 192.168.1.1 -D 192.168.1.225

- A veces hay direcciones IP bloqueadas por los Firewalls

**Indicación de puerto de origen**

	nmap -p22 --open --source-port 53 -T5 -v -n 192.168.1.1

- En ocasiones los Firewalls conocen los puertos usados por nmap

**Cambio de tamaño de los paquetes enviados**

	nmap -p22 192.168.1.1 --data-length 21

- Los Firewalls saben los tamaños usados por nmap

Falsificación de la MAC

	nmap -p22 192.168.1.1 --spoof-mac 00:11:22:33:44:55 -Pn

## Scripts de NMAP

**Localización de todos los scripts usados por nmap**

	locate .nse

**Escaneo del servicio y la versión que corren por un puerto y lanzamiento de scripts básicos**

	nmap -p22 192.168.1.1 -sCV

- *http-robots* es un script de detección de directorios en una web

**Existen varias categorías de scripts en nmap**

	locate .nse | xargs grep "categories"

- De esta manera, se pueden ver las categorías de cada uno de los scripts

**Visualización de todas las categorías (hay 14)** 

	locate .nse | xargs grep "categories" | grep -oP '".*?"' | sort -u

**Lanzamiento de scripts que pertenezcan a la categoría "vuln" y la de "safe"**

	nmap -p22 192.168.1.1 --script="vuln and safe"

### Prueba de Scripts en un servidor local

**Montaje de servidor en local con python**

	python3 -m http.server 80

**Comprobación de qué está corriendo por un puerto**

	lsof -i:80

**Forma de ver en que directorio se está ejecutando un proceso**

	pwdx 16265

**Script de enumeración de directorios en una web (fuzzing)**

	nmap -p80 192.168.1.64 --script http-enum

**Intercepción de tráfico en interfaz de loopback**

	tcpdump -i lo -w captura.cap -v

**Lanzamos tshark para visualizar captura**

	tshark -r captura.cap 2>/dev/null

**Filtramos por protocolo HTTP**

	tshark -r captura.cap -Y "http" 2>/dev/null

## MASSCAN

**Herramienta de escaneo parecida a nmap**

	masscan -p21,22,445,8080,80,443 -Pn 192.168.0.0/16 --rate=10000


## Análisis de Red

**Muestra las interfaces de red disponibles**

	iwconfig

**Herramienta usada para capturar los paquetes enviados y recibidos en la red**

	tcpdump -i ens33 -w captura.cap -v

**Con wireshark se analiza la captura de paquetes recién realizada**

	wireshark captura.cap &>/dev/null & disown

- En wireshark: `tcp.port == 22` -> Filtra por las conexiones por TCP en el puerto 22
- En wireshark: `ip.flags.mf == 1` -> Filtro para buscar por paquetes fragmentados (Los no fragmentados serían con un 0)	
- En wireshark: `ip.dst == 192.168.1.1` / `ip.src == 192.168.1.1` -> Indicar IP de origen o de destino

**Manera de sacar equipos conectados a la red**

	arp-scan -I ens33 --localnet


