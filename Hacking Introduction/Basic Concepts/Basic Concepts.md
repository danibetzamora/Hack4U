## Direcciones IP (IPv4 e IPv6)

### Direcciones IPv4
 
- Dirección IPV4 = 32 bits = 4 octetos de 8 bits.
- Número de direcciones IPV4 diferentes = 2^32 = 4 mil millones (echo "2^32" | bc).
- Insuficientes direcciones para todo el mundo (de ahí nace la necesidad de IPV6).

**Ejemplo de dirección IPv4**: 192.168.111.42

### Direcciones IPv6

- Dirección IPV6 = 128 bits = 8 conjuntos de 16 bits en hexadecimal.

**Ejemplo de dirección IPv6**: 2001:0db8:85a3:0000:0000:8a2e:0370:7334

### Comandos relacionados

- Obtener IP de la máquina en Linux: `ifconfig` o `hostname -I`.
- Obtener la Dirección IP en binario en terminal:

		echo "obase=2;192;168;1;45" | bc

## Direcciones MAC

- Dirección MAC = Dirección Física -> Es "única" para cada dispositivo.
- Ejemplo de dirección MAC -> 00:0c:29:e1:6d:92 -> 12 Dígitos = 6 bytes = 48 bits de dirección.

Las direcciones MAC se dividen en dos:

1. Primeros 3 bytes -> **Identificador Único Organizacional** (OUI).
2. Últimos 3 bytes -> **Controlador de Interfaz de Red** (NIC).

Los primeros 3 bytes (24 bits) representan el fabricante de la tarjeta, y los últimos 3 bytes (24 bits) identifican la tarjeta particular de ese fabricante. Cada grupo de 3 bytes se puede representar con 6 dígitos hexadecimales, formando un número hexadecimal de 12 dígitos que representa la MAC completa.

- **macchanger**: Herramienta usada para cambiar la dirección MAC o listar los diferentes OUI asignados a los proveedores.

Lista todos los OUI asociados a los proveedores:

	macchanger -l
 
## Protocolos UDP y TCP 

Nos ponemos en escucha por el puerto 4646 con netcat:

	nc -nlvp 4646

Nos envíamos datos a nosotros mismos con netcat por el puerto 4646:

	nc 192.168.1.64 4646

En wireshark (abrir con root), veremos en loopback el Three-Way Handshake (SYN, SYN-ACK, ACK):

	wireshark &> /dev/null & disown

### Puertos TCP comunes:

- **21**: **FTP** (File Transfer Protocol) - Permite la transferencia de archivos entre sistemas.
- **22**: **SSH** (Secure Shell) - Un protocolo de red seguro que permite conectarse y administrar sistemas de forma remota.
- **23**: **Telnet** – Un protocolo utilizado para la conexión remota a dispositivos de red.
- **80**: **HTTP** (Hypertext Transfer Protocol) – El protocolo que se utiliza para la transferencia de datos en Internet.
- **443**: **HTTPS** (Hypertext Transfer Protocol Secure) – La versión segura de HTTP.

### Puertos UDP comunes:

- **53**: **DNS** (Domain Name System) – Un sistema que traduce nombres de dominio en direcciones IP.
- **67/68**: **DHCP** (Dynamic Host Configuration Protocol) – Un protocolo utilizado para asignar direcciones IP en una red.
- **69**: **TFTP** (Trivial File Transfer Protocol) – Un protocolo para transferir archivos entre dispositivos en una red.
- **123**: **NTP** (Network Time Protocol) – Un protocolo utilizado para sincronizar los relojes de los dispositivos en una red.
- **161**: **SNMP** (Simple Network Management Protocol) – Un protocolo para administrar y supervisar dispositivos en una red.

## Modelo OSI

1. **Capa física**: Es la capa más baja del modelo OSI, que se encarga de la transmisión de datos a través del medio físico de la red, como cables de cobre o fibra óptica.

2. **Capa de enlace de datos**: Esta capa se encarga de la transferencia confiable de datos entre dispositivos en la misma red. También proporciona funciones para la detección y corrección de errores en los datos transmitidos.

3. **Capa de red**: La capa de red se ocupa del enrutamiento de paquetes de datos a través de múltiples redes. Esta capa utiliza direcciones lógicas, como direcciones IP, para identificar dispositivos y rutas de red.

4. **Capa de transporte**: La capa de transporte se encarga de la entrega confiable de datos entre dispositivos finales, proporcionando servicios como el control de flujo y la corrección de errores.

5. **Capa de sesión**: Esta capa se encarga de establecer y mantener las sesiones de comunicación entre dispositivos. También proporciona servicios de gestión de sesiones, como la autenticación y la autorización.

6. **Capa de presentación**: La capa de presentación se encarga de la representación de datos, proporcionando funciones como la codificación y decodificación de datos, la compresión y el cifrado.

7. **Capa de aplicación**: La capa de aplicación proporciona servicios para aplicaciones de usuario finales, como correo electrónico, navegadores web y transferencia de archivos.

## Subnetting

**Máscara de red (Netmask)**: Los bits a 1 representan la porción de la IP que corresponde a la red, y los bits a 0 a los hosts.

- Netmask 255.255.255.0: Los tres primeros octetos corresponden a la red y el último a los hosts.

**CIDR (Classless Inter-Domain Routing)**: Una IP se representa mediante una dirección IP base y una Netmask (indicada con una /).

- 192.168.1.0/24: El "/24" indica que hay 24 bits de la IP correspondientes a la red, es decir Netmask = 255.255.255.0

Para **calcular la máscara de red** a partir de CIDR, se deben poner a 1 los primeros bits de una dirección IP (los que indique el prefijo), y el resto a 0.

Para **calcular la cantidad de hosts disponibles en una red** CIDR, se deben contar el número de bits "0" en la Netmask y elevar 2 a ese número.

- 255.255.255.0 (/24) -> Tiene 8 bits en "0" (32 totales - 24 de red = 8 de hosts) -> 2^8 = 256 IP para hosts en esa red.
- A los hosts totales resultantes hay que restarles 2, ya que una dirección IP es para la "red" y otra para "broadcast".

Para **calcular el Network ID**, lo que debemos hacer es aplicar la máscara de red a la dirección IP de la red. Veamos el ejemplo:

- **IP de la red**: 192.168.1.3/26 = 11000000.10101000.00000001.00000011/26
- **Netmask**: 255.255.255.192 = 11111111.11111111.11111111.11000000
- **Network ID o Dirección de red**: Se hace un AND entre la Netmask y la dirección IP (ambos en binario).
	```
	-----------------------------------
	11111111.11111111.11111111.11000000 -> Netmask
	
	AND
	
	11000000.10101000.00000001.00000011 -> IP
	-----------------------------------
	11000000.10101000.00000001.00000000 = 192.168.1.0 -> Network ID
	```

Para **calcular la Broadcast Address**, debemos asignar todos los bits de la parte del host de la dirección IP de red a 1.

- En este caso, la dirección IP es 192.168.1.0 y se convierte en binario como 11000000.10101000.00000001.00000011
- Como el prefijo es /26 sabemos que los últimos 6 bits corresponden a los hosts (32 totales - 26 de prefijo = 6 de hosts).
- Ponemos los bits de host a "1" y obtendremos la dirección de broadcast -> 11000000.10101000.00000001.00111111
- Por lo que la Broadcast Address es -> 192.168.1.63
- Esta es la dirección a la que se enviarán los paquetes para llegar a todos los hosts de la subred.

### Tipos de Máscaras de Red 

- **Clase A**: Usan Netmask de 255.0.0.0 y tienen de 0 a 127 como su primer octeto (10.52.36.11)

- **Clase B**: Usan Netmask de 255.255.0.0 y tienen de 128 a 191 como su primer octeto (172.16.52.63)

- **Clase C**: Usan Netmask de 255.255.255.0 y tienen de 192 a 223 como su primer octeto (192.168.123.132)