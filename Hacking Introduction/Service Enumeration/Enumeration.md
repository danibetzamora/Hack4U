## Enumeración del servicio FTP

El **File Transfer Protocol** (FTP) trabaja bajo el puerto **21**. 

La enumeración del servicio FTP implica recopilar información relevante, como la versión del servidor FTP, la configuración de permisos de archivos, los usuarios y las contraseñas (mediante ataques de fuerza bruta o guessing), entre otros.

Existen dos formas de acceder a los recursos suministrados mediante FTP. En el primer caso, bastará con introducir el usuario *anonymous*, sin contraseña, para poder acceder a los recursos. Sin embargo, existe la posibilidad de necesitar un usuario y una contraseña para acceder a los ficheros listados mediante FTP.

Para llevar a cabo esta práctica, se hará uso del siguiente repositorio, mediante el cual se podrá montar un contenedor de Docker que disponga de un servicio FTP: [Docker-FTP-Server](https://github.com/garethflowers/docker-ftp-server).

Además, se hará uso de un diccionario para realizar un ataque de fuerza bruta y obtener la contraseña del usuario con acceso al servicio FTP. Uno de los diccionarios que pueden ser usados es el **rockyou** ("/usr/share/wordlists/rockyou.txt/"). De la siguiente manera podemos obtener una línea concreta del diccionario:

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


## Enumeración del servicio SMB

**SMB** significa **Server Message Block**, es un **protocolo** de comunicación de red utilizado para compartir archivos, impresoras y otros recursos entre dispositivos de red. Es un protocolo de **Microsoft** que se utiliza en sistemas operativos **Windows**.

**Samba**, por otro lado, es una implementación libre y de código abierto del **protocolo SMB**, que se utiliza principalmente en sistemas operativos basados en **Unix** y **Linux**. Samba proporciona una manera de compartir archivos y recursos entre dispositivos de red que ejecutan sistemas operativos diferentes, como Windows y Linux.

En esta ocasión se hará uso del siguiente repositorio de GitHub, el cual contiene el laboratorio vulnerable para montar un servidor samba: [Samba Authenticated RCE](https://github.com/vulhub/vulhub/tree/master/samba/CVE-2017-7494).

La finalidad principal es enumerar correctamente este servicio, para detectar vulnerabilidades que puedan ser explotadas posteriormente.

Una vez desplegado el laboratorio, si a través de nmap se detecta que el puerto 445 está abierto (puerto correspondiente a SMB), se puede empezar la numeración con **smbclient**. Esta herramienta permite listar los recursos compartidos existentes a nivel de red. A continuación se muestra un ejemplo de uso:

	smbclient -L 127.0.0.1 -N

- El parámetro `-L` indica que se quiere listar todo recurso existente.
- El parámetro `-N` se usa cuando no se dispone de credenciales válidas (sesión nula).

Además de estos parámetros, también son comunes los siguientes con smbclient:

- **-U**: Este parámetro se utiliza para especificar el nombre de usuario y la contraseña utilizados para la autenticación con el servidor SMB o Samba.
- **-c**: Este parámetro se utiliza para especificar un comando que se ejecutará en el servidor SMB o Samba.

De forma alternativa existe **smbmap**. Smbmap es una herramienta de línea de comandos utilizada para enumerar recursos compartidos y permisos en un servidor SMB (Server Message Block) o Samba. Es una herramienta muy útil para la enumeración de redes y para la identificación de posibles vulnerabilidades de seguridad.

A continuación se muestra el uso de algunos de sus parámetros:

- **-H**: Este parámetro se utiliza para especificar la dirección IP o el nombre de host del servidor SMB al que se quiere conectarse.
- **-P**: Este parámetro se utiliza para especificar el puerto TCP utilizado para la conexión SMB. El puerto predeterminado para SMB es el 445, pero si el servidor SMB está configurado para utilizar un puerto diferente, este parámetro debe ser utilizado para especificar el puerto correcto.
- **-u**: Este parámetro se utiliza para especificar el nombre de usuario para la conexión SMB.
- **-p**: Este parámetro se utiliza para especificar la contraseña para la conexión SMB.
- **-d**: Este parámetro se utiliza para especificar el dominio al que pertenece el usuario que se está utilizando para la conexión SMB.
- **-s**: Este parámetro se utiliza para especificar el recurso compartido específico que se quiere enumerar. Si no se especifica, smbmap intentará enumerar todos los recursos compartidos en el servidor SMB.

En el caso práctico, se encontró una carpeta llamada "**myshare**" con capacidad de lectura y escritura, por lo que podríamos conectarnos a ella mediante smbclient de la siguiente forma:

	smbclient //127.0.0.1/myshare -N

- Ya conectados podríamos ejecutar comandos propios de SMB, como `put`, `get`, `dir`...

Sin embargo, el problema es que si accediéramos a un servidor SMB en el que hubieran muchos directorios y archivos, sería muy complicado navegar entre ellos. Por eso mismo, si montamos la carpeta del servidor SMB en nuestro equipo local con el siguiente comando, tendremos un acceso mucho más sencillo a todos los recursos:

	mount -t cifs //127.0.0.1/myshare /mnt/mounted

Para desmontarlo, simplemente se deberá hacer lo siguiente:

	umount /mnt/mounted


## Enumeración de WordPress

**WordPress** es uno de los gestores de contenido (CMS) más famosos en la actualidad. A lo largo de este apartado se estudiará como enumerarlo.

En primer lugar, se procederá con la clonación del siguiente repositorio: [DVWP](https://github.com/vavkamil/dvwp). En este repositorio se encuentra el proyecto que se utilizará para enumerar WordPress.

Una vez clonado, se deberá ejecutar el siguiente comando de **docker-compose** para crear el contenedor:

	docker-compose up -d --build

**ADVERTENCIA**: Al ejecutar este comando, se crean unos volúmenes en Docker con toda la información del contenedor. Existen varios comandos para listar y eliminar estos volúmes:

***LISTAR VOLÚMENES***

	docker volume ls

***ELIMINAR VOLÚMENES***

	docker volume rm $(docker volume ls -q)

En caso de querer volver a usar el proyecto de WordPress en Docker desde 0, será necesario borrar estos dos volúmenes antes de volver a usarlo o crearlo. Pues, de lo contrario, aunque volvamos a clonar el repositorio y a crear el contenedor, se seguirá manteniendo toda la información almacenada de otras veces.

Una vez creado el usuario y demás (accediendo al panel de WordPress desde: "**localhost:31337**"), se deberá ejecutar el siguiente comando para que se instalen los plugins necesarios:

	docker-compose run --rm wp-cli install-wp

Si se quisieran "apagar" los contenedores creados, se debe usar el siguiente comando:

	docker-compose down

### SEARCHSPLOIT

A continuación se hace uso de la utilidad '**searchsploit**', la cual está sincronizada con la web **exploit-db**, en la que pueden encontrarse todo tipo de exploits.

	searchsploit wordpress user enumeration

- De esta forma se podría buscar en la base de datos exploits que permitan enumerar los usuarios relacionados con una página WordPress.

*Imagen*

Con **searchsploit** se pueden examinar los archivos en los que se encuentran los exploits de la siguiente manera:

	searchsploit -x 41497.php

- El parámetro `-x` se usa para *examinar* un archivo.
- En este caso, el archivo se obtuvo después de aplicar la búsqueda para enumerar usuarios en WP.

### WPSCAN

Sin embargo, una de las herramientas que utilizamos en esta clase para enumerar este gestor de contenido es **Wpscan**. Wpscan es una herramienta de código abierto que se utiliza para escanear sitios web en busca de vulnerabilidades de seguridad en WordPress.

Con Wpscan, podemos realizar una enumeración completa del sitio web y obtener información detallada sobre la instalación de WordPress, como la versión utilizada, los plugins y temas instalados y los usuarios registrados en el sitio. También nos permite realizar pruebas de fuerza bruta para descubrir contraseñas débiles y vulnerabilidades conocidas en plugins y temas.

Se puede instalar con el siguiente comando:

	gem install wpscan

Y para usarlo, bastará con ejecutar la siguiente orden, indicando una URL de un sitio web hecho con WordPress:

	wpscan --url http//127.0.0.1:31337

Si se desea enumerar usuarios o plugins vulnerables en WordPress utilizando la herramienta wpscan, puedes añadir los siguientes parámetros a la línea de comandos:

	wpscan --url http//127.0.0.1:31337 --enumerate vp,u

En caso de querer enumerar más vulnerabilidades de los plugins, deberemos hacernos una cuenta en **wpscan** para obtener un *api token*. Una vez obtenido, se podrá ejecutar el siguiente comando:

	wpscan --url http://127.0.0.1:31337 -e vp --api-token="GJ6DtvnSQk63DjacadfATOnoGx41Ikf9utvZ702vdrY"

También, con esta herramienta puede hacerse uso de un diccionario para realizar un ataque de fuerza bruta, pudiendo obtener las credenciales de acceso:

	wpscan --url http://localhost:31337 -U dalnitak -P /usr/share/wordlists/rockyou.txt

### Escaneo de plugins manual

Existe una forma de enumerar los plugins de forma manual. En el siguiente directorio de **Wordpress** se deberían listar todos los plugins que están siendo usados en un directorio (Directory Listing): <http://localhost:31337/wp-content/plugins/>. 

Sin embargo, en el ejemplo práctico, esta ruta no mostraba nada a través del navegador. En caso de que ocurra esto, se podría obtener información de esta ruta haciendo una petición mediante el método **GET** del protocolo **HTTP** con el comando `curl`, de la siguiente manera:

	curl -s -X GET "http://localhost:31337/"

De esta forma, obtendremos el código fuente de esta ruta de **Wordpress**. En el código fuente, podremos ver varias rutas en las que se contempla la palabra *plugin*, por lo que filtrando con una expresión regular de la siguiente forma podremos obtener los plugins disponibles en el sitio web en concreto:

	curl -s -X GET "http://localhost:31337/" | grep -oP '/plugins/\K[^/]+' | sort -u

Por lo que esto es una forma alternativa de enumerar los plugins que están siendo usados en un sitio web que haga uso de Wordpress.

### XMLRPC

Asimismo, otro de los recursos que contemplamos en esta clase es el archivo **xmlrpc.php**. Este archivo es una característica de WordPress que permite la comunicación entre el sitio web y aplicaciones externas utilizando el protocolo **XML-RPC**.

El archivo xmlrpc.php es utilizado por muchos plugins y aplicaciones móviles de WordPress para interactuar con el sitio web y realizar diversas tareas, como publicar contenido, actualizar el sitio y obtener información.

Sin embargo, este archivo también puede ser abusado por atacantes malintencionados para aplicar **fuerza bruta** y descubrir **credenciales válidas** de los usuarios del sitio. Esto se debe a que xmlrpc.php permite a los atacantes realizar un número ilimitado de solicitudes de inicio de sesión sin ser bloqueados, lo que hace que la ejecución de un ataque de fuerza bruta sea relativamente sencilla.

Por lo que, antes que nada, será necesario ver si el archivo *xmlrpc.php* está expuesto o no. Simplemente se deberá buscar la siguiente URL: <http://localhost:31337/xmlrpc.php/>.

*Imagen*

Como se puede observar en la imagen, el servidor solo acepta peticiones por **POST**. Por eso mismo, se deberá realizar una petición por POST de la siguiente manera:

	curl -s -X POST "http://localhost:31337/xmlrpc.php/"ç

Esto devolverá un error, ya que la petición por POST no está bien formada. Para que sea correcta, se deberá enviar una estructura bien formada de XML.

Para realizar una petición que contenga un archivo XML bien estructurado, podremos realizar una búsqueda simple en Google de la siguiente forma: "*abusing xmlrpc.php wordpress*". Tras realizar dicha búsqueda, se muestra un ejemplo de archivo XML:

```xml
<?xml version="1.0" encoding="utf-8"?> 
<methodCall> 
<methodName>system.listMethods</methodName> 
<params></params> 
</methodCall>
```

Para comprobar que la petición por POST ahora funciona correctamente, se deberá ejecutar el siguiente comando:

	curl -s -X POST "http://localhost:31337/xmlrpc.php" -d@file.xml

- El parámetro `-d@`, seguido del nombre del archivo, sirve para indicar el nombre del archivo que se incluirá en la petición que se va a realizar.

Sabiendo esto, podemos hacer uso de la siguiente estructura de XML, en la cual se puede introducir un nombre de usuario y una contraseña. Al realizar una petición por POST adjuntando este archivo, el servidor nos responderá o con un mensaje de error (usuario o contraseña incorrectos), o con una estructura XML que nos dice que el usuario y la contraseña son correctos, aparte de darnos más información. 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<methodCall> 
<methodName>wp.getUsersBlogs</methodName> 
<params> 
<param><value>dalnitak</value></param> 
<param><value>louise</value></param> 
</params> 
</methodCall>
```

De esta manera, podría realizarse un script en bash que permita aplicar fuerza bruta, haciendo uso de esta estructura XML, para obtener las credenciales de administrador de un sitio web hecho con Wordpress. Dejo el enlace directo al script en cuestión: [Fuerza Bruta Wordpress - Bash Script](xmlrpc_bruteforce.sh).








