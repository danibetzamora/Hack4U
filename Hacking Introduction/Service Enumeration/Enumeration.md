## Enumeración del servicio FTP

El **File Transfer Protocol** (FTP) trabaja bajo el puerto **21**. 

La enumeración del servicio FTP implica recopilar información relevante, como la versión del servidor FTP, la configuración de permisos de archivos, los usuarios y las contraseñas (mediante ataques de fuerza bruta o guessing), entre otros.

Existen dos formas de acceder a los recursos suministrados mediante FTP. En el primer caso, bastará con introducir el usuario *anonymous* sin contraseña para poder acceder a los recursos. Sin embargo, existe la posibilidad de necesitar un usuario y una contraseña para acceder a los ficheros listados mediante FTP.

Para llevar a cabo esta práctica, se hará uso del siguiente repositorio, mediante el cual se podrá montar un contenedor de Docker que disponga de un servicio FTP: [Docker-FTP-Server](https://github.com/garethflowers/docker-ftp-server).

Además, se hará uso de un diccionario para realizar un ataque de fuerza bruta y obtener la contraseña del usuario con acceso al servicio FTP. Uno de los diccionarios que pueden ser usados es el **rockyou** ("/usr/share/wordlists/rockyou.txt"). De la siguiente manera podemos obtener una línea concreta del diccionario:

	cat /usr/share/wordlists/rockyou.txt | awk "NR==132"

El comando usado para crear el contenedor de Docker fue el siguiente:

	docker run \
        --detach \
        --env FTP_PASS=louise \
        --env FTP_USER=dalnitak \
        --name my-ftp-server \
        --publish 20-21:20-21/tcp \
        --publish 40000-40009:40000-40009/tcp \
        --volume /data:/home/user \
        garethflowers/ftp-server

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

![[hydra.png]]

Para el siguiente caso práctico se hará uso del siguiente repositorio: [Docker-ANON-FTP](https://github.com/metabrainz/docker-anon-ftp).

En este caso, se trata de enumerar un servicio FTP que disponga de un usuario invitado *anonymous* sin contraseña.

Con el siguiente comando se creará el contenedor:

	docker run -d -p 20-21:20-21 -p 65500-65515:65500-65515 -v /tmp:/var/ftp:ro metabrainz/docker-anon-ftp

Si ahora se vuelve a hacer el mismo escaneo que se hizo antes con **nmap**, los scripts básicos de nmap reportarán que existe un usuario *anonymous*:

![[2023-08-21_11-40.png]]

