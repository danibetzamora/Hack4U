## Explicaciones Docker

Para crear una imagen de Docker, es necesario tener un archivo Dockerfile que defina la configuración de la imagen. Algunas de las secciones más comunes en un archivo Dockerfile son:

- FROM: se utiliza para especificar la imagen base desde la cual se construirá la nueva imagen.
- RUN: se utiliza para ejecutar comandos en el interior del contenedor, como la instalación de paquetes o la configuración del entorno.
- COPY: se utiliza para copiar archivos desde el sistema host al interior del contenedor.
- CMD: se utiliza para especificar el comando que se ejecutará cuando se arranque el contenedor.

Una vez que se tiene el Dockerfile, se puede utilizar el comando `docker build` para construir la imagen.

`docker build [opciones] ruta_al_Dockerfile`

`docker build -t mi_imagen:v1 ruta_al_Dockerfile` - Ver ejemplo en [Comandos](#Comandos)

- El parámetro `-t` permite indicar un nombre y una etiqueta a la imagen. 

Además, si se añade algo nuevo al Dockerfile y se vuelve a hacer un `docker build`, Docker se encarga de cachear todo lo que ejecutó anteriormente y lleva a cabo únicamente las nuevas instrucciones que se hayan añadido.

El comando `docker pull`  se utiliza para descargar una imagen de Docker desde un registro de imágenes.

`docker pull nombre_de_la_imagen:etiqueta` - Ver ejemplo en [Comandos](#Comandos)

El comando `docker run` se utiliza para crear y arrancar un contenedor a partir de una imagen:

- `-d` o `--detach`: se utiliza para arrancar el contenedor en segundo plano, en lugar de en primer plano.
- `-i` o `--interactive--`: se utiliza para permitir la entrada interactiva al contenedor.
- `-t` o `–tty`: se utiliza para asignar un pseudoterminal al contenedor.
- `--name`: se utiliza para asignar un nombre al contenedor

`docker run [opciones] nombre_de_la_imagen`  - Ver ejemplo en [Comandos](#Comandos)

Se puede utilizar el comando `docker ps` para listar los contenedores que están en ejecución en el sistema: 

- `-a` o `--all`: se utiliza para listar todos los contenedores, incluyendo los contenedores detenidos.
- `-q` o `--quiet`: se utiliza para mostrar sólo los identificadores numéricos de los contenedores.

Para ejecutar comandos en un contenedor que ya está en ejecución, se utiliza el comando `docker exec` con diferentes opciones:

- `-i` o `--interactive`: se utiliza para permitir la entrada interactiva al contenedor.
- `-t` o `--tty`: se utiliza para asignar un pseudoterminal al contenedor.

### Port Forwarding

El **port forwarding** nos permitirá redirigir el tráfico de red desde un puerto específico en el host a un puerto específico en el contenedor, lo que nos permitirá acceder a los servicios que se ejecutan dentro del contenedor desde el exterior.

Para este ejemplo, se procederá a montar un servidor **apache** dentro del contenedor, al cual se pretende acceder desde el host, redirigiendo la petición al contenedor gracias al **port forwarding**.

Para crear un contenedor en el que se redirijan los puertos, se deberá usar el comando `run` con el parámetro `-p`. En la sección de [Comandos](#Comandos) se podrá ver el uso del comando con más detalle.

Una vez creado, con el siguiente comando se podrá observar en el host que el puerto 80 está siendo usado por Docker. Por lo tanto, todas las peticiones que se hagan bajo ese puerto del host serán redirigidas al puerto 80 del contenedor.

	lsof -i:80

Después de esto, al acceder a la web desde el host, mediante *localhost*, o accediendo al equipo host desde otro equipo que esté en la misma red (a través de la IP del host e indicando el puerto) [192.168.1.64:80] se verá la página web por defecto de apache que está siendo enviada desde el contenedor.

Es seguro hacer que los aplicativos se encuentren dentro del contenedor, ya que si un atacante lograse tener acceso a la máquina, estaría teniendo únicamente acceso al contenedor y no al host.

Por ejemplo, si un atacante inyectase el siguiente fichero *php* en el servidor (el contenedor en este caso) podría llegar a ejecutar comandos de forma remota:

	<?php
        echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
	?>

Con esta estructura se consigue que se muestre a través del navegador el resultado de ejecutar un comando en la shell y, este comando, ejecutará cualquier comando que se le indique a través del parámetro `cmd` que es obtenido mediante el método `GET`. Por lo que si en la URL se escribe <https://localhost/cmd.php?cmd=whoami> se obtendrá el resultado por pantalla de la ejecución del comando `whoami`.

### Monturas

Las **monturas** nos permitirán compartir un directorio o archivo entre el sistema host y el contenedor, lo que será útil para guardar de forma persistente la información entre ejecuciones de contenedores y compartir datos entre diferentes contenedores.

Tal y como se puede observar en la sección [Comandos](#Comandos), con el comando `run` y el parámetro `-v` se puede hacer que el host y el contenedor compartan un directorio. De esta manera, los ficheros que se encuentren en ese directorio del host estarán también en el directorio indicado del contenedor. Además, si se lleva a cabo una modificación desde el host de uno de los archivos, los cambios se realizarán también en los archivos del contenedor y viceversa.
## Comandos

**Instalación de Docker**

	apt install docker.io

**Montaje de la imagen**

	docker build -t my_first_image:v2 .

- Busca en el directorio actual el archivo *Dockerfile*.
- Con el parámetro `-t` se especifica un nombre para la imagen.
- Se puede incrustar una etiqueta a la imagen con `:v2`.

**Descarga de imagen de los repositorios de Docker**

	docker pull debian:latest

**Visualización de las imágenes disponibles**

	docker images

- Si se añadiese el parámetro `-q` se mostrarían únicamente los identificadores de las imágenes.

**Creación y arranque de un contenedor a partir de una imagen**

	docker run -dit --name myContainer my_first_image

- Con `-d` se arranca el contenedor en segundo plano.
- Con `-i` se indica que el contenedor sea interactivo.
- Con `-t` se habilita el uso de una terminal virtual.
- Con `--name` se le puede asignar un nombre al contenedor (para no trabajar con identificadores).
- Finalmente se indica la imagen que deberá usarse para la creación del contenedor.

En el siguiente comando se realiza lo mismo pero se usa la segunda versión de la imagen:

	docker run -dit --name mySecondContainer my_first_image:v2

**Creación de contenedor con redirección de puertos**

	docker run -dit -p 80:80 --name myWebServer webserver

**Creación de un contenedor con monturas**

	docker run -dit -p 80:80 -v /home/dalnitak/docker/:/var/www/html/ --name myWebServer webserver

**Visualización de los puertos de un contenedor**

	docker port myWebServer

**Visualización de los logs de un contenedor**

	docker logs 4c8cc2efda27

**Listado de los contenedores del sistema**

	docker ps -a

- Con el parámetro `-a` se listan los contenedores activos e inactivos.
- Si únicamente se ejecuta `docker ps`, se muestran solo los contenedores activos.
- Con `-q` se mostrarían los identificadores de los contenedores activos.

**Ejecución de un contenedor por nombre (o identificador)**

	docker exec -it myContainer bash

- Al incluir `bash` al final del comando, se le especifica que ejecute una *bash* en la terminal virtual.

**Inicio de un contenedor parado**

	docker start containerName
	docker start containerID

**Parada de un contenedor activo**

	docker stop containerName
	docker stop containerID

**Borrado de una imagen**

	docker rmi imagenID

- La eliminación de una imagen eliminará también cualquier contenedor que se haya creado a partir de esa imagen.

**Borrado de todas las imágenes**

	docker rmi $(docker images -q)

**Borrado de imágenes "none"**

	docker rmi $(docker images --filter "dangling=true" -q)

**Borrado de un contenedor**

	docker rm containerID

- En caso de estar "corriendo", Docker no permitirá que se borre el contenedor. En ese caso se podría usar el parámetro `--force`.

**Borrado de todos los contenedores**

	docker rm $(docker ps -a -q) --force

- Con `$(docker ps -a -q)` se muestran todos los identificadores de todos los contenedores.



