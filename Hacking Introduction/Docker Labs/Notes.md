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

**Creación y arranque de un contenedor a partir de una imagen**

	docker run -dit --name myContainer my_first_image

- Con `-d` se arranca el contenedor en segundo plano.
- Con `-i` se indica que el contenedor sea interactivo.
- Con `-t` se habilita el uso de una terminal virtual.
- Con `--name` se le puede asignar un nombre al contenedor (para no trabajar con identificadores).
- Finalmente se indica la imagen que deberá usarse para la creación del contenedor.

En el siguiente comando se realiza lo mismo pero se usa la segunda versión de la imagen:

	docker run -dit --name mySecondContainer my_first_image:v2

**Listado de los contenedores del sistema**

	docker ps -a

- Con el parámetro `-a` se listan los contenedores activos e inactivos.
- Si únicamente se ejecuta `docker ps`, se muestran solo los contenedores activos.
- Con `-q` se mostrarían los identificadores de los contenedores.

**Ejecución de un contenedor por nombre (o identificador)**

	docker exec -it myContainer bash

- Al incluir `bash` al final del comando, se le especifica que ejecute una *bash* en la terminal virtual.


