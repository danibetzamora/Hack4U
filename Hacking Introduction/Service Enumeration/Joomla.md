## Enumeración de Joomla

En esta clase, estaremos viendo cómo enumerar el gestor de contenido **Joomla**. Joomla es un sistema de gestión de contenidos (CMS) de código abierto que se utiliza para **crear sitios web** y **aplicaciones en línea**. Joomla es muy popular debido a su facilidad de uso y flexibilidad, lo que lo hace una opción popular para sitios web empresariales, gubernamentales y de organizaciones sin fines de lucro.

Joomla es altamente personalizable y cuenta con una gran cantidad de extensiones disponibles, lo que permite a los usuarios añadir funcionalidades adicionales a sus sitios web sin necesidad de conocimientos de programación avanzados. Joomla también cuenta con una comunidad activa de desarrolladores y usuarios que comparten sus conocimientos y recursos para mejorar el CMS.

A continuación, se comparte el enlace del proyecto que estaremos desplegando en Docker para auditar un Joomla:

- **CVE-2015-8562**: [https://github.com/vulhub/vulhub/tree/master/joomla/CVE-2015-8562](https://github.com/vulhub/vulhub/tree/master/joomla/CVE-2015-8562)

Una vez clonado el repositorio a través de la utilidad `svn`, podremos iniciar el contenedor de Docker ejecutando el comando de siempre:

	docker-compose up -d

Una de las herramientas que usamos en esta clase es **Joomscan**. Joomscan es una herramienta de línea de comandos diseñada específicamente para escanear sitios web que utilizan Joomla y buscar posibles vulnerabilidades y debilidades de seguridad.

Joomscan utiliza una variedad de técnicas de enumeración para identificar información sobre el sitio web de Joomla, como la versión de Joomla utilizada, los plugins y módulos instalados y los usuarios registrados en el sitio. También utiliza una base de datos de vulnerabilidades conocidas para buscar posibles vulnerabilidades en la instalación de Joomla.

Para utilizar Joomscan, primero debemos descargar la herramienta desde su sitio web oficial. A continuación se proporciona el enlace al proyecto:

- **Joomscan**: [https://github.com/OWASP/joomscan](https://github.com/OWASP/joomscan)

Para hacer uso de esta utilidad, simplemente se deberá ejecutar el siguiente comando:

	perl joomscan.pl -u localhost:8080

- Se debe ejecutar con `perl` ya que la utilidad ha sido desarrollada en ese lenguaje.
- El parámetro `-u` sirve para indicar la URL que se va a analizar.

Una vez terminado el análisis, el programa realiza un reporte el cual guarda en la carpeta "/reports/" que se encuentra dentro del repositorio clonado. Si se quiere visualizar dicho reporte a través de la web, de una forma mucho más gráfica, se deberá hacer lo siguiente:

1. Entrar en la carpeta "/reports/" del repositorio.
2. Acceder al reporte correspondiente al análisis que se acaba de realizar: `localhost:8080`.
3. Cambiar el nombre al fichero *html*, para que pase a llamarse *index.html*.
4. Montar un servidor *python* o *php* en el directorio actual: `python -m http.server 80` o `php -S 0.0.0.0:80`.
5. Acceder al servidor desde el navegador.





