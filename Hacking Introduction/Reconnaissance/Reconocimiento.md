## Descubrimiento de Correos de un Dominio

- https://hunter.io/
- https://intelx.io/	
- https://phonebook.cz/

## Reconocimiento de Imágenes

- https://pimeyes.com/en

## Enumeración de Subdominios

**Enumera subdominios de forma pasiva (no aplica fuerza bruta ni hace peticiones)**

	pip3 ctfr.py -d google.com

**Enumeración activa de subdominios aplicando fuerza bruta**

	gobuster vhost -u https://youtube.com -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 20

- `vhost` indica que se van a enumerar subdominios.
- Con `-u` se indica la url a enumerar.
- Con `-w` se indica el diccionario con el que aplicar fuerza bruta
- Con `-t 20` se le indica que se ejecute en 20 hilos paralelos

**Enumeración activa de subdominios con wfuzz**

	wfuzz -c -t 20 -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.google.com" https://google.com

- Con `--hc=403` se oculta el código de estado y se muestran todos los demás (Hide Code).
- Con `--sc=200` se muestran únicamente subdominios con este código de estado (Show Code).

## Brechas de Seguridad y Credenciales

**Webs para encontrar credenciales**

- https://www.dehashed.com/
- https://breachforums.is/

## Identificación de Tecnologías Web

**Herramienta para identificar las tecnologías presentes detrás de una web**

	whatweb https://www.ulpgc.es

## FUZZING

### GOBUSTER

	gobuster dir -u https://www.ulpgc.es/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 --add-slash -b 403,404

- El parámetro `--add-slash` añade una barra al final de las url.
- Con el parámetro` -b` se introducen los códigos de estado indicados en una blacklist para que no se tengan en cuenta.

**Buscar por extensiones de archivo**

	gobuster dir -u https://www.ulpgc.es/ -w "diccionario" -t 200 -b 403,404 -x php,html,txt

### WFUZZ

	wfuzz -c -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt https://miwifi.com/FUZZ

	wfuzz -c --sl=216 --hc=403,404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt https://miwifi.com/FUZZ/

**Buscar por extensión**

	wfuzz -c --hc=403,404 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt https://miwifi.com/FUZZ.html

**Contemplar segundo payload**

	wfuzz -c --hc=403,404 -t 200 -w "Diccionario" -z list,html-txt-php https://miwifi.com/FUZZ.FUZ2Z

**Especificación de rango para probar todos los ID posibles**

	wfuzz -c --hw=5786,5797 -t 200 -z range,10000-20000 'https://www.mi.com/shop/buy/detail?product_id=FUZZ'
	
## Google Dorks

	site:amazon.com

	filetype:txt

	intext:amazon.com

	inurl:wp-config.php.txt

**Página web con exploits y Google Hacking**

- https://www.exploit-db.com/

## Metadatos

	exiftool "fichero"