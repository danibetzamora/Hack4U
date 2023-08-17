FROM ubuntu:latest

MAINTAINER Daniel Betancor aka dalnitak

ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt install -y net-tools \
  iputils-ping \
  nano \
  git \
  curl \
  apache2 \
  php

EXPOSE 80

COPY prueba.txt /var/www/html/

ENTRYPOINT service apache2 start && /bin/bash