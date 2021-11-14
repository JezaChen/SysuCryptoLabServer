# Base Image
FROM python:3.8-alpine
EXPOSE 5000
# RUN apk add --update bash curl git && rm -rf /var/cache/apk/*

COPY . /usr/src/app
COPY /home/lighthouse/ssl/* /usr/src/app
WORKDIR /usr/src/app

RUN pip install -r requirements.txt
CMD gunicorn --certfile=server.crt --keyfile=server.key --workers=4 -b 0.0.0.0:5000 wsgi:app