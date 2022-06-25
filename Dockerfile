# Base Image
FROM python:3.8-alpine
EXPOSE 5000
# RUN apk add --update bash curl git && rm -rf /var/cache/apk/*

COPY . /usr/src/app
WORKDIR /usr/src/app

RUN apk add postgresql postgresql-dev
RUN apk add build-base
RUN apk add libffi-dev
RUN apk add openssl
RUN pip install -r requirements.txt
CMD gunicorn --workers=4 -b 0.0.0.0:5000 wsgi:app