# Base Image
FROM python:3.8-alpine
EXPOSE 5000
# RUN apk add --update bash curl git && rm -rf /var/cache/apk/*

COPY . /usr/src/app
WORKDIR /usr/src/app

RUN pip install -r requirements.txt
CMD ["python", "app.py"]