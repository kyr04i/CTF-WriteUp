FROM python:3.11-slim-bullseye

RUN apt-get update && apt-get install -y socat qemu-user

COPY . /app
RUN chmod 0400 /app/flag.txt

WORKDIR /app

CMD /app/socat.sh
