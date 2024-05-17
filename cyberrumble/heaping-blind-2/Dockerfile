FROM ubuntu:18.04

RUN apt-get update && apt-get install -y socat gcc

COPY ./heaping-blind-2.c ./flag.txt /

RUN gcc -o /heaping-blind-2 /heaping-blind-2.c

RUN useradd heaping

ENTRYPOINT ["socat", "-v", "TCP-LISTEN:13372,reuseaddr,fork", "EXEC:/heaping-blind-2"]
