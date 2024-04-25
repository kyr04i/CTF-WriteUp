FROM ubuntu:18.04@sha256:dca176c9663a7ba4c1f0e710986f5a25e672842963d95b960191e2d9f7185ebe

EXPOSE 32912

RUN apt-get update
RUN apt-get upgrade -y

ENV TERM=linux
RUN useradd -m santa_protocol
WORKDIR /home/santa_protocol

ADD ./santa_protocold /home/santa_protocol/
ADD ./flag /

RUN chmod 777 /home/santa_protocol
RUN chown santa_protocol:root /home/santa_protocol/*
RUN chown santa_protocol:root /home/santa_protocol

RUN chmod +x /home/santa_protocol/santa_protocold

RUN chmod +x /home/santa_protocol/santa_protocold
RUN cd /home/santa_protocol/


RUN echo "santa_protocol 32912/tcp" >> /etc/services

USER santa_protocol

CMD ["bash", "-c", "/home/santa_protocol/santa_protocold && while true; do sleep 1000; done"]
