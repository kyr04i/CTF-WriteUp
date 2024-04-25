FROM ubuntu:22.04

RUN apt-get -y update --fix-missing
RUN apt-get -y upgrade
RUN apt-get -y install socat python3 python3-pip
RUN pip install frida-tools
RUN groupadd -r ctf && useradd -r -g ctf ctf

WORKDIR /home/ctf
COPY ./flag.txt .
RUN mv flag.txt flag-$(md5sum flag.txt | awk '{print $1}').txt
COPY ./inst.js .
COPY ./prog .
COPY ./launch.py .
RUN chmod -R og-w .
RUN chown -R root:ctf /home/ctf

USER ctf
CMD socat TCP-L:8109,reuseaddr,fork EXEC:"python3 -u ./launch.py"
EXPOSE 8109
