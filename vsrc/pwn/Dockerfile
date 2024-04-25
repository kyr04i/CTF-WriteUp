FROM ubuntu:17.10

ADD sources.list /etc/apt/sources.list
RUN apt-get update -y
RUN apt-get install -y xinetd gcc-multilib
    
RUN rm -fr /etc/xinetd.d/*

RUN useradd -U -m ctf && mkdir -p /home/ctf
ADD calc /home/ctf/
ADD flag.txt /home/ctf/flag.txt
ADD ctf.xinetd /etc/xinetd.d/ctf

RUN chmod 755 /home/ctf/calc \
    && chmod 444 /home/ctf/flag.txt

RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*


ENV CTF_PORT 20000
EXPOSE 20000

ENTRYPOINT ["/usr/sbin/xinetd", "-dontfork", "-stayalive", "-inetd_compat"]