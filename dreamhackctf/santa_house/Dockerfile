FROM ubuntu:20.04@sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715

ENV user santa_library
ENV chall_port 5555

RUN apt-get update
RUN apt-get -y install socat

RUN adduser --disabled-password $user

ADD ./flag /home/$user/flag
ADD ./chall /home/$user/chall

COPY ./libc-2.31.so /libc-2.31.so
RUN export LD_PRELOAD='/libc-2.31.so' 

RUN chown -R root:root /home/$user
RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/chall

RUN chmod 755 /home/$user/chall
RUN chmod 440 /home/$user/flag

WORKDIR /home/$user
USER $user
EXPOSE $chall_port
CMD while :; do socat -T 300 TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/chall ; done
