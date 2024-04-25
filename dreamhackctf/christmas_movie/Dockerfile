FROM ubuntu:22.04@sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac

RUN apt update
RUN apt-get install -y xinetd ssh
RUN apt-get install -y openssh-server
RUN apt-get install vim gdb python3 python3-pip -y

RUN python3 -m pip install --upgrade pip
RUN pip3 install unicorn
RUN pip3 install keystone-engine
RUN pip3 install pwntools

RUN adduser hacker --disabled-password --gecos '' newuser
RUN adduser wyv3rn
RUN echo "Port 31337" >> /etc/ssh/sshd_config

COPY ./deploy/flag /home/hacker/flag
COPY ./deploy/prob /home/hacker/prob

RUN chown root:wyv3rn /home/hacker/flag
RUN chown root:wyv3rn /home/hacker/prob
RUN chmod 2640 /home/hacker/flag
RUN chmod 2755 /home/hacker/prob

RUN ssh-keygen -A
RUN mkdir -p /run/sshd

EXPOSE 31337
CMD ["/usr/sbin/sshd","-D"]
