FROM ubuntu:22.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g"  /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && \
    apt-get install -y lib32z1 xinetd && \
    apt-get install -y python3 python3-pip

COPY ./main /main

RUN  pip3 install -r /main/requirements.txt

COPY init_tiktoken.py /app/init_tiktoken.py

RUN  python3 /app/init_tiktoken.py

CMD  python3 /main/main.py