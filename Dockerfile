FROM python:3.6

RUN apt-get update && apt-get install -y \
    postgresql-client

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gnupg \
        software-properties-common \
        wget
RUN wget -qO - https://www.wireshark.org/download/apt/pubkey.gpg | apt-key add -
RUN add-apt-repository "deb https://dl.wireshark.org/apt/release-3.x/ $(lsb_release -cs) main"
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wireshark

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        tshark

WORKDIR /app

COPY . /app

RUN pip install -r requirements.txt

RUN useradd -m ubuntu18
RUN echo 'ubuntu18:rusanow' | chpasswd
RUN chown -R ubuntu18:ubuntu18 /home/ubuntu18
USER ubuntu18

RUN groupadd -r wireshark && \
    usermod -a -G wireshark ubuntu18 && \
    chgrp wireshark /usr/bin/dumpcap && \
    chmod 750 /usr/bin/dumpcap && \
    setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap


ENV FLASK_APP=main.py
ENV FLASK_RUN_HOST=0.0.0.0

CMD ["python3", "main.py"]