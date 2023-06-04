FROM python:3.6

RUN apt-get update && apt-get install -y \
    postgresql-client

WORKDIR /app

COPY . /app

RUN pip3 install --update pip
RUN pip install -r requirements.txt

RUN usermod -aG wireshark kali
RUN chown kali /usr/bin/dumpcap
RUN chgrp kali /usr/bin/dumpcap 
RUN apt install wireshark
RUN apt install tshark
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.6

ENV FLASK_APP=main.py
ENV FLASK_RUN_HOST=0.0.0.0

CMD ["python3", "main.py"]