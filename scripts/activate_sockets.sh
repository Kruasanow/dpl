sudo apt install tshark
sudo apt install postgesql
sudo usermod -aG wireshark ubuntu18
sudo chown ubuntu18 /usr/bin/dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.6
