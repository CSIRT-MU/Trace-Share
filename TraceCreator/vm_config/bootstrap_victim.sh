#!/usr/bin/env bash

echo "bootstrap working"

#apt-get update
#apt-get install -y apache2
#if ! [ -L /var/www ]; then
#  rm -rf /var/www
#  ln -fs /vagrant /var/www
#fi

#DEBIAN_FRONTEND=noninteractive apt-get -y install tshark
#apt-get install nmap
#apt-get install -y hydra hydra-gtk


#### install medusa with working ssh module 
# use custom install for medusa (missing ssh module)
#sudo apt-get install linux-headers-$(uname -r) build-essential make patch openssl libpq-dev libgnutls-dev zlib1g-dev libssh2-1-dev gettext autoconf libpcap0.8-dev python-scapy python-dev
#cd /opt/
#sudo wget http://www.foofus.net/jmk/tools/medusa-2.1.1.tar.gz
#sudo tar xvzf medusa-2.1.1.tar.gz
#cd medusa-2.1.1
#./configure
#make
#sudo make install

#### scenario medusa
### consumer
# sudo adduser vagrant 
## password vagrant
# sudo tshark -i enp0s8 -s 0 -w capture.pcap

### producer
# medusa -u vagrant -P passwords.txt -h 192.168.0.3 -M ssh
