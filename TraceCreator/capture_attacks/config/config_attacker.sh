#!/usr/bin/env bash

echo "attacker config working"
cd /vagrant/capture_attacks/config/
touch bla
ping 203.0.113.101 -c 3
