#!/bin/bash

case "$1" in
     "create")
         ip link add name vpp1out type veth peer name vpp1host
         ip link set dev vpp1out up
         ip link set dev vpp1host up
         ip addr add 10.10.1.1/24 dev vpp1host;;
     "remove")
         ip link set dev vpp1out down
         ip link set dev vpp1host down
         ip link del vpp1out;;
     "ping")
         ping -c 3 10.10.1.2;;
     *)
         echo "Usage $0 create|remove|ping"
         exit 1;;
esac
