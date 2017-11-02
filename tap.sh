#!/bin/sh

sudo ip addr add 10.0.0.2/24 dev foobar
ping -c 3 10.0.0.1
