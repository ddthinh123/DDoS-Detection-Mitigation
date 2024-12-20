#!/bin/csh

# Iperf to server using udp
iperf -c 10.0.0.1 -u -b 10M -l 512 -t 10 -i 1


