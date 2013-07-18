#!/bin/sh
if [ `uname` = "FreeBSD" ]
then
    sudo sysctl -w net.inet.ip.forwarding=1
    sudo sysctl -w net.inet.ip.fastforwarding=1
else
    sudo sysctl -w net.ipv4.conf.all.forwarding=1
fi
exit 0
