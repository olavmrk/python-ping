python-ping
===========

This repository contains a simple example of using the `IPPROTO_ICMP` socket type from Python 3.

Note that to be able to use this, you may need to adjust the `net.ipv4.ping_group_range` sysctl option.

For example, to grant yourself access:

```
sudo sysctl -w "net.ipv4.ping_group_range=$(id -g) $(id -g)"
```
