# Martian Packets

A repo containing a python script which can be used to craft raw TCP/IP packets.

Used for testing out martian packets following a vulnerability announced in kubernetes (kube-proxy).

Currently does not work for the vulnerability I was trying to test for (I can't see the packets coming in on the target), but useful to see how TCP/IP packets are constructed nonetheless.

For a more robust PoC for the particular vulnerability, see [here](https://github.com/kubernetes/kubernetes/issues/90259).

Credits:
https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/
https://gist.github.com/NickKaramoff/b06520e3cb458ac7264cab1c51fa33d6
