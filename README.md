# monitorBX

Monitoring network traffic by interface using **eBPF**.

The eBPF part is compatible with kernel version 5.10.3.


###Setup environment
- Make sure your kernel version supports eBPF
- Install **libbpf** 

###Monitoring
```
sudo make
sudo ./monitorBX .. 
```

###Start network flow

```
python emulate_network.py [-h] [-s S] [-u] [-n N] [-t] dst
```

**Arguments**
```
dst         destination ip address
-h, --help  show this help message and exit
-s S        break in seconds between sending packets
-u          send packets with n unique ip addresses
-n N        number of unique addresses to be used (-u option should be enabled)
-t          testing mode, send packets with all possible ip addresses (ipv4)
```