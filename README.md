# monitorBX

Monitoring network traffic by interface using **eBPF**.

The eBPF part is compatible with kernel version 5.10.3.


### Setup environment
- Make sure your kernel version supports eBPF
- Install **libbpf** 

### Monitoring
```
sudo make
sudo ./monitorBX -i I [-f F] [-c] 
```

**Arguments**
```
-h     Help
-i     Index of network interface
-f     Filename for saved data
-c     Count distinct mode
```

**Output example**
```
Speed:                       6.40
Packets passed:              4
Packets dropped:             0
Packets with TCP protocol:   2
Packets with UDP protocol:   2
Packets with Other protocol: 0
```

### Start network flow

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