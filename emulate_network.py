from scapy.all import *
import random


DESTINATION_IP = "192.168.99.120"


def main():
    for i in range(100):
        source = '192.168.99.{}'.format(random.randrange(1,255))
        source_port = 1500
        destination_port = 20000
        payload = "yada yada yada"  # packet payload
        spoofed_packet = IP(src=source, dst=DESTINATION_IP) / TCP(sport=source_port, dport=destination_port) / payload
        send(spoofed_packet)


if __name__ == "__main__":
    main()
