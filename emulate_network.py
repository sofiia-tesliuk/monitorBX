from scapy.all import *
import time
import random
import argparse


DEFAULT_NUMBER_OF_PACKETS = 10
DEFAULT_NUMBER_OF_UNIQUE_IP_ADDRESSES = 1000
DEFAULT_BREAK_IN_SECONDS = 2


def send_packets(destination, number, sleep_seconds):
    for _ in range(number):
        source = '192.168.{}.{}'.format(random.randrange(1, 255), random.randrange(1, 255))
        sendp(Ether()/IP(src=source, dst=destination, ttl=(1, 1)), iface="vboxnet0")
        print(source)
        time.sleep(sleep_seconds)


def send_packets_unique_ip_addresses(destination, number_of_unique, sleep_seconds):
    ip_addresses = []
    for _ in range(number_of_unique):
        ip_addresses.append('192.168.{}.{}'.format(random.randrange(1, 255), random.randrange(1, 255)))

    while (True):
        source = random.choice(ip_addresses)
        sendp(Ether()/IP(src=source, dst=destination, ttl=(1, 1)), iface="vboxnet0")
        print(source)
        time.sleep(sleep_seconds)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('dst', help='destination ip address')
    parser.add_argument('-n', action='store', type=int, help='number of packets to be sent / unique addresses to be used')
    parser.add_argument('-s', action='store', type=float, help='break in seconds between sending packets')
    parser.add_argument('-u', action='store_true', help='send packets with n unique ip addresses')

    args = parser.parse_args()

    if args.n is None:
        if args.u:
            args.n = DEFAULT_NUMBER_OF_UNIQUE_IP_ADDRESSES
        else:
            args.n = DEFAULT_NUMBER_OF_PACKETS

    if args.s is None:
        args.s = DEFAULT_BREAK_IN_SECONDS

    if args.u:
        send_packets_unique_ip_addresses(args.dst, args.n, args.s)
    else:
        send_packets(args.dst, args.n, args.s)


if __name__ == "__main__":
    main()
