from scapy.all import *
import time
import random
import argparse


DEFAULT_NUMBER_OF_PACKETS = 10
DEFAULT_BREAK_IN_SECONDS = 2


def send_packets(destination, number, sleep_seconds):
    for i in range(number):
        source = '192.168.{}.{}'.format(random.randrange(1, 255), random.randrange(1, 255))
        sendp(Ether()/IP(src=source, dst=destination, ttl=(1, 1)), iface="vboxnet0")
        print(source)
        time.sleep(sleep_seconds)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('dst', help='destination ip address')
    parser.add_argument('-n', action='store', type=int, help='number of packets to be sent')
    parser.add_argument('-s', action='store', type=int, help='break in seconds between sending packets')

    args = parser.parse_args()

    if args.n is None:
        args.n = DEFAULT_NUMBER_OF_PACKETS

    if args.s is None:
        args.s = DEFAULT_BREAK_IN_SECONDS

    send_packets(args.dst, args.n, args.s)


if __name__ == "__main__":
    main()
