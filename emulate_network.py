from scapy.all import *
import time
import random
import argparse
from tqdm import tqdm


DEFAULT_NUMBER_OF_PACKETS = 10
DEFAULT_NUMBER_OF_UNIQUE_IP_ADDRESSES = 1000
DEFAULT_BREAK_IN_SECONDS = 2


def send_packets(destination, sleep_seconds):
    while (True):
        source_ip = '{}.{}.{}.{}'.format(random.randrange(1, 255), random.randrange(1, 255), random.randrange(1, 255), random.randrange(1, 255))
        destination_port = random.randrange(1, 1000)
        protocol_id = random.randrange(0, 4)
        if protocol_id == 0:
            sendp(Ether()/IP(src=source_ip, dst=destination, ttl=(1, 1))/TCP(dport=destination_port,flags='S'), iface="vboxnet0")
        elif protocol_id == 1:
            sendp(Ether()/IP(src=source_ip, dst=destination, ttl=(1, 1))/UDP(dport=destination_port), iface="vboxnet0")
        elif protocol_id == 2:
            sendp(Ether()/IP(src=source_ip, dst=destination, ttl=(1, 1))/ICMP(), iface="vboxnet0")
        else:
            sendp(Ether()/IP(src=source_ip, dst=destination, ttl=(1, 1)), iface="vboxnet0")

        protocol = lambda x: "TCP" if x == 0 else "UDP" if x == 1 else "ICMP" if x == 2 else "Other"
        print("Source IP: {}\tProtocol: {}\tDestination port: {}".format(source_ip, protocol(protocol_id), destination_port))
        time.sleep(sleep_seconds)


def send_packets_unique_ip_addresses(destination, number_of_unique, sleep_seconds):
    ip_addresses = []
    for _ in range(number_of_unique):
        ip_addresses.append('{}.{}.{}.{}'.format(random.randrange(1, 255), random.randrange(1, 255), random.randrange(1, 255), random.randrange(1, 255)))

    while (True):
        source = random.choice(ip_addresses)
        sendp(Ether()/IP(src=source, dst=destination, ttl=(1, 1)), iface="vboxnet0")
        print(source)
        time.sleep(sleep_seconds)


def int_to_ip_string(n):
    return '{}.{}.{}.{}'.format((n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF)


def test_count_distinct(destination, sleep_seconds):
    print("Generating ip addresses.")
    ip_addresses_int = [i for i in tqdm(range(1, 4294967296, 37))]
    random.shuffle(ip_addresses_int)

    with open('ips.txt', 'w') as f:
        for source in ip_addresses_int:
            f.write("{}\n".format(str(source)))

    # print("Starting the flow.")
    # for source in ip_addresses_int:
    #     sendp(Ether()/IP(src=int_to_ip_string(source), dst=destination, ttl=(1, 1)), iface="vboxnet0", verbose=False)
    #     print(source)
    #     time.sleep(sleep_seconds)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('dst', help='destination ip address')
    parser.add_argument('-s', action='store', type=float, help='break in seconds between sending packets')
    parser.add_argument('-u', action='store_true', help='send packets with n unique ip addresses')
    parser.add_argument('-n', action='store', type=int, help='number of unique addresses to be used (-u option should be enabled)')
    parser.add_argument('-t', action='store_true', help='testing mode, send packets with all possible ip addresses (ipv4)')

    args = parser.parse_args()

    if args.n is None:
        if args.u:
            args.n = DEFAULT_NUMBER_OF_UNIQUE_IP_ADDRESSES

    if args.s is None:
        args.s = DEFAULT_BREAK_IN_SECONDS

    if args.u:
        send_packets_unique_ip_addresses(args.dst, args.n, args.s)
    elif args.t:
        test_count_distinct(args.dst, args.s)
    else:
        send_packets(args.dst, args.s)


if __name__ == "__main__":
    main()
