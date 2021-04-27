import random


def hashing(ip):
    return ip * 2654435761 % (2 ** 32)


def main():
    for _ in range(15):
        a = random.randrange(1, 255)
        b = random.randrange(1, 255)
        source = '192.168.{}.{}'.format(a, b)
        u = (192 << 24) + (168 << 16) + (a << 8) + b

        print("{:15s}: {:32b}".format(source, hashing(u)))


if __name__ == "__main__":
    main()
