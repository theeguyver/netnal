import sys
from scapy.all import *

def print_help():
    print(r"""
          
               __             _____  .____     
  ____   _____/  |_  ____    /  _  \ |    |    
 /    \_/ __ \   __\/    \  /  /_\  \|    |    
|   |  \  ___/|  | |   |  \/    |    \    |___ 
|___|  /\___  >__| |___|  /\____|__  /_______ \
     \/     \/          \/         \/        \/

          """)
    print("Usage: python -m netnal -sS/-sU/-sA/-sN/-sX/-p/-t address [port1-port2-port3]/[start:end] ")
    print("\n\nFlags:")
    print("  -sS    :  SYN  :   Perform SYN scan")
    print("  -sU    :  UDP  :   Perform UDP scan")
    print("  -sA    :  ACK  :   Perform ACK scan")
    print("  -sN    :  NULL :   Perform NULL scan")
    print("  -sX    :  XMAS :   Perform XMAS scan")
    print("  -p :   :  ping :   Perform ping check")
    print("  -t :   : trace :   Perform traceroute")
    
    print("\nPort Number Specifications:\n")
    print("  You can specify ports individually or as a range.")
    print("  --default          :   will scan port 1 - 1023 of specified address.")
    print("  port1              :   will scan port1 of specified address.")
    print("  port1-port2-port3  :   will scan port1, port2, port3 of specified address.")
    print("  port1:port_n       :   will scan port1 to port_n of specified address\n\n")
    sys.exit()

if "--help" in sys.argv or "-h" in sys.argv or len(sys.argv) == 1:
    print_help()    
elif len(sys.argv) < 4:
    if sys.argv[1] in ["-sS", "-sU", "-sA", "-sN", "-sX"]:
        print_help()
        sys.exit()

scan_type = sys.argv[1]
address = sys.argv[2]

# Check if ports are provided, if not, scan default ports 1-1023
try: 
    if '-' in sys.argv[3]:
        ports = sys.argv[3].split("-")
        ports = [int(port) for port in ports]
    elif ':' in sys.argv[3]:
        start, end = sys.argv[3].split(":")
        ports = list(range(int(start), int(end)+1))
    elif sys.argv[3] == "--default":
        ports = list(range(1, 1024))
    else:
        ports = os.sys.argv[3].split("-")
        ports = [int(port) for port in ports]
except IndexError:
    pass 


def udp_scan():
    print("EXECUTING UDP SCAN ON " + address + " ports " + str(ports))
    ans, unans = sr(IP(dst=address)/UDP(dport=ports), timeout=2, verbose=False)
    ans.summary(lambda s, r: r.sprintf("%IP.sport%: open"))
    unans.summary(lambda s: s.sprintf("%IP.dport%: open|filtered"))

def syn_scan():
    print("EXECUTING SYN SCAN ON " + address + " ports " + str(ports))
    ans, unans = sr(IP(dst=address)/TCP(dport=ports, flags="S"), timeout=2, verbose=False)
    for s, r in ans:
        if s[TCP].dport == r[TCP].sport:
            print(str(s[TCP].dport) + ": open")
    for s in unans:
        print(str(s[TCP].dport) + ": closed")

def ack_scan():
    print("EXECUTING ACK SCAN ON " + address + " ports " + str(ports))
    ans, unans = sr(IP(dst=address)/TCP(dport=ports, flags="A"), timeout=1, verbose=False)
    for s, r in ans:
        if s[TCP].dport == r[TCP].sport:
            print(str(s[TCP].dport) + ": open")
    for s in unans:
        print(str(s[TCP].dport) + ": open|filtered")

def null_scan():
    print("EXECUTING NULL SCAN ON " + address + " ports " + str(ports))
    ans, unans = sr(IP(dst=address)/TCP(dport=ports, flags=""), timeout=1, verbose=False)
    for s, r in ans:
        if s[TCP].dport == r[TCP].sport:
            print(str(s[TCP].dport) + ": open")
    for s in unans:
        print(str(s[TCP].dport) + ": open|filtered")

def xmas_scan():
    print("EXECUTING XMAS SCAN ON " + address + " ports " + str(ports))
    ans, unans = sr(IP(dst=address)/TCP(dport=ports, flags="FPU"), timeout=1, verbose=False)
    for s, r in ans:
        if s[TCP].dport == r[TCP].sport:
            print(str(s[TCP].dport) + ": open")
    for s in unans:
        print(str(s[TCP].dport) + ": open|filtered")
        
def ping_check():
    print("PING CHECKING " + address)
    sent_packets = 0
    received_packets = 0
    lost_packets = 0
    round_trip_times = []

    for _ in range(4):
        sent_packets += 1
        response = sr1(IP(dst=address)/ICMP(), timeout=2, verbose=False)
        if response:
            received_packets += 1
            bytes = len(response)
            time_ms = response.time * 1000
            ttl = response.ttl
            print(f"Reply from {address}: bytes={bytes} time={time_ms:.2f}ms TTL={ttl}")
            round_trip_times.append(response.time)
        else:
            lost_packets += 1

    print("\nPing statistics:")
    print(f"Packets: Sent = {sent_packets}, Received = {received_packets}, Lost = {lost_packets} "
          f"({(lost_packets / sent_packets) * 100:.2f}% loss)")
    if received_packets > 0:
        print("Approximate round trip times in milli-seconds:")
        print(f"    Minimum = {min(round_trip_times) * 1000:.2f}ms, Maximum = {max(round_trip_times) * 1000:.2f}ms, "
              f"Average = {(sum(round_trip_times) / len(round_trip_times)) * 1000:.2f}ms")

def traceroute():
    print("EXECUTING TRACEROUTE TO " + address)
    hostname = address
    for i in range(1, 28):
        pkt = IP(dst=hostname, ttl=i) / UDP(dport=33434)
        try:
            # Send the packet and get a reply
            reply = sr1(pkt, timeout=2, verbose=0)
            if reply is None:
                # No reply = Timeout
                print(f"{i}. Hop: * - Unknown")
            elif reply.type == 3:
                # We've reached our destination
                print("Traceroute complete.", reply.src)
                break
            else:
                # We're in the middle somewhere
                print(f"{i}. Hop: {reply.src} - Round Trip Time: {reply.time * 1000:.2f}ms")
        except Exception as e:
            print(f"{i}. Hop: * - Unknown (Timeout)")
    

if scan_type == "-sS":
    syn_scan()
elif scan_type == "-sU":
    udp_scan()
elif scan_type == "-sA":
    ack_scan()
elif scan_type == "-sN":
    null_scan()
elif scan_type == "-sX":
    xmas_scan()
elif scan_type == "-p":
    ping_check()
elif scan_type == "-t":
    traceroute()
else:
    print("Invalid scan type. Please use -sS/-sU/-sA/-sN/-sX.")
