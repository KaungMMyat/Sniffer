from scapy.all import get_if_list 

interfaces = get_if_list()

for interface in interfaces:
    print(interface)