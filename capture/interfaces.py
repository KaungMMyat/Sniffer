from scapy.all import get_if_list

def get_interfaces():
    
    try:
        return get_if_list()
    
    except Exception as e:
        print(f"Error retrieving network interfaces: {e}")
        return []