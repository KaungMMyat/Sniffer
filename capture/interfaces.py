# get_interfaces() return only NPF names [hard to understand]
from scapy.arch.windows import get_windows_if_list


def is_valid_interface(interface):

    name = interface["name"].lower()
    description = interface["description"].lower()

    blocked_keywords = [
        "npcap",
        "wan miniport",
        "loopback",
        "virtual",
        "filter",
        "qos",
    ]

    for keyword in blocked_keywords:
        if keyword in name or keyword in description:
            return False

    return True


def get_interfaces():
    interfaces = []

    try:
        for iface in get_windows_if_list():
            name = iface["name"]

            # Skip virtual/filter interfaces
            if any(
                keyword in name
                for keyword in (
                    "Npcap",
                    "QoS",
                    "WFP",
                    "Loopback",
                    "Teredo",
                    "6to4",
                    "Kernel",
                    "Miniport",
                )
            ):
                continue

            interfaces.append(
                {
                    "name": name,
                    "description": iface["description"],
                }
            )

        return [interface for interface in interfaces if is_valid_interface(interface)]

    except Exception as e:
        print(e)
        return []
