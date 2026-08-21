# Packet ရောက်ပြီဆို raw packet object ရမယ် ၊ အဲ့ဒါကို parser က convert လုပ်ပေးပြီး ၊ flet GUI မှာထည့်မယ်
# ဘာလို့ scapy ကနေ GUI ပေါ်ကိုတန်းမတင်လဲဆိုရင် ၊ နောက်ပိုင်း scapy အစား PyShark တို့ dpkt တို့ပြောင်းသုံးရင် UI break သွားမှာစိုးလို့

from dataclasses import dataclass


@dataclass
class PacketInfo:
    number: int

    time: str

    source: str

    destination: str

    protocol: str

    length: int

    mac_source: str = ""

    mac_destination: str = ""

    src_port: str = ""

    dst_port: str = ""

    info: str = ""
