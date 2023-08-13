from enum import Enum


class EConfigType(Enum):
    VMESS = (1, "vmess://")
    CUSTOM = (2, "")
    SHADOWSOCKS = (3, "ss://")
    SOCKS = (4, "socks://")
    VLESS = (5, "vless://")
    TROJAN = (6, "trojan://")
    WIREGUARD = (7, "wireguard://")
