from enum import Enum


class EConfigType(Enum):
    VMESS = ("VMESS", "vmess://")
    CUSTOM = ("CUSTOM", "")
    SHADOWSOCKS = ("SHADOWSOCKS", "ss://")
    SOCKS = ("SOCKS", "socks://")
    VLESS = ("VLESS", "vless://")
    TROJAN = ("TROJAN", "trojan://")
    WIREGUARD = ("WIREGUARD", "wireguard://")
