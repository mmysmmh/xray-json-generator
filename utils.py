import base64
import logging
import re
from urllib.parse import unquote
from typing import List
from typing import Union


class Utils:
    @staticmethod
    def decode(text: str) -> str:
        decoded = Utils.try_decode_base64(text)
        if decoded:
            return decoded
        if text.endswith('='):
            trimmed_text = text.rstrip('=')
            decoded_trimmed = Utils.try_decode_base64(trimmed_text)
            if decoded_trimmed:
                return decoded_trimmed
        return ""

    @staticmethod
    def try_decode_base64(text: str) -> Union[str, None]:
        try:
            return base64.b64decode(text).decode("utf-8")
        except Exception as e:
            print(f"Parse base64 standard failed: {e}")
        try:
            return base64.urlsafe_b64decode(text).decode("utf-8")
        except Exception as e:
            print(f"Parse base64 url safe failed: {e}")
        return None

    @staticmethod
    def get_remote_dns_servers() -> List[str]:
        ret = ['1.1.1.1']
        return ret

    # @staticmethod
    # def get_vpn_dns_servers() -> List[str]:
    #     vpn_dns = (settingsStorage.decodeString(AppConfig.PREF_VPN_DNS) or settingsStorage.decodeString(
    #         AppConfig.PREF_REMOTE_DNS) or AppConfig.DNS_AGENT)
    #     return [server for server in vpn_dns.split(",") if Utils.is_pure_ip_address(server)]
    #
    # @staticmethod
    # def get_domestic_dns_servers() -> List[str]:
    #     domestic_dns = settingsStorage.decodeString(AppConfig.PREF_DOMESTIC_DNS) or AppConfig.DNS_DIRECT
    #     ret = [server for server in domestic_dns.split(",") if
    #            Utils.is_pure_ip_address(server) or Utils.is_core_dns_address(server)]
    #     if not ret:
    #         return [AppConfig.DNS_DIRECT]
    #     return ret
    #
    # @staticmethod
    # def is_ip_address(value: str) -> bool:
    #     try:
    #         addr = value
    #         if not addr or addr.isspace():
    #             return False
    #         if '/' in addr:
    #             arr = addr.split("/")
    #             if len(arr) == 2 and int(arr[1]) > 0:
    #                 addr = arr[0]
    #         if addr.startswith("::ffff:") and '.' in addr:
    #             addr = addr[7:]
    #         elif addr.startswith("[::ffff:") and '.' in addr:
    #             addr = addr[8:].replace("]", "")
    #         octets = addr.split('.')
    #         if len(octets) == 4:
    #             if ':' in octets[3]:
    #                 addr = addr[:addr.index(":")]
    #             return Utils.is_ipv4_address(addr)
    #         return Utils.is_ipv6_address(addr)
    #     except Exception as e:
    #         print(e)
    #         return False

    @staticmethod
    def is_pure_ip_address(value: str) -> bool:
        return Utils.is_ipv4_address(value) or Utils.is_ipv6_address(value)

    @staticmethod
    def is_ipv4_address(value: str) -> bool:
        reg_v4 = re.compile(r"^([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\."
                            r"([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\."
                            r"([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\."
                            r"([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])$")
        return bool(reg_v4.match(value))

    @staticmethod
    def is_ipv6_address(value: str) -> bool:
        addr = value
        if addr.startswith("[") and addr.rfind("]") > 0:
            addr = addr[1:addr.rfind("]")]
        reg_v6 = re.compile(r"^([0-9A-Fa-f]{1,4})?"
                            r"(:[0-9A-Fa-f]{1,4})*::"
                            r"([0-9A-Fa-f]{1,4})?"
                            r"(:[0-9A-Fa-f]{1,4})*"
                            r"|([0-9A-Fa-f]{1,4})"
                            r"(:[0-9A-Fa-f]{1,4}){7}$")
        return bool(reg_v6.match(addr))

    # @staticmethod
    # def is_core_dns_address(s: str) -> bool:
    #     return s.startswith("https") or s.startswith("tcp") or s.startswith("quic")
    #
    #
    # @staticmethod
    # def is_valid_url(value: str) -> bool:
    #     try:
    #         if (re.match(Patterns.WEB_URL.pattern, value) or URLUtil.isValidUrl(value)):
    #             return True
    #     except Exception as e:
    #         print(e)
    #         return False
    #     return False

    @staticmethod
    def url_decode(url) -> str:
        try:
            return unquote(url)
        except Exception as e:
            # logging.exception(e)
            return url

    @staticmethod
    def read_text_from_assets(file_name) -> str:
        with open(file_name) as file:
            return file.read()

    # @staticmethod
    # def get_ipv6_address(address) -> str:
    #     if Utils.is_ipv6_address(address):
    #         return f"[{address}]"
    #     return address

    @staticmethod
    def fix_illegal_url(str_) -> str:
        return str_.replace(" ", "%20").replace("|", "%7C")

    # @staticmethod
    # def remove_white_space(str_) -> Union[str, None]:
    #     return str_.replace(" ", "") if str_ else None
    #
    # @staticmethod
    # def idn_to_ascii(str_) -> str:
    #     url = urlparse(str_)
    #     return urlunparse(
    #        (url.scheme, IDN.toASCII(url.netloc, IDN.ALLOW_UNASSIGNED), url.path, url.params, url.query, url.fragment))
    #
    # @staticmethod
    # def is_tv(context) -> bool:
    #     return context.packageManager.hasSystemFeature(PackageManager.FEATURE_LEANBACK)
