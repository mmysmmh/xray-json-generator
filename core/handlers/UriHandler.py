import re

from core import settings


class UriHandler:
    def __init__(self, txt):
        self.text = txt
        self.uri_list = []

    def get_uri_list(self):
        uri_list = []
        for protocol in settings.PROTOCOL_LIST:
            match_list = re.findall(f"\s+{protocol}://\S*", self.text) + re.findall(f"^{protocol}://\S*", self.text)
            for match in match_list:
                uri_list.append(match.strip())
        self.uri_list = uri_list
        return uri_list
