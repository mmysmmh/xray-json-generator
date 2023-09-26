import logging
import random

from core.handlers.uri_handler import UriHandler
from core.handlers.xray_handler import XrayHandler
from core.settings import DEFAULT_PORT, URI_FILE


def xray_checker(uri, port):
    xray_handler = XrayHandler(uri, port)
    try:
        xray_handler.run()
        if xray_handler.status:
            return xray_handler
        return -1
    except Exception as e:
        logging.error(e)


def check_status():
    file = open(URI_FILE, 'r')
    text = file.read()
    uri_handler = UriHandler(text)
    uri_handler.get_uri_list()
    connect_list = set()
    for uri in uri_handler.uri_list:
        port = 10808
        check = xray_checker(uri, port)
        if check != -1:
            connect_list.add(check)
    return connect_list


if __name__ == '__main__':
    # while True:
    check_status()
