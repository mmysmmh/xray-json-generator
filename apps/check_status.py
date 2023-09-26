import logging
import random

from core.handlers.uri_handler import UriHandler
from core.handlers.xray_handler import XrayHandler
from core.settings import DEFAULT_PORT, URI_FILE


def xray_checker(uri, port):
    xray_handler = XrayHandler(uri, 10808)
    try:
        xray_handler.run()
        logging.info(xray_handler.status)
        if xray_handler.status:
            return xray_handler.uri
        return None
    except Exception as e:
        logging.error(e)


def main():
    file = open(URI_FILE, 'r')
    text = file.read()
    uri_handler = UriHandler(text)
    uri_handler.get_uri_list()
    connect_list = set()
    for uri in uri_handler.uri_list:
        port = 10808
        logging.info(uri)
        check = xray_checker(uri, port)
        if check is not None:
            connect_list.add(check)
    logging.info(connect_list)


if __name__ == '__main__':
    # while True:
    main()
