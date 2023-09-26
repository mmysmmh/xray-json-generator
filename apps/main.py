import json
import logging
from typing import List

from apps.check_status import check_status
from core.handlers.xray_handler import XrayHandler
from core.settings import RESULT_JSON_CONFIG_PATH


def main():
    uri_list: List[XrayHandler] = check_status()
    i = 0
    for xray in uri_list:
        i = i + 1
        try:
            file = open(f'{RESULT_JSON_CONFIG_PATH}/config_{i}.json', 'w')
            json.dump(xray.config, file)
        except Exception as e:
            logging.error(e)


if __name__ == '__main__':
    main()
