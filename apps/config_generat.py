import json

from core.handlers.xray_handler import XrayHandler
from core.settings import RESULT_JSON_CONFIG_PATH


def main():
    uri = input()
    xray_handler = XrayHandler(uri, 10808)
    config = xray_handler.get_config_json()
    json.dump(config, open(RESULT_JSON_CONFIG_PATH, 'w'))


if __name__ == '__main__':
    main()
