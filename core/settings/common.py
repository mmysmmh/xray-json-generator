from pathlib import Path

from decouple import AutoConfig

BASE_DIR = Path(__file__).resolve().parent.parent.parent
XRAY_RUN_PATH = BASE_DIR.joinpath("core", "xray")
BASE_CONFIG_JSON_PATH = BASE_DIR.joinpath("core", "xray_json_generator", "xray_config.json")

config = AutoConfig(search_path=BASE_DIR)

# Access environment variables
# TOKEN = config("TOKEN")
GET_ADDRESS = config(f"GET_ADDRESS", default="https://api.ipify.org?format=json")
BEARER_TOKEN = config("BEARER_TOKEN", default=None)
PROTOCOL_LIST = ("vmess", "vless", "ss", "trogan")
CHECKER_ADD_JOB_LIMIT = config("CHECKER_ADD_JOB_LIMIT", cast=int, default=1000)
