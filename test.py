from config_creator import create_config_object
from server_config import ServerConfig
from v2ray_config_util import V2rayConfigUtil

if __name__ == '__main__':
    # uri = "vless://92838ef6-a329-42c7-aa6f-709c8ee406fc@104.31.16.9:80?path=/&security=none&encryption=none&host=philOsOphY.dlonLInEdoctOr.onlInE&type=ws#@proxy_mtm+@proxy_mtm+@proxy_mtm+@proxy_mtm"
    uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpiZWxlUEt1N2hhOUw0V3Z3N2MzZzdJT28yMEYxeEFQaHZ1cUpTbDZtZ01BQQ==@5.35.100.50:2#@proxy_mtm+@proxy_mtm+@proxy_mtm+@proxy_mtm"
    create_config = create_config_object(uri)
    v2ray_config_util = V2rayConfigUtil()
    result = v2ray_config_util.get_v2ray_config(create_config)
    config = result.content
    print(config)

