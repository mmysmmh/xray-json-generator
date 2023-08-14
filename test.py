from config_creator import create_config_object
from server_config import ServerConfig
from v2ray_config_util import V2rayConfigUtil

if __name__ == '__main__':
    # uri = "vless://ddb133fc-d277-4c27-d518-0966796c35dc@104.31.16.197:80?path=nameless-wave-c0e0-work-new.helloworldperianscript.workers.dev&security=none&encryption=none&host=PHONe.Kashti.WORLd&type=ws#@proxy_mtm+@proxy_mtm+@proxy_mtm+@proxy_mtm"
    # uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpiZWxlUEt1N2hhOUw0V3Z3N2MzZzdJT28yMEYxeEFQaHZ1cUpTbDZtZ01BQQ==@5.35.100.50:2#@proxy_mtm+@proxy_mtm+@proxy_mtm+@proxy_mtm"
    uri = "vmess://eyJhZGQiOiI4OC44MC4xODYuNjUiLCJhaWQiOiIwIiwiYWxwbiI6IiIsImZwIjoiIiwiaG9zdCI6IiIsImlkIjoiOGRiYmUzOWItNDY5ZS00YzI4LTg0YjMtZTFhOWE1ZmEyZGYyIiwibmV0Ijoia2NwIiwicGF0aCI6InpJcUpGOXQ5ZnQiLCJwb3J0IjoiNDQzIiwicHMiOiJAcHJveHlfbXRtIEBwcm94eV9tdG0gQHByb3h5X210bSBAcHJveHlfbXRtIiwic2N5IjoiYXV0byIsInNuaSI6IiIsInRscyI6IiIsInR5cGUiOiJub25lIiwidiI6IjIifQ=="
    create_config = create_config_object(uri)
    v2ray_config_util = V2rayConfigUtil()
    result = v2ray_config_util.get_v2ray_config(create_config)
    config = result.content
    print(config)

