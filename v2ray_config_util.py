import json
import logging
from typing import Dict

from consts import PREF_LOGLEVEL, PREF_LOCAL_DNS_ENABLED, PREF_SPEED_ENABLED, PORT_HTTP, PORT_SOCKS, TAG_AGENT, \
    PORT_LOCAL_DNS, PREF_PROXY_SHARING
from config_type import EConfigType
from server_config import ServerConfig

from utils import Utils
from v2ray_config import V2rayConfig, DEFAULT_NETWORK, HTTP


class V2rayConfigUtil:
    class Result:
        def __init__(self, status=None, content=None):
            self.status = status
            self.content = content

    def get_v2ray_config(self, config: "ServerConfig"):
        try:
            if not config:
                return self.Result(False, "")
            if config.configType == EConfigType.CUSTOM.value[1]:
                custom_config = json.dumps(config.configType, indent=4)
                return self.Result(True, custom_config)
            outbound: "V2rayConfig.OutboundBean" = config.getProxyOutbound()

            if not outbound:
                return self.Result(False, "")
            result = self.get_v2ray_non_custom_config(outbound)
            return result

        except Exception as e:
            # logging.exception(e)
            return self.Result(False, "")

    def get_v2ray_non_custom_config(self, outbound: "V2rayConfig.OutboundBean"):
        result = self.Result(False, "")
        assets = Utils.read_text_from_assets("v2ray_config.json")
        if not assets:
            return result
        v2ray_config = json.loads(assets)
        v2ray_config["log"]["loglevel"] = PREF_LOGLEVEL
        v2ray_config = self.inbounds(v2ray_config) or v2ray_config
        outbound = self.http_request_object(outbound) or outbound
        v2ray_config["outbounds"][0] = outbound.dict()
        v2ray_config = self.routing(v2ray_config) or v2ray_config
        # self.fakedns(v2ray_config)
        v2ray_config = self.dns(v2ray_config) or v2ray_config
        if PREF_LOCAL_DNS_ENABLED:
            v2ray_config = self.custom_local_dns(v2ray_config) or v2ray_config
        if not PREF_SPEED_ENABLED:
            v2ray_config["stats"] = None
            v2ray_config["policy"] = None
        result.status = True
        result.content = json.dumps(v2ray_config, indent=4)
        return result

    def inbounds(self, v2ray_config) -> Dict:
        try:
            for cur_inbound in v2ray_config["inbounds"]:
                if PREF_PROXY_SHARING:
                    cur_inbound["listen"] = "127.0.0.1"
            v2ray_config["inbounds"][0]["port"] = PORT_SOCKS
            fakedns = False
            sniff_all_tls_and_http = True
            v2ray_config["inbounds"][0]["sniffing"]["enabled"] = fakedns or sniff_all_tls_and_http
            if not sniff_all_tls_and_http:
                v2ray_config["inbounds"][0]["sniffing"]["destOverride"].clear()
            if fakedns:
                v2ray_config["inbounds"][0]["sniffing"]["destOverride"].append("fakedns")

            v2ray_config["inbounds"][1]["port"] = PORT_HTTP
        except Exception as e:
            # logging.exception(e)
            return False
        return v2ray_config

    # def fakedns(self, v2ray_config):
    #     if settings_storage.decode_bool(AppConfig.PREF_FAKE_DNS_ENABLED, False):
    #         v2ray_config["fakedns"] = [{}]
    #         for outbound in v2ray_config["outbounds"]:
    #             if outbound["protocol"] == "freedom":
    #                 outbound["settings"]["domainStrategy"] = "UseIP"

    def routing(self, v2ray_config) -> Dict:
        try:
            # routing_user_rule(settings_storage.decode_string(AppConfig.PREF_V2RAY_ROUTING_AGENT, ""),
            #                   AppConfig.TAG_AGENT, v2ray_config)
            # routing_user_rule(settings_storage.decode_string(AppConfig.PREF_V2RAY_ROUTING_DIRECT, ""),
            #                   AppConfig.TAG_DIRECT, v2ray_config)
            # routing_user_rule(settings_storage.decode_string(AppConfig.PREF_V2RAY_ROUTING_BLOCKED, ""),
            #                   AppConfig.TAG_BLOCKED, v2ray_config)

            v2ray_config["routing"]["domainStrategy"] = "IPIfNonMatch"

            # v2ray_config["routing"]["domainMatcher"] = "mph"  # Uncomment if needed
            #
            # routing_mode = 0
            #
            # googleapis_route = {
            #     "type": "field",
            #     "outboundTag": TAG_AGENT,
            #     "domain": ["domain:googleapis.cn"]
            # }
            #
            # if routing_mode == ERoutingMode.BYPASS_LAN.value:
            #     routing_geo("ip", "private", AppConfig.TAG_DIRECT, v2ray_config)
            # elif routing_mode == ERoutingMode.BYPASS_MAINLAND.value:
            #     routing_geo("", "cn", AppConfig.TAG_DIRECT, v2ray_config)
            #     v2ray_config["routing"]["rules"].insert(0, googleapis_route)
            # elif routing_mode == ERoutingMode.BYPASS_LAN_MAINLAND.value:
            #     routing_geo("ip", "private", AppConfig.TAG_DIRECT, v2ray_config)
            #     routing_geo("", "cn", AppConfig.TAG_DIRECT, v2ray_config)
            #     v2ray_config["routing"]["rules"].insert(0, googleapis_route)
            # elif routing_mode == ERoutingMode.GLOBAL_DIRECT.value:
            #     global_direct = {
            #         "type": "field",
            #         "outboundTag": AppConfig.TAG_DIRECT,
            #         "port": "0-65535"
            #     }
            #     v2ray_config["routing"]["rules"].insert(0, global_direct)

        except Exception as e:
            # logging.exception(e)
            return False
        return v2ray_config

    # def routing_geo(self, ip_or_domain, code, tag, v2ray_config):
    #     try:
    #         if code:
    #             # IP
    #             if ip_or_domain == "ip" or not ip_or_domain:
    #                 rules_ip = {
    #                     "type": "field",
    #                     "outboundTag": tag,
    #                     "ip": ["geoip:" + code]
    #                 }
    #                 v2ray_config["routing"]["rules"].append(rules_ip)
    #
    #             if ip_or_domain == "domain" or not ip_or_domain:
    #                 # Domain
    #                 rules_domain = {
    #                     "type": "field",
    #                     "outboundTag": tag,
    #                     "domain": ["geosite:" + code]
    #                 }
    #                 v2ray_config["routing"]["rules"].append(rules_domain)
    #     except Exception as e:
    #         print(e)

    # def routing_user_rule(self, user_rule, tag, v2ray_config):
    #     try:
    #         if user_rule:
    #             rules_domain = {
    #                 "type": "field",
    #                 "outboundTag": tag,
    #                 "domain": []
    #             }
    #
    #             rules_ip = {
    #                 "type": "field",
    #                 "outboundTag": tag,
    #                 "ip": []
    #             }
    #
    #             for item in map(str.strip, user_rule.split(",")):
    #                 if Utils.is_ip_address(item) or item.startswith("geoip:"):
    #                     rules_ip["ip"].append(item)
    #                 elif item:
    #                     rules_domain["domain"].append(item)
    #
    #             if rules_domain["domain"]:
    #                 v2ray_config["routing"]["rules"].append(rules_domain)
    #             if rules_ip["ip"]:
    #                 v2ray_config["routing"]["rules"].append(rules_ip)
    #     except Exception as e:
    #         print(e)
    #
    # def user_rule_to_domain(self, user_rule):
    #     domain = []
    #     for item in map(str.strip, user_rule.split(",")):
    #         if item.startswith("geosite:") or item.startswith("domain:"):
    #             domain.append(item)
    #     return domain

    def custom_local_dns(self, v2ray_config) -> Dict:
        try:
            # if settings_storage.decode_bool(AppConfig.PREF_FAKE_DNS_ENABLED):
            #     geosite_cn = ["geosite:cn"]
            #     proxy_domain = user_rule_to_domain(settings_storage.decode_string(AppConfig.PREF_V2RAY_ROUTING_AGENT))
            #     direct_domain = user_rule_to_domain(settings_storage.decode_string(AppConfig.PREF_V2RAY_ROUTING_DIRECT))
            #     v2ray_config["dns"]["servers"].insert(0, {
            #         "address": "fakedns",
            #         "domains": geosite_cn + proxy_domain + direct_domain
            #     })

            remote_dns = Utils.get_remote_dns_servers()
            if not any(
                    e for e in v2ray_config["inbounds"] if e["protocol"] == "dokodemo-door" and e["tag"] == "dns-in"):
                dns_inbound_settings = {
                    "address": remote_dns[0] if Utils.is_pure_ip_address(remote_dns[0]) else "1.1.1.1",
                    "port": 53,
                    "network": "tcp,udp"
                }
                local_dns_port = int(PORT_LOCAL_DNS)
                v2ray_config["inbounds"].append({
                    "tag": "dns-in",
                    "port": local_dns_port,
                    "listen": "127.0.0.1",
                    "protocol": "dokodemo-door",
                    "settings": dns_inbound_settings,
                    "sniffing": None
                })

            if not any(e for e in v2ray_config["outbounds"] if e["protocol"] == "dns" and e["tag"] == "dns-out"):
                v2ray_config["outbounds"].append({
                    "protocol": "dns",
                    "tag": "dns-out",
                    "settings": None,
                    "streamSettings": None,
                    "mux": None
                })

            v2ray_config["routing"]["rules"].insert(0, {
                "type": "field",
                "inboundTag": ["dns-in"],
                "outboundTag": "dns-out",
                "domain": None
            })
        except Exception as e:
            # logging.exception(e)
            return False
        return v2ray_config

    def dns(self, v2ray_config) -> Dict:
        try:
            hosts = {}
            servers = []
            remote_dns = Utils.get_remote_dns_servers()
            servers.extend(remote_dns)
            # proxy_domain = user_rule_to_domain(settings_storage.decode_string(AppConfig.PREF_V2RAY_ROUTING_AGENT))
            #
            # servers.extend(remote_dns)
            # if proxy_domain:
            #     servers.append({
            #         "address": remote_dns[0],
            #         "port": 53,
            #         "domains": proxy_domain
            #     })
            #
            # direct_domain = user_rule_to_domain(settings_storage.decode_string(AppConfig.PREF_V2RAY_ROUTING_DIRECT))
            # routing_mode = 0
            # if direct_domain or routing_mode == ERoutingMode.BYPASS_MAINLAND.value or routing_mode == ERoutingMode.BYPASS_LAN_MAINLAND.value:
            #     domestic_dns = Utils.get_domestic_dns_servers()
            #     geosite_cn = ["geosite:cn"]
            #     geoip_cn = ["geoip:cn"]
            #     if direct_domain:
            #         servers.append({
            #             "address": domestic_dns[0],
            #             "port": 53,
            #             "domains": direct_domain,
            #             "ip": geoip_cn
            #         })
            #     if routing_mode == ERoutingMode.BYPASS_MAINLAND.value or routing_mode == ERoutingMode.BYPASS_LAN_MAINLAND.value:
            #         servers.append({
            #             "address": domestic_dns[0],
            #             "port": 53,
            #             "domains": geosite_cn,
            #             "ip": geoip_cn
            #         })
            #     if Utils.is_pure_ip_address(domestic_dns[0]):
            #         v2ray_config["routing"]["rules"].insert(0, {
            #             "type": "field",
            #             "outboundTag": AppConfig.TAG_DIRECT,
            #             "port": "53",
            #             "ip": [domestic_dns[0]],
            #             "domain": None
            #         })
            #
            # blk_domain = user_rule_to_domain(settings_storage.decode_string(AppConfig.PREF_V2RAY_ROUTING_BLOCKED))
            # if blk_domain:
            #     hosts.update({item: "127.0.0.1" for item in blk_domain})

            hosts["domain:googleapis.cn"] = "googleapis.com"

            v2ray_config["dns"] = {
                "servers": servers,
                "hosts": hosts
            }

            if Utils.is_pure_ip_address(remote_dns[0]):
                v2ray_config["routing"]["rules"].insert(0, {
                    "type": "field",
                    "outboundTag": TAG_AGENT,
                    "port": "53",
                    "ip": [remote_dns[0]],
                    "domain": None
                })
        except Exception as e:
            # logging.exception(e)
            return False
        return v2ray_config

    def http_request_object(self, outbound: V2rayConfig.OutboundBean):
        try:
            if (outbound.streamSettings and
                    outbound.streamSettings.network == DEFAULT_NETWORK and
                    outbound.streamSettings.tcpSettings.header.type == HTTP):
                path = outbound.streamSettings.tcpSettings.header.request.path
                host = outbound.streamSettings.tcpSettings.header.request.headers.Host

                request_string = """{"version":"1.1","method":"GET","headers":{"User-Agent":["Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36","Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/53.0.2785.109 Mobile/14A456 Safari/601.1.46"],"Accept-Encoding":["gzip, deflate"],"Connection":["keep-alive"],"Pragma":"no-cache"}}"""
                request_obj = json.loads(request_string)
                outbound.streamSettings.tcpSettings.header.request = request_obj
                outbound.streamSettings.tcpSettings.header.request.path = ["/"] if not path else path
                outbound.streamSettings.tcpSettings.header.request.headers.Host = host

        except Exception as e:
            # logging.exception(e)
            return False
        return outbound
