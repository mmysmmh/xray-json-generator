import time

from apps.xray_json_generator.config_type import EConfigType
from apps.xray_json_generator.xray_config import BaseConfig, XrayConfig


class ServerConfig(BaseConfig):
    def __init__(self, config_version=3, config_type=None, added_time=0, remarks="", outbound_bean=None,
                 full_config=None):
        self.configVersion = config_version
        self.configType = config_type
        self.addedTime = added_time if added_time != 0 else int(time.time() * 1000)
        self.remarks = remarks
        self.outboundBean = outbound_bean
        self.fullConfig = full_config

    @staticmethod
    def create(config_type_tuple):
        config_type = config_type_tuple.value[1]
        protocol = config_type_tuple.value[0]
        if (config_type == EConfigType.VMESS.value[1] or
                config_type == EConfigType.VLESS.value[1]):
            return ServerConfig(
                config_type=config_type,
                outbound_bean=XrayConfig.OutboundBean(
                    protocol=protocol.lower(),
                    settings=XrayConfig.OutboundBean.OutSettingsBean(
                        vnext=[XrayConfig.OutboundBean.OutSettingsBean.VnextBean(
                            users=[XrayConfig.OutboundBean.OutSettingsBean.VnextBean.UsersBean()]
                        )]
                    ),
                    stream_settings=XrayConfig.OutboundBean.StreamSettingsBean()
                )
            )

        elif (config_type == EConfigType.CUSTOM.value[1] or
              config_type == EConfigType.WIREGUARD.value[1]):
            return ServerConfig(config_type=config_type)

        elif (config_type == EConfigType.SHADOWSOCKS.value[1] or
              config_type == EConfigType.SOCKS.value[1] or
              config_type == EConfigType.TROJAN.value[1]):
            return ServerConfig(
                config_type=config_type,
                outbound_bean=XrayConfig.OutboundBean(
                    protocol=protocol.lower(),
                    settings=XrayConfig.OutboundBean.OutSettingsBean(
                        servers=[XrayConfig.OutboundBean.OutSettingsBean.ServersBean()]
                    ),
                    stream_settings=XrayConfig.OutboundBean.StreamSettingsBean()
                )
            )

    def get_proxy_outbound(self):
        if self.configType != EConfigType.CUSTOM.value[1]:
            return self.outboundBean
        return self.fullConfig.get_proxy_outbound() if self.fullConfig else None
