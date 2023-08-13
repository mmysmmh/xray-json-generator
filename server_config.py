import time
import urllib.parse

from config_type import EConfigType
from v2ray_config import V2rayConfig, BaseConfig


class ServerConfig(BaseConfig):
    def __init__(self, configVersion=3, configType=None, addedTime=0, remarks="", outboundBean=None, fullConfig=None):
        self.configVersion = configVersion
        self.configType = configType
        self.addedTime = addedTime if addedTime != 0 else int(time.time() * 1000)
        self.remarks = remarks
        self.outboundBean = outboundBean
        self.fullConfig = fullConfig

    @staticmethod
    def create(configType):
        protocol = urllib.parse.urlparse(configType).scheme
        if (configType == EConfigType.VMESS.value[1] or
                configType == EConfigType.VLESS.value[1]):
            return ServerConfig(
                configType=configType,
                outboundBean=V2rayConfig.OutboundBean(
                    protocol=protocol.lower(),
                    settings=V2rayConfig.OutboundBean.OutSettingsBean(
                        vnext=[V2rayConfig.OutboundBean.OutSettingsBean.VnextBean(
                            users=[V2rayConfig.OutboundBean.OutSettingsBean.VnextBean.UsersBean()]
                        )]
                    ),
                    streamSettings=V2rayConfig.OutboundBean.StreamSettingsBean()
                )
            )

        elif (configType == EConfigType.CUSTOM.value[1] or
              configType == EConfigType.WIREGUARD.value[1]):
            return ServerConfig(configType=configType)

        elif (configType == EConfigType.SHADOWSOCKS.value[1] or
              configType == EConfigType.SOCKS.value[1] or
              configType == EConfigType.TROJAN.value[1]):
            return ServerConfig(
                configType=configType,
                outboundBean=V2rayConfig.OutboundBean(
                    protocol=protocol.lower(),
                    settings=V2rayConfig.OutboundBean.OutSettingsBean(
                        servers=[V2rayConfig.OutboundBean.OutSettingsBean.ServersBean()]
                    ),
                    streamSettings=V2rayConfig.OutboundBean.StreamSettingsBean()
                )
            )

    def getProxyOutbound(self):
        if self.configType != EConfigType.CUSTOM.value[1]:
            return self.outboundBean
        return self.fullConfig.getProxyOutbound() if self.fullConfig else None
