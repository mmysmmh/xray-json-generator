import json

from config_type import EConfigType

DEFAULT_PORT = 443
DEFAULT_SECURITY = "auto"
DEFAULT_LEVEL = 8
DEFAULT_NETWORK = "tcp"

TLS = "tls"
REALITY = "reality"
HTTP = "http"


class BaseConfig:
    def convert_list_to_dict(self, input_list: list):
        """
            converting list to dict

        Args:
            input_list (list): input list

        Returns:
            dict: dict of converted list
        """
        return [input_data.dict() for input_data in input_list]

    def dict(self):
        """
        change a list to a dictionary.

        Returns:
            (dict): dictionary from input list.
        """
        data = self.__dict__
        new_data = {}
        for k, v in data.items():
            if not v and not v == 0:
                continue
                # new_data[k] = None
            elif type(v) in (list, tuple):
                new_data[k] = self.convert_list_to_dict(v)
            elif type(v) not in (float, int, str, dict, bool):
                result = v.dict()
                if result:
                    new_data[k] = result
            else:
                new_data[k] = v
        return new_data


class V2rayConfig(BaseConfig):

    def __init__(self, stats=None, log=None, policy=None, inbounds=None, outbounds=None,
                 dns=None, routing=None, api=None, transport=None, reverse=None, fakedns=None,
                 browser_forwarder=None):
        self.stats = stats
        self.log = log
        self.policy = policy
        self.inbounds = inbounds or []
        self.outbounds = outbounds or []
        self.dns = dns
        self.routing = routing
        self.api = api
        self.transport = transport
        self.reverse = reverse
        self.fakedns = fakedns
        self.browserForwarder = browser_forwarder

    class LogBean(BaseConfig):
        def __init__(self, access, error, loglevel=None, dnsLog=None):
            self.access = access
            self.error = error
            self.loglevel = loglevel
            self.dnsLog = dnsLog

    class InboundBean(BaseConfig):
        def __init__(self, tag, port, protocol, listen=None, settings=None, sniffing=None,
                     streamSettings=None, allocate=None):
            self.tag = tag
            self.port = port
            self.protocol = protocol
            self.listen = listen
            self.settings = settings
            self.sniffing = sniffing
            self.streamSettings = streamSettings
            self.allocate = allocate

        class InSettingsBean:
            def __init__(self, auth=None, udp=None, userLevel=None, address=None, port=None, network=None):
                self.auth = auth
                self.udp = udp
                self.userLevel = userLevel
                self.address = address
                self.port = port
                self.network = network

        class SniffingBean:
            def __init__(self, enabled, destOverride, metadataOnly=None):
                self.enabled = enabled
                self.destOverride = destOverride
                self.metadataOnly = metadataOnly

    class OutboundBean(BaseConfig):
        def __init__(self, tag="proxy", protocol=None, settings=None, streamSettings=None,
                     proxySettings=None, sendThrough=None, mux=None):
            self.tag = tag
            self.protocol = protocol
            self.settings = settings
            self.streamSettings = streamSettings
            self.proxySettings = proxySettings
            self.sendThrough = sendThrough
            self.mux = mux or self.MuxBean(False)

        class OutSettingsBean(BaseConfig):
            def __init__(self, vnext=None, servers=None, response=None, network=None,
                         address=None, port=None, domainStrategy=None, redirect=None,
                         userLevel=None, inboundTag=None, secretKey=None, peers=None):
                self.vnext = vnext or []
                self.servers = servers or []
                self.response = response
                self.network = network
                self.address = address
                self.port = port
                self.domainStrategy = domainStrategy
                self.redirect = redirect
                self.userLevel = userLevel
                self.inboundTag = inboundTag
                self.secretKey = secretKey
                self.peers = peers or []

            class VnextBean(BaseConfig):
                def __init__(self, address="", port=DEFAULT_PORT, users=None):
                    self.address = address
                    self.port = port
                    self.users = users or []

                class UsersBean(BaseConfig):
                    def __init__(self, id="", alterId=None, security=DEFAULT_SECURITY,
                                 level=DEFAULT_LEVEL, encryption="", flow=""):
                        self.id = id
                        self.alterId = alterId
                        self.security = security
                        self.level = level
                        self.encryption = encryption
                        self.flow = flow

            class ServersBean(BaseConfig):
                def __init__(self, address="", method="chacha20-poly1305", ota=False,
                             password="", port=DEFAULT_PORT, level=DEFAULT_LEVEL,
                             email=None, flow=None, ivCheck=None, users=None):
                    self.address = address
                    self.method = method
                    self.ota = ota
                    self.password = password
                    self.port = port
                    self.level = level
                    self.email = email
                    self.flow = flow
                    self.ivCheck = ivCheck
                    self.users = users or []

                class SocksUsersBean(BaseConfig):
                    def __init__(self, user="", passw="", level=DEFAULT_LEVEL):
                        self.user = user
                        self.passw = passw
                        self.level = level

            class Response(BaseConfig):
                def __init__(self, type):
                    self.type = type

            class WireGuardBean(BaseConfig):
                def __init__(self, publicKey="", endpoint=""):
                    self.publicKey = publicKey
                    self.endpoint = endpoint

        class StreamSettingsBean(BaseConfig):
            def __init__(self, network=DEFAULT_NETWORK, security="", tcpSettings=None,
                         kcpSettings=None, wsSettings=None, httpSettings=None,
                         tlsSettings=None, quicSettings=None, realitySettings=None,
                         grpcSettings=None, dsSettings=None, sockopt=None):
                self.network = network
                self.security = security
                self.tcpSettings = tcpSettings
                self.kcpSettings = kcpSettings
                self.wsSettings = wsSettings
                self.httpSettings = httpSettings
                self.tlsSettings = tlsSettings
                self.quicSettings = quicSettings
                self.realitySettings = realitySettings
                self.grpcSettings = grpcSettings
                self.dsSettings = dsSettings
                self.sockopt = sockopt

            class TcpSettingsBean(BaseConfig):
                def __init__(self, header=None, acceptProxyProtocol=None):
                    self.header = header or self.HeaderBean()
                    self.acceptProxyProtocol = acceptProxyProtocol

                class HeaderBean(BaseConfig):
                    def __init__(self, type="none", request=None, response=None):
                        self.type = type
                        self.request = request or self.RequestBean()
                        self.response = response

                    class RequestBean(BaseConfig):
                        def __init__(self, path=None, headers=None, version=None, method=None):
                            self.path = path or []
                            self.headers = headers or self.HeadersBean()
                            self.version = version
                            self.method = method

                        class HeadersBean(BaseConfig):
                            def __init__(self, Host=None, UserAgent=None, AcceptEncoding=None,
                                         Connection=None, Pragma=None):
                                self.Host = Host or []
                                self.UserAgent = UserAgent or []
                                self.AcceptEncoding = AcceptEncoding or []
                                self.Connection = Connection or []
                                self.Pragma = Pragma

            class KcpSettingsBean(BaseConfig):
                def __init__(self, mtu=1350, tti=50, uplinkCapacity=12, downlinkCapacity=100,
                             congestion=False, readBufferSize=1, writeBufferSize=1,
                             header=None, seed=None):
                    self.mtu = mtu
                    self.tti = tti
                    self.uplinkCapacity = uplinkCapacity
                    self.downlinkCapacity = downlinkCapacity
                    self.congestion = congestion
                    self.readBufferSize = readBufferSize
                    self.writeBufferSize = writeBufferSize
                    self.header = header or self.HeaderBean()
                    self.seed = seed

                class HeaderBean(BaseConfig):
                    def __init__(self, type="none"):
                        self.type = type

            class WsSettingsBean(BaseConfig):
                def __init__(self, path="", headers=None, maxEarlyData=None,
                             useBrowserForwarding=None, acceptProxyProtocol=None):
                    self.path = path
                    self.headers = headers or self.HeadersBean()
                    self.maxEarlyData = maxEarlyData
                    self.useBrowserForwarding = useBrowserForwarding
                    self.acceptProxyProtocol = acceptProxyProtocol

                class HeadersBean(BaseConfig):
                    def __init__(self, Host=""):
                        self.Host = Host

            class HttpSettingsBean(BaseConfig):
                def __init__(self, host=None, path=""):
                    self.host = host or []
                    self.path = path

            class TlsSettingsBean(BaseConfig):
                def __init__(self, allowInsecure=False, serverName="", alpn=None,
                             minVersion=None, maxVersion=None, preferServerCipherSuites=None,
                             cipherSuites=None, fingerprint=None, certificates=None,
                             disableSystemRoot=None, enableSessionResumption=None,
                             show=False, publicKey=None, shortId=None, spiderX=None):
                    self.allowInsecure = allowInsecure
                    self.serverName = serverName
                    self.alpn = alpn or []
                    self.minVersion = minVersion
                    self.maxVersion = maxVersion
                    self.preferServerCipherSuites = preferServerCipherSuites
                    self.cipherSuites = cipherSuites
                    self.fingerprint = fingerprint
                    self.certificates = certificates or []
                    self.disableSystemRoot = disableSystemRoot
                    self.enableSessionResumption = enableSessionResumption
                    self.show = show
                    self.publicKey = publicKey
                    self.shortId = shortId
                    self.spiderX = spiderX

            class QuicSettingBean(BaseConfig):
                def __init__(self, security="none", key="", header=None):
                    self.security = security
                    self.key = key
                    self.header = header or self.HeaderBean()

                class HeaderBean(BaseConfig):
                    def __init__(self, type="none"):
                        self.type = type

            class GrpcSettingsBean(BaseConfig):
                def __init__(self, serviceName="", multiMode=None):
                    self.serviceName = serviceName
                    self.multiMode = multiMode

            def populate_transport_settings(self, transport, headerType=None, host=None, path=None,
                                            seed=None, quicSecurity=None, key=None, mode=None,
                                            serviceName=None):
                sni = ""
                self.network = transport
                if self.network == "tcp":
                    tcp_setting = self.TcpSettingsBean()
                    if headerType == HTTP:
                        tcp_setting.header.type = HTTP
                        if host or path:
                            request_obj = self.TcpSettingsBean.HeaderBean.RequestBean()
                            request_obj.headers.Host = [h.strip() for h in (host or "").split(",")
                                                        if h.strip()]
                            request_obj.path = [p.strip() for p in (path or "").split(",") if
                                                p.strip()]
                            tcp_setting.header.request = request_obj
                            sni = request_obj.headers.Host[0] if request_obj.headers.Host else sni
                    else:
                        tcp_setting.header.type = "none"
                        sni = host or ""
                    self.tcpSettings = tcp_setting
                elif self.network == "kcp":
                    kcp_setting = self.KcpSettingsBean()
                    kcp_setting.header.type = headerType or "none"
                    kcp_setting.seed = None if seed is None else seed
                    self.kcpSettings = kcp_setting
                elif self.network == "ws":
                    ws_setting = self.WsSettingsBean()
                    ws_setting.headers.Host = host or ""
                    sni = ws_setting.headers.Host
                    ws_setting.path = path or "/"
                    self.wsSettings = ws_setting
                elif self.network in ("h2", "http"):
                    self.network = "h2"
                    h2_setting = self.HttpSettingsBean()
                    h2_setting.host = [h.strip() for h in (host or "").split(",") if h.strip()]
                    sni = h2_setting.host[0] if h2_setting.host else sni
                    h2_setting.path = path or "/"
                    self.httpSettings = h2_setting
                elif self.network == "quic":
                    quic_setting = self.QuicSettingBean()
                    quic_setting.security = quicSecurity or "none"
                    quic_setting.key = key or ""
                    quic_setting.header.type = headerType or "none"
                    self.quicSettings = quic_setting
                elif self.network == "grpc":
                    grpc_setting = self.GrpcSettingsBean()
                    grpc_setting.multiMode = mode == "multi"
                    grpc_setting.serviceName = serviceName or ""
                    sni = host or ""
                    self.grpcSettings = grpc_setting
                return sni

            def populate_tls_settings(self, stream_security, allow_insecure, sni, fingerprint, alpns,
                                      public_key, short_id, spider_x):
                self.security = stream_security
                tls_setting = self.TlsSettingsBean(
                    allowInsecure=allow_insecure,
                    serverName=sni,
                    fingerprint=fingerprint,
                    alpn=[a.strip() for a in (alpns or "").split(",") if a.strip()],
                    publicKey=public_key,
                    shortId=short_id,
                    spiderX=spider_x
                )
                if self.security == TLS:
                    self.tlsSettings = tls_setting
                    self.realitySettings = None
                elif self.security == REALITY:
                    self.tlsSettings = None
                    self.realitySettings = tls_setting

        class MuxBean(BaseConfig):
            def __init__(self, enabled, concurrency=8):
                self.enabled = enabled
                self.concurrency = concurrency

        def get_server_address(self):
            if self.protocol.lower() == EConfigType.VMESS.name.lower() or self.protocol.lower() == EConfigType.VLESS.name.lower():
                return self.settings.vnext[0].address
            elif self.protocol.lower() == EConfigType.SHADOWSOCKS.name.lower() or self.protocol.lower() == EConfigType.SOCKS.name.lower() or self.protocol.lower() == EConfigType.TROJAN.name.lower():
                return self.settings.servers[0].address
            elif self.protocol.lower() == EConfigType.WIREGUARD.name.lower():
                return self.settings.peers[0].endpoint.split(":")[0]
            return None

        def get_server_port(self):
            if self.protocol.lower() == EConfigType.VMESS.name.lower() or self.protocol.lower() == EConfigType.VLESS.name.lower():
                return self.settings.vnext[0].port
            elif self.protocol.lower() == EConfigType.SHADOWSOCKS.name.lower() or self.protocol.lower() == EConfigType.SOCKS.name.lower() or self.protocol.lower() == EConfigType.TROJAN.name.lower():
                return self.settings.servers[0].port
            elif self.protocol.lower() == EConfigType.WIREGUARD.name.lower():
                return int(self.settings.peers[0].endpoint.split(":")[-1])
            return None

        def get_password(self):
            if self.protocol.lower() == EConfigType.VMESS.name.lower() or self.protocol.lower() == EConfigType.VLESS.name.lower():
                return self.settings.vnext[0].users[0].id
            elif self.protocol.lower() == EConfigType.SHADOWSOCKS.name.lower() or self.protocol.lower() == EConfigType.TROJAN.name.lower():
                return self.settings.servers[0].password
            elif self.protocol.lower() == EConfigType.SOCKS.name.lower():
                return self.settings.servers[0].users[0].get('pass')
            elif self.protocol.lower() == EConfigType.WIREGUARD.name.lower():
                return self.settings.secretKey
            return None

        def get_security_encryption(self):
            if self.protocol.lower() == EConfigType.VMESS.name.lower():
                return self.settings.vnext[0].users[0].security
            elif self.protocol.lower() == EConfigType.VLESS.name.lower():
                return self.settings.vnext[0].users[0].encryption
            elif self.protocol.lower() == EConfigType.SHADOWSOCKS.name.lower():
                return self.settings.servers[0].method
            return None

        def get_transport_setting_details(self):
            if self.protocol.lower() == EConfigType.VMESS.name.lower() or self.protocol.lower() == EConfigType.VLESS.name.lower() or self.protocol.lower() == EConfigType.TROJAN.name.lower():
                transport = self.streamSettings.network
                if transport == "tcp":
                    tcp_setting = self.streamSettings.tcpSettings
                    return [
                        tcp_setting.header.type,
                        ",".join(tcp_setting.header.request.headers.Host) if tcp_setting.header.request else "",
                        ",".join(tcp_setting.header.request.path) if tcp_setting.header.request else ""
                    ]
                elif transport == "kcp":
                    kcp_setting = self.streamSettings.kcpSettings
                    return [kcp_setting.header.type, "", kcp_setting.seed]
                elif transport == "ws":
                    ws_setting = self.streamSettings.wsSettings
                    return ["", ws_setting.headers.Host, ws_setting.path]
                elif transport == "h2":
                    h2_setting = self.streamSettings.httpSettings
                    return ["", ",".join(h2_setting.host), h2_setting.path]
                elif transport == "quic":
                    quic_setting = self.streamSettings.quicSettings
                    return [quic_setting.header.type, quic_setting.security, quic_setting.key]
                elif transport == "grpc":
                    grpc_setting = self.streamSettings.grpcSettings
                    return ["multi" if grpc_setting.multiMode else "gun", "", grpc_setting.serviceName]
            return None

    class DnsBean(BaseConfig):
        def __init__(self, servers=None, hosts=None, clientIp=None,
                     disableCache=None, queryStrategy=None, tag=None):
            self.servers = servers or []
            self.hosts = hosts or {}
            self.clientIp = clientIp
            self.disableCache = disableCache
            self.queryStrategy = queryStrategy
            self.tag = tag

        class ServersBean(BaseConfig):
            def __init__(self, address="", port=None, domains=None, expectIPs=None,
                         clientIp=None):
                self.address = address
                self.port = port
                self.domains = domains or []
                self.expectIPs = expectIPs or []
                self.clientIp = clientIp

    class RoutingBean(BaseConfig):
        def __init__(self, domainStrategy, domainMatcher=None, rules=None, balancers=None):
            self.domainStrategy = domainStrategy
            self.domainMatcher = domainMatcher
            self.rules = rules or []
            self.balancers = balancers or []

        class RulesBean(BaseConfig):
            def __init__(self, type="", ip=None, domain=None, outboundTag="",
                         balancerTag=None, port=None, sourcePort=None,
                         network=None, source=None, user=None, inboundTag=None,
                         protocol=None, attrs=None, domainMatcher=None):
                self.type = type
                self.ip = ip or []
                self.domain = domain or []
                self.outboundTag = outboundTag
                self.balancerTag = balancerTag
                self.port = port
                self.sourcePort = sourcePort
                self.network = network
                self.source = source or []
                self.user = user or []
                self.inboundTag = inboundTag or []
                self.protocol = protocol or []
                self.attrs = attrs
                self.domainMatcher = domainMatcher

    class PolicyBean(BaseConfig):
        def __init__(self, levels=None, system=None):
            self.levels = levels or {}
            self.system = system

        class LevelBean(BaseConfig):
            def __init__(self, handshake=None, connIdle=None, uplinkOnly=None,
                         downlinkOnly=None, statsUserUplink=None, statsUserDownlink=None,
                         bufferSize=None):
                self.handshake = handshake
                self.connIdle = connIdle
                self.uplinkOnly = uplinkOnly
                self.downlinkOnly = downlinkOnly
                self.statsUserUplink = statsUserUplink
                self.statsUserDownlink = statsUserDownlink
                self.bufferSize = bufferSize

    class FakednsBean(BaseConfig):
        def __init__(self, ipPool="198.18.0.0/15", poolSize=10000):
            self.ipPool = ipPool
            self.poolSize = poolSize

    def getProxyOutbound(self):
        for outbound in self.outbounds:
            for protocol in EConfigType:
                if outbound.protocol.lower() == protocol.name.lower():
                    return outbound
        return None

    def toPrettyPrinting(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
