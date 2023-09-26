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
    @classmethod
    def get_value(cls, v):
        if type(v) in (list, tuple):
            return cls.convert_list_to_dict(v)
        elif type(v) not in (float, int, str, dict, bool):
            return v.dict()
        return v

    @classmethod
    def convert_list_to_dict(cls, input_list: list):
        """
            converting list to dict

        Args:
            input_list (list): input list

        Returns:
            dict: dict of converted list
        """
        return [cls.get_value(input_data) for input_data in input_list]

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
            new_data[k] = self.get_value(v)
        return new_data


class XrayConfig(BaseConfig):

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
        def __init__(self, access, error, loglevel=None, dns_log=None):
            self.access = access
            self.error = error
            self.loglevel = loglevel
            self.dnsLog = dns_log

    class InboundBean(BaseConfig):
        def __init__(self, tag, port, protocol, listen=None, settings=None, sniffing=None,
                     stream_settings=None, allocate=None):
            self.tag = tag
            self.port = port
            self.protocol = protocol
            self.listen = listen
            self.settings = settings
            self.sniffing = sniffing
            self.streamSettings = stream_settings
            self.allocate = allocate

        class InSettingsBean(BaseConfig):
            def __init__(self, auth=None, udp=None, user_level=None, address=None, port=None, network=None):
                self.auth = auth
                self.udp = udp
                self.userLevel = user_level
                self.address = address
                self.port = port
                self.network = network

        class SniffingBean(BaseConfig):
            def __init__(self, enabled, dest_override, metadata_only=None):
                self.enabled = enabled
                self.destOverride = dest_override
                self.metadataOnly = metadata_only

    class OutboundBean(BaseConfig):
        def __init__(self, tag="proxy", protocol=None, settings=None, stream_settings=None,
                     proxy_settings=None, send_through=None, mux=None):
            self.tag = tag
            self.protocol = protocol
            self.settings = settings
            self.streamSettings = stream_settings
            self.proxySettings = proxy_settings
            self.sendThrough = send_through
            self.mux = mux or self.MuxBean(False)

        class OutSettingsBean(BaseConfig):
            def __init__(self, vnext=None, servers=None, response=None, network=None,
                         address=None, port=None, domain_strategy=None, redirect=None,
                         user_level=None, inbound_tag=None, secret_key=None, peers=None):
                self.vnext = vnext or []
                self.servers = servers or []
                self.response = response
                self.network = network
                self.address = address
                self.port = port
                self.domainStrategy = domain_strategy
                self.redirect = redirect
                self.userLevel = user_level
                self.inboundTag = inbound_tag
                self.secretKey = secret_key
                self.peers = peers or []

            class VnextBean(BaseConfig):
                def __init__(self, address="", port=DEFAULT_PORT, users=None):
                    self.address = address
                    self.port = port
                    self.users = users or []

                class UsersBean(BaseConfig):
                    def __init__(self, id="", alter_id=None, security=DEFAULT_SECURITY,
                                 level=DEFAULT_LEVEL, encryption="", flow=""):
                        self.id = id
                        self.alterId = alter_id
                        self.security = security
                        self.level = level
                        self.encryption = encryption
                        self.flow = flow

            class ServersBean(BaseConfig):
                def __init__(self, address="", method="chacha20-poly1305", ota=False,
                             password="", port=DEFAULT_PORT, level=DEFAULT_LEVEL,
                             email=None, flow=None, iv_check=None, users=None):
                    self.address = address
                    self.method = method
                    self.ota = ota
                    self.password = password
                    self.port = port
                    self.level = level
                    self.email = email
                    self.flow = flow
                    self.ivCheck = iv_check
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
                def __init__(self, public_key="", endpoint=""):
                    self.publicKey = public_key
                    self.endpoint = endpoint

        class StreamSettingsBean(BaseConfig):
            def __init__(self, network=DEFAULT_NETWORK, security="", tcp_settings=None,
                         kcp_settings=None, ws_settings=None, http_settings=None,
                         tls_settings=None, quic_settings=None, reality_settings=None,
                         grpc_settings=None, ds_settings=None, sockopt=None):
                self.network = network
                self.security = security
                self.tcpSettings = tcp_settings
                self.kcpSettings = kcp_settings
                self.wsSettings = ws_settings
                self.httpSettings = http_settings
                self.tlsSettings = tls_settings
                self.quicSettings = quic_settings
                self.realitySettings = reality_settings
                self.grpcSettings = grpc_settings
                self.dsSettings = ds_settings
                self.sockopt = sockopt

            class TcpSettingsBean(BaseConfig):
                def __init__(self, header=None, accept_proxy_protocol=None):
                    self.header = header or self.HeaderBean()
                    self.acceptProxyProtocol = accept_proxy_protocol

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
                            def __init__(self, host=None, user_agent=None, accept_encoding=None,
                                         connection=None, pragma=None):
                                self.Host = host or []
                                self.UserAgent = user_agent or []
                                self.AcceptEncoding = accept_encoding or []
                                self.Connection = connection or []
                                self.Pragma = pragma

            class KcpSettingsBean(BaseConfig):
                def __init__(self, mtu=1350, tti=50, uplink_capacity=12, downlink_capacity=100,
                             congestion=False, read_buffer_size=1, write_buffer_size=1,
                             header=None, seed=None):
                    self.mtu = mtu
                    self.tti = tti
                    self.uplinkCapacity = uplink_capacity
                    self.downlinkCapacity = downlink_capacity
                    self.congestion = congestion
                    self.readBufferSize = read_buffer_size
                    self.writeBufferSize = write_buffer_size
                    self.header = header or self.HeaderBean()
                    self.seed = seed

                class HeaderBean(BaseConfig):
                    def __init__(self, type="none"):
                        self.type = type

            class WsSettingsBean(BaseConfig):
                def __init__(self, path="", headers=None, max_early_data=None,
                             use_browser_forwarding=None, accept_proxy_protocol=None):
                    self.path = path
                    self.headers = headers or self.HeadersBean()
                    self.maxEarlyData = max_early_data
                    self.useBrowserForwarding = use_browser_forwarding
                    self.acceptProxyProtocol = accept_proxy_protocol

                class HeadersBean(BaseConfig):
                    def __init__(self, host=""):
                        self.Host = host

            class HttpSettingsBean(BaseConfig):
                def __init__(self, host=None, path=""):
                    self.host = host or []
                    self.path = path

            class TlsSettingsBean(BaseConfig):
                def __init__(self, allow_insecure=False, server_name="", alpn=None,
                             min_version=None, max_version=None, prefer_server_cipher_suites=None,
                             cipher_suites=None, fingerprint=None, certificates=None,
                             disable_system_root=None, enable_session_resumption=None,
                             show=False, public_key=None, short_id=None, spider_x=None):
                    self.allowInsecure = allow_insecure
                    self.serverName = server_name
                    self.alpn = alpn or []
                    self.minVersion = min_version
                    self.maxVersion = max_version
                    self.preferServerCipherSuites = prefer_server_cipher_suites
                    self.cipherSuites = cipher_suites
                    self.fingerprint = fingerprint
                    self.certificates = certificates or []
                    self.disableSystemRoot = disable_system_root
                    self.enableSessionResumption = enable_session_resumption
                    self.show = show
                    self.publicKey = public_key
                    self.shortId = short_id
                    self.spiderX = spider_x

            class QuicSettingBean(BaseConfig):
                def __init__(self, security="none", key="", header=None):
                    self.security = security
                    self.key = key
                    self.header = header or self.HeaderBean()

                class HeaderBean(BaseConfig):
                    def __init__(self, type="none"):
                        self.type = type

            class GrpcSettingsBean(BaseConfig):
                def __init__(self, service_name="", multi_mode=None):
                    self.serviceName = service_name
                    self.multiMode = multi_mode

            def populate_transport_settings(self, transport, header_type=None, host=None, path=None,
                                            seed=None, quic_security=None, key=None, mode=None,
                                            service_name=None):
                sni = ""
                self.network = transport
                if self.network == "tcp":
                    tcp_setting = self.TcpSettingsBean()
                    if header_type == HTTP:
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
                    kcp_setting.header.type = header_type or "none"
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
                    quic_setting.security = quic_security or "none"
                    quic_setting.key = key or ""
                    quic_setting.header.type = header_type or "none"
                    self.quicSettings = quic_setting
                elif self.network == "grpc":
                    grpc_setting = self.GrpcSettingsBean()
                    grpc_setting.multiMode = mode == "multi"
                    grpc_setting.serviceName = service_name or ""
                    sni = host or ""
                    self.grpcSettings = grpc_setting
                return sni

            def populate_tls_settings(self, stream_security, allow_insecure, sni, fingerprint, alpns,
                                      public_key, short_id, spider_x):
                self.security = stream_security
                tls_setting = self.TlsSettingsBean(
                    allow_insecure=allow_insecure,
                    server_name=sni,
                    fingerprint=fingerprint,
                    alpn=[a.strip() for a in (alpns or "").split(",") if a.strip()],
                    public_key=public_key,
                    short_id=short_id,
                    spider_x=spider_x
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
            if (self.protocol.lower() == EConfigType.VMESS.name.lower() or
                    self.protocol.lower() == EConfigType.VLESS.name.lower()):
                return self.settings.vnext[0].address
            elif (self.protocol.lower() == EConfigType.SHADOWSOCKS.name.lower() or
                  self.protocol.lower() == EConfigType.SOCKS.name.lower() or
                  self.protocol.lower() == EConfigType.TROJAN.name.lower()):
                return self.settings.servers[0].address
            elif self.protocol.lower() == EConfigType.WIREGUARD.name.lower():
                return self.settings.peers[0].endpoint.split(":")[0]
            return None

        def get_server_port(self):
            if (self.protocol.lower() == EConfigType.VMESS.name.lower() or
                    self.protocol.lower() == EConfigType.VLESS.name.lower()):
                return self.settings.vnext[0].port
            elif (self.protocol.lower() == EConfigType.SHADOWSOCKS.name.lower() or
                  self.protocol.lower() == EConfigType.SOCKS.name.lower() or
                  self.protocol.lower() == EConfigType.TROJAN.name.lower()):
                return self.settings.servers[0].port
            elif self.protocol.lower() == EConfigType.WIREGUARD.name.lower():
                return int(self.settings.peers[0].endpoint.split(":")[-1])
            return None

        def get_password(self):
            if (self.protocol.lower() == EConfigType.VMESS.name.lower() or
                    self.protocol.lower() == EConfigType.VLESS.name.lower()):
                return self.settings.vnext[0].users[0].id
            elif (self.protocol.lower() == EConfigType.SHADOWSOCKS.name.lower() or
                  self.protocol.lower() == EConfigType.TROJAN.name.lower()):
                return self.settings.servers[0].password
            elif self.protocol.lower() == EConfigType.SOCKS.name.lower():
                return self.settings.servers[0].users[0].passw
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
            if (self.protocol.lower() == EConfigType.VMESS.name.lower() or
                    self.protocol.lower() == EConfigType.VLESS.name.lower() or
                    self.protocol.lower() == EConfigType.TROJAN.name.lower()):
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
        def __init__(self, servers=None, hosts=None, client_ip=None,
                     disable_cache=None, query_strategy=None, tag=None):
            self.servers = servers or []
            self.hosts = hosts or {}
            self.clientIp = client_ip
            self.disableCache = disable_cache
            self.queryStrategy = query_strategy
            self.tag = tag

        class ServersBean(BaseConfig):
            def __init__(self, address="", port=None, domains=None, expect_i_ps=None,
                         client_ip=None):
                self.address = address
                self.port = port
                self.domains = domains or []
                self.expectIPs = expect_i_ps or []
                self.clientIp = client_ip

    class RoutingBean(BaseConfig):
        def __init__(self, domain_strategy, domain_matcher=None, rules=None, balancers=None):
            self.domainStrategy = domain_strategy
            self.domainMatcher = domain_matcher
            self.rules = rules or []
            self.balancers = balancers or []

        class RulesBean(BaseConfig):
            def __init__(self, type="", ip=None, domain=None, outbound_tag="",
                         balancer_tag=None, port=None, source_port=None,
                         network=None, source=None, user=None, inbound_tag=None,
                         protocol=None, attrs=None, domain_matcher=None):
                self.type = type
                self.ip = ip or []
                self.domain = domain or []
                self.outboundTag = outbound_tag
                self.balancerTag = balancer_tag
                self.port = port
                self.sourcePort = source_port
                self.network = network
                self.source = source or []
                self.user = user or []
                self.inboundTag = inbound_tag or []
                self.protocol = protocol or []
                self.attrs = attrs
                self.domainMatcher = domain_matcher

    class PolicyBean(BaseConfig):
        def __init__(self, levels=None, system=None):
            self.levels = levels or {}
            self.system = system

        class LevelBean(BaseConfig):
            def __init__(self, handshake=None, conn_idle=None, uplink_only=None,
                         downlink_only=None, stats_user_uplink=None, stats_user_downlink=None,
                         buffer_size=None):
                self.handshake = handshake
                self.connIdle = conn_idle
                self.uplinkOnly = uplink_only
                self.downlinkOnly = downlink_only
                self.statsUserUplink = stats_user_uplink
                self.statsUserDownlink = stats_user_downlink
                self.bufferSize = buffer_size

    class FakednsBean(BaseConfig):
        def __init__(self, ip_pool="198.18.0.0/15", pool_size=10000):
            self.ipPool = ip_pool
            self.poolSize = pool_size

    def get_proxy_outbound(self):
        for outbound in self.outbounds:
            for protocol in EConfigType:
                if outbound.protocol.lower() == protocol.name.lower():
                    return outbound
        return None

    def to_pretty_printing(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
