import logging
import re
import urllib.parse

from apps.xray_json_generator.consts import *
from apps.xray_json_generator.server_config import *
from apps.xray_json_generator.utils import Utils
from apps.xray_json_generator.xray_config import *


class ConfigGenerator:

    def __init__(self, uri):
        self.uri = uri
        self.config = {}

    def create_config_object(self) -> bool:
        try:
            if self.uri is None or self.uri.strip() == "":
                logging.info("uri is empty.")
                return False

            if self.uri.startswith(HTTP_PROTOCOL) or self.uri.startswith(HTTPS_PROTOCOL):
                logging.info("uri is http or https protocol.")
                return False

            config = None
            allow_insecure = False

            if self.uri.startswith(EConfigType.VMESS.value[1]):
                config: ServerConfig = ServerConfig.create(EConfigType.VMESS)
                if config.outboundBean:
                    stream_setting: XrayConfig.OutboundBean.StreamSettingsBean = config.outboundBean.streamSettings
                else:
                    logging.info("stream setting nothing")
                    return False

                if not self.try_parse_new_vmess(config, allow_insecure):
                    if "?" in self.uri:
                        if not self.try_resolve_vmess_4_kitsunebi(config):
                            logging.info("incorrect protocol")
                            return False
                    else:
                        result = self.uri.replace(EConfigType.VMESS.value[1], "")
                        result = Utils.decode(result)
                        if result == "":
                            logging.info("decoding failed.")
                            return False

                        vmess_qr_code = json.loads(result)
                        if (not vmess_qr_code.get("add") or
                                not vmess_qr_code.get("port") or
                                not vmess_qr_code.get("id") or
                                not vmess_qr_code.get("net")):
                            logging.info("incorrect protocol.")
                            return False

                        config.remarks = vmess_qr_code.get("ps")
                        vnext = config.outboundBean.settings.vnext[0]
                        vnext.address = vmess_qr_code.get("add")
                        vnext.port = int(vmess_qr_code.get("port"))
                        vnext.users[0].id = vmess_qr_code.get("id")
                        vnext.users[0].security = DEFAULT_SECURITY if vmess_qr_code.get("scy") is None \
                            else vmess_qr_code.get("scy")
                        vnext.users[0].alterId = int(vmess_qr_code.get("aid"))
                        sni = stream_setting.populate_transport_settings(
                            vmess_qr_code.get("net"),
                            vmess_qr_code.get("type"),
                            vmess_qr_code.get("host"),
                            vmess_qr_code.get("path"),
                            vmess_qr_code.get("path"),
                            vmess_qr_code.get("host"),
                            vmess_qr_code.get("path"),
                            vmess_qr_code.get("type"),
                            vmess_qr_code.get("path")
                        )

                        fingerprint = vmess_qr_code.get("fp") if vmess_qr_code.get("fp") is not None \
                            else stream_setting.tlsSettings.fingerprint if stream_setting.tlsSettings is not None \
                            else None

                        stream_setting.populate_tls_settings(
                            vmess_qr_code.get("tls"), allow_insecure,
                            sni if vmess_qr_code.get("sni") is None else vmess_qr_code.get("sni"),
                            fingerprint, vmess_qr_code.get("alpn"), None, None, None
                        )

            elif self.uri.startswith(EConfigType.SHADOWSOCKS.value[1]):
                config: ServerConfig = ServerConfig.create(EConfigType.SHADOWSOCKS)
                if not self.try_resolve_sip002(config):
                    result = self.uri.replace(EConfigType.SHADOWSOCKS.value[1], "")
                    index_split = result.find("#")
                    if index_split > 0:
                        try:
                            config.remarks = Utils.url_decode(result[index_split + 1:])
                        except Exception as e:
                            logging.error(e)
                            # logging.exception(e)
                        result = result[:index_split]

                    index_s = result.find("@")
                    if index_s > 0:
                        result = Utils.decode(result[:index_s]) + result[index_s:]
                    else:
                        result = Utils.decode(result)

                    legacy_pattern = r"^(.+?):(.*)@(.+?):(\d+?)/?$"
                    match = re.match(legacy_pattern, result)
                    if not match:
                        logging.info("incorrect protocol.")
                        return False

                    server = config.outboundBean.settings.servers[0]
                    server.address = match.group(3).strip("[]")
                    server.port = int(match.group(4))
                    server.password = match.group(2)
                    server.method = match.group(1).lower()

            elif self.uri.startswith(EConfigType.SOCKS.value[1]):
                result = self.uri.replace(EConfigType.SOCKS.value[1], "")
                index_split = result.find("#")
                config: ServerConfig = ServerConfig.create(EConfigType.SOCKS)
                if index_split > 0:
                    try:
                        config.remarks = Utils.url_decode(result[index_split + 1:])
                    except Exception as e:
                        logging.error(e)
                        # logging.exception(e)
                    result = result[:index_split]

                index_s = result.find("@")
                if index_s > 0:
                    result = Utils.decode(result[:index_s]) + result[index_s:]
                else:
                    result = Utils.decode(result)

                legacy_pattern = r"^(.*):(.*)@(.+?):(\d+?)$"
                match = re.match(legacy_pattern, result)
                if not match:
                    logging.info("incorrect protocol.")
                    return False

                server = config.outboundBean.settings.servers[0]
                server.address = match.group(3).strip("[]")
                server.port = int(match.group(4))
                socks_users_bean = XrayConfig.OutboundBean.OutSettingsBean.ServersBean.SocksUsersBean()
                socks_users_bean.user = match.group(1).lower()
                socks_users_bean.passw = match.group(2)
                server.users = [socks_users_bean]

            elif self.uri.startswith(EConfigType.TROJAN.value[1]):
                uri = urllib.parse.urlparse(self.uri)
                config: ServerConfig = ServerConfig.create(EConfigType.TROJAN)
                config.remarks = Utils.url_decode(uri.fragment or "")

                flow = ""
                if uri.query:
                    query_param = dict(item.split("=") for item in uri.query.split("&"))
                    sni = config.outboundBean.streamSettings.populate_transport_settings(
                        query_param.get("type", "tcp"),
                        query_param.get("headerType"),
                        query_param.get("host"),
                        query_param.get("path"),
                        query_param.get("seed"),
                        query_param.get("quicSecurity"),
                        query_param.get("key"),
                        query_param.get("mode"),
                        query_param.get("serviceName")
                    )
                    fingerprint = query_param.get("fp", "")
                    config.outboundBean.streamSettings.populate_tls_settings(
                        query_param.get("security", TLS),
                        allow_insecure,
                        query_param.get("sni", sni),
                        fingerprint,
                        query_param.get("alpn"),
                        None,
                        None,
                        None
                    )
                    flow = query_param.get("flow", "")
                else:
                    fingerprint = config.outboundBean.streamSettings.tlsSettings.fingerprint
                    config.outboundBean.streamSettings.populate_tls_settings(
                        TLS,
                        allow_insecure,
                        "",
                        fingerprint,
                        None,
                        None,
                        None,
                        None
                    )

                server = config.outboundBean.settings.servers[0]
                server.address = uri.hostname
                server.port = uri.port
                server.password = uri.username
                server.flow = flow

            elif self.uri.startswith(EConfigType.VLESS.value[1]):
                uri = urllib.parse.urlparse(self.uri)
                query_param = dict(item.split("=") for item in uri.query.split("&"))
                config: ServerConfig = ServerConfig.create(EConfigType.VLESS)
                stream_setting = config.outboundBean.streamSettings
                # fingerprint = stream_setting.tlsSettings.fingerprint

                config.remarks = Utils.url_decode(uri.fragment or "")
                vnext = config.outboundBean.settings.vnext[0]
                vnext.address = uri.hostname
                vnext.port = uri.port
                vnext.users[0].id = uri.username
                vnext.users[0].encryption = query_param.get("encryption", "none")
                vnext.users[0].flow = query_param.get("flow", "")

                sni = stream_setting.populate_transport_settings(
                    query_param.get("type", "tcp"),
                    query_param.get("headerType"),
                    query_param.get("host"),
                    query_param.get("path"),
                    query_param.get("seed"),
                    query_param.get("quicSecurity"),
                    query_param.get("key"),
                    query_param.get("mode"),
                    query_param.get("serviceName")
                )
                fingerprint = query_param.get("fp", "")
                pbk = query_param.get("pbk", "")
                sid = query_param.get("sid", "")
                spx = Utils.url_decode(query_param.get("spx", ""))
                stream_setting.populate_tls_settings(
                    query_param.get("security", ""),
                    allow_insecure,
                    query_param.get("sni", sni),
                    fingerprint,
                    query_param.get("alpn"),
                    pbk,
                    sid,
                    spx
                )

            if config is None:
                return False
        except Exception as e:
            logging.exception(f"error in create config object. e: {e}")
            return False

        self.config = config
        return True

    def try_parse_new_vmess(self, config: ServerConfig, allow_insecure: bool):
        try:
            uri = urllib.parse.urlparse(self.uri)
            if uri.scheme != "vmess":
                return False
            match = re.match(
                r"(tcp|http|ws|kcp|quic|grpc)(\+tls)?:([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})",
                str(uri.username))
            if not match:
                return False

            protocol, tls_str, uuid, alter_id = match.groups()
            tls = tls_str.strip() != ""

            query_param = dict(item.split("=") for item in uri.query.split("&"))

            stream_setting = config.outboundBean.streamSettings
            config.remarks = Utils.url_decode(uri.fragment or "")
            vnext = config.outboundBean.settings.vnext[0]
            vnext.address = uri.hostname
            vnext.port = uri.port
            vnext.users[0].id = uuid
            vnext.users[0].security = DEFAULT_SECURITY
            vnext.users[0].alterId = int(alter_id)

            fingerprint = stream_setting.tlsSettings.fingerprint
            sni = stream_setting.populate_transport_settings(
                protocol,
                query_param.get("type"),
                query_param.get("host", "").split("|")[0],
                query_param.get("path", "") if query_param.get("path", "").strip() != "/" else "",
                query_param.get("seed"),
                query_param.get("security"),
                query_param.get("key"),
                query_param.get("mode"),
                query_param.get("serviceName")
            )
            stream_setting.populate_tls_settings(
                TLS if tls else "", allow_insecure, sni, fingerprint, None, None, None, None
            )
            return True

        except Exception as e:
            logging.error(e)
            logging.exception(e)
            return False

    def try_resolve_vmess_4_kitsunebi(self, config):
        try:
            result = self.uri.replace(EConfigType.VMESS.value[1], "")
            index_split = result.find("?")
            if index_split > 0:
                result = result[:index_split]
            result = Utils.decode(result)

            arr1 = result.split('@')
            if len(arr1) != 2:
                return False
            arr21 = arr1[0].split(':')
            arr22 = arr1[1].split(':')
            if len(arr21) != 2:
                return False

            config.remarks = "Alien"
            vnext = config.outboundBean.settings.vnext[0]
            vnext.address = arr22[0]
            vnext.port = int(arr22[1])
            vnext.users[0].id = arr21[1]
            vnext.users[0].security = arr21[0]
            vnext.users[0].alterId = 0
            return True

        except Exception as e:
            logging.error(e)
            # logging.exception(e)
            return False

    def try_resolve_sip002(self, config):
        try:
            uri = urllib.parse.urlparse(self.uri)
            config.remarks = Utils.url_decode(uri.fragment or "")

            if ":" in uri.username:
                arr_user_info = uri.username.split(":")
                if len(arr_user_info) != 2:
                    return False
                method = arr_user_info[0].strip()
                password = Utils.url_decode(arr_user_info[1].strip())
            else:
                base64_decode = Utils.decode(uri.username)
                arr_user_info = base64_decode.split(":")
                if len(arr_user_info) < 2:
                    return False
                method = arr_user_info[0].strip()
                password = base64_decode.split(":", 1)[1]

            server = config.outboundBean.settings.servers[0]
            server.address = uri.hostname
            server.port = uri.port
            server.password = password
            server.method = method
            return True

        except Exception as e:
            logging.error(e)
            # logging.exception(e)
            return False
