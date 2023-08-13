import json
import logging
import re
import urllib.parse

from consts import HTTP_PROTOCOL, HTTPS_PROTOCOL
from config_type import EConfigType
from server_config import ServerConfig
from utils import Utils
from v2ray_config import DEFAULT_SECURITY, V2rayConfig, TLS


def create_config_object(uri):
    try:
        if uri is None or uri.strip() == "":
            return "nothing"

        if uri.startswith(HTTP_PROTOCOL) or uri.startswith(HTTPS_PROTOCOL):
            return "protocol nothing"

        config = None
        allow_insecure = False

        if uri.startswith(EConfigType.VMESS.value[1]):
            config: ServerConfig = ServerConfig.create(EConfigType.VMESS.value[1])
            if config.outboundBean:
                stream_setting: V2rayConfig.OutboundBean.StreamSettingsBean = config.outboundBean.streamSettings
            else:
                return "stream setting nothing"

            if not try_parse_new_vmess(uri, config, allow_insecure):
                if "?" in uri:
                    if not try_resolve_vmess_4_kitsunebi(uri, config):
                        return "incorrect protocol"
                else:
                    result = uri.replace(EConfigType.VMESS.value[1], "")
                    result = Utils.decode(result)
                    if result == "":
                        return "R.string.toast_decoding_failed"

                    vmess_qr_code = json.loads(result)
                    if (not vmess_qr_code["add"] or
                            not vmess_qr_code["port"] or
                            not vmess_qr_code["id"] or
                            not vmess_qr_code["net"]):
                        return "R.string.toast_incorrect_protocol"

                    config.remarks = vmess_qr_code["ps"]
                    vnext = config.outboundBean.settings.vnext[0]
                    vnext.address = vmess_qr_code["add"]
                    vnext.port = int(vmess_qr_code["port"])
                    vnext.users[0].id = vmess_qr_code["id"]
                    vnext.users[0].security = DEFAULT_SECURITY if not vmess_qr_code["scy"] else vmess_qr_code["scy"]
                    vnext.users[0].alterId = int(vmess_qr_code["aid"])
                    sni = stream_setting.populate_transport_settings(
                        vmess_qr_code["net"],
                        vmess_qr_code["type"],
                        vmess_qr_code["host"],
                        vmess_qr_code["path"],
                        vmess_qr_code["path"],
                        vmess_qr_code["host"],
                        vmess_qr_code["path"],
                        vmess_qr_code["type"],
                        vmess_qr_code["path"]
                    )

                    fingerprint = vmess_qr_code["fp"] if vmess_qr_code["fp"] is not None \
                        else stream_setting.tlsSettings.fingerprint if stream_setting.tlsSettings is not None else None

                    stream_setting.populate_tls_settings(
                        vmess_qr_code["tls"], allow_insecure,
                        sni if vmess_qr_code["sni"] == "" else vmess_qr_code["sni"],
                        fingerprint, vmess_qr_code["alpn"], None, None, None
                    )

        elif uri.startswith(EConfigType.SHADOWSOCKS.value[1]):
            config = ServerConfig.create(EConfigType.SHADOWSOCKS.value[1])
            if not try_resolve_sip002(uri, config):
                result = uri.replace(EConfigType.SHADOWSOCKS.value[1], "")
                index_split = result.find("#")
                if index_split > 0:
                    try:
                        config.remarks = Utils.url_decode(result[index_split + 1:])
                    except Exception as e:
                        logging.exception(e)
                    result = result[:index_split]

                index_s = result.find("@")
                if index_s > 0:
                    result = Utils.decode(result[:index_s]) + result[index_s:]
                else:
                    result = Utils.decode(result)

                legacy_pattern = r"^(.+?):(.*)@(.+?):(\d+?)/?$"
                match = re.match(legacy_pattern, result)
                if not match:
                    return "R.string.toast_incorrect_protocol"

                server = config.outboundBean.settings.servers[0]
                server.address = match.group(3).strip("[]")
                server.port = int(match.group(4))
                server.password = match.group(2)
                server.method = match.group(1).lower()
        elif uri.startswith(EConfigType.SOCKS.value[1]):
            result = uri.replace(EConfigType.SOCKS.value[1], "")
            index_split = result.find("#")
            config = ServerConfig.create(EConfigType.SOCKS.value[1])
            if index_split > 0:
                try:
                    config.remarks = Utils.url_decode(result[index_split + 1:])
                except Exception as e:
                    logging.exception(e)
                result = result[:index_split]

            index_s = result.find("@")
            if index_s > 0:
                result = Utils.decode(result[:index_s]) + result[index_s:]
            else:
                result = Utils.decode(result)

            legacy_pattern = r"^(.*):(.*)@(.+?):(\d+?)$"
            match = re.match(legacy_pattern, result)
            if not match:
                return "R.string.toast_incorrect_protocol"

            server = config.outboundBean.settings.servers[0]
            server.address = match.group(3).strip("[]")
            server.port = int(match.group(4))
            socks_users_bean = V2rayConfig.OutboundBean.OutSettingsBean.ServersBean.SocksUsersBean()
            socks_users_bean.user = match.group(1).lower()
            socks_users_bean.passw = match.group(2)
            server.users = [socks_users_bean]

        elif uri.startswith(EConfigType.TROJAN.value[1]):
            uri = urllib.parse.urlparse(uri)
            config = ServerConfig.create(EConfigType.TROJAN.value[1])
            config.remarks = Utils.url_decode(uri.fragment or "")

            flow = ""
            fingerprint = config.outboundBean.streamSettings.tlsSettings.fingerprint
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

        elif uri.startswith(EConfigType.VLESS.value[1]):
            uri = urllib.parse.urlparse(uri)
            query_param = dict(item.split("=") for item in uri.query.split("&"))
            config = ServerConfig.create(EConfigType.VLESS.value[1])
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
            return "incorrect protocol"

    except Exception as e:
        logging.exception(e)
        return -1

    return config


def try_parse_new_vmess(uri_string, config, allow_insecure):
    try:
        uri = urllib.parse.urlparse(uri_string)
        if uri.scheme != "vmess":
            return False

        match = re.match(
            r"(tcp|http|ws|kcp|quic|grpc)(\+tls)?:([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})",
            uri.username)
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
        return False


def try_resolve_vmess_4_kitsunebi(server, config):
    try:
        result = server.replace(EConfigType.VMESS.value[1], "")
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
        return False


def try_resolve_sip002(str_val, config):
    try:
        uri = urllib.parse.urlparse(str_val)
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
        logging.exception(e)
        return False
