import logging
import tempfile
import time

import requests
from autoutils.file import write_file, FileModes
from autoutils.script import ShellScript

from apps.xray_json_generator.xray_config_util import XrayConfigUtil
from fastapi import status
from core import settings


class XrayHandler:
    def __init__(self, uri: str, port: int):
        self.uri = uri
        self.port = port
        self.pid = 0
        self.status = False
        self.response_time = None
        self._retry_count = 1
        self.error_message = None
        self.result_obj = None
        self.result_dict = None
        self.config = None
        self.request_timeout = 10

    def get_config_json(self) -> dict:
        result = XrayConfigUtil().get_xray_config(uri=self.uri, port=self.port)
        if not result.status:
            self.error_message = result.error_message
            return result.error_message
        return result.config_dict

    def run(self):
        try:
            self.config = self.get_config_json()
            self.start_xray()
            self.check()
            self.stop_xray()
            logging.info(f"{self.port} response {self.status}")
        except Exception as e:
            self.error_message = e
            return e

    def start_xray(self):
        with tempfile.NamedTemporaryFile(suffix='.json') as temp_file:
            logging.info(f"{self.port} start...")
            # write config json to config-addr
            result = write_file(temp_file.name, self.config, file_mode=FileModes.JSON)
            if not result:
                raise Exception("can not write config file")
            logging.info(f"{self.port} created config.json file")

            logging.info(f"{self.port} xray start...")
            result = ShellScript(['xray', "-c", temp_file.name],
                                 background=True, timeout=40, split_stderr=False, split_stdout=False).run()
            time.sleep(1)
            if not result.is_running:
                raise Exception(f"{self.port} can not start xray, {result.stderr} / {result.stdout}")
            logging.info(f"{self.port} xray started")
            self.pid = result.process_id
            logging.info(f"{self.port} process id {result.process_id}")

    @property
    def request_proxy(self):
        return {"http": f"socks5://127.0.0.1:{self.port}",
                "https": f"socks5://127.0.0.1:{self.port}"}

    def check(self):
        logging.info(f"{self.port} send get request from {settings.GET_ADDRESS} with timeout {self.request_timeout}")
        error_message = ""
        for i in range(self._retry_count):
            try:
                response = requests.get(settings.GET_ADDRESS,
                                        proxies=self.request_proxy,
                                        timeout=self.request_timeout)
                self.status = response.status_code == status.HTTP_200_OK
                if not self.status:
                    continue
                self.response_time = int(response.elapsed.total_seconds() * 1000)
                logging.info(f"{self.port} connect with status code {response.status_code}")
            except Exception as e:
                error_message = str(e)
                continue
        if not self.status:
            logging.error(f"{self.port} can not connect to server, e: {error_message}")
            self.status = False

        return self.status

    def stop_xray(self):
        if self.pid is None:
            return
        result = ShellScript(f"kill {self.pid}", shell=True, split_stderr=False, split_stdout=False).run()
        try:
            if result.exit_code == 0:
                logging.info(f"{self.port} pid {self.pid} killed")
            else:
                logging.warning(f"{self.port} {result.stderr} / {result.stdout}")
        except Exception as e:
            logging.exception(f"{self.port}: error in stop_xray. e: {e}")
            return False

        return True
