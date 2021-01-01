import json

from pathlib import Path

from . import setting
from .log import logger


class Settings(object):

    def _load_cdn_ip_cidr(self, encode: str = "utf-8") -> list:
        """
        读取json文件内容并转为list

        :return : list data
        :rtype  : list
        """
        filepath = self.analysis.cdn_ip_cidr_file
        logger.log("TRACE", f"Read file: {filepath}")
        self.analysis.cdn_ip_cidr = list()
        try:
            with open(filepath, 'r', encoding=encode) as cdn_file:
                self.analysis.cdn_ip_cidr = json.load(cdn_file)
            logger.log("TRACE", f"CDN data: {self.analysis.cdn_ip_cidr}")
        except Exception as identifier:
            logger.log("ERROR", identifier)
            if encode != "GBK":
                logger.log("TRACE", "Try GBK encode")
                self.load_cdn_ip_cidr("GBK")

    def _check_netscan_proxies(self):
        """
        检查是否开启代理，是则拼接代理语句
        """
        if self.netscan.enable_proxies:
            self.netscan.arguments_alive = f"--proxies {self.netscan.proxies_list} {self.netscan.arguments_alive} "
            self.netscan.arguments_port = f"--proxies {self.netscan.proxies_list} {self.netscan.arguments_port} "
            logger.log("DEBUG", f"Proxies arguments: --proxies {self.netscan.proxies_list}")

    def _netscan_join_ports(self):
        """
        检查是否使用自定义的端口列表
        """
        if self.netscan.enable_custom_ports:
            self.netscan.arguments_port = f"-p{','.join([str(port) for port in self.netscan.ports])} {self.netscan.arguments_port} "
            logger.log("DEBUG", f"Port arguments: {self.netscan.arguments_port}")

    def _analysis_join_arguments(self):
        """
        拼接_filtr函数的筛选参数
        """
        if self.analysis.enable_dict_filtr:
            self.analysis.dict_filtr_arguments = " and ".join([str(f"itm.get(\"{itm.get('field')}\") {itm.get('operator')} \"{itm.get('value')}\"") for itm in self.analysis.dict_filtr_arguments])
            logger.log("DEBUG", f"Data filter: {self.analysis.dict_filtr_arguments}")
        else:
            self.analysis.dict_filtr_arguments = "True"
    
    def _check_path(self):
        Path(self.result_save_dir).mkdir(exist_ok=True)
        Path(self.temp_save_dir).mkdir(exist_ok=True)

    def __init__(self):
        # 获取全局变量中的配置信息
        for attr in dir(setting):
            setattr(self, attr, getattr(setting, attr))
        
        self._check_netscan_proxies()
        self._netscan_join_ports()
        self._analysis_join_arguments()
        self._check_path()
        self._load_cdn_ip_cidr()


settings = Settings()
