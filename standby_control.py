#!/usr/bin/python3
# coding=utf-8

import fire
from datetime import datetime

from airin import Database
from airin import request
from airin.config import settings
from airin.config.log import logger


class Control(object):
    """
    我也不知道该怎么描述这个模块，主要用于处理中断AirinScan遗留的数据
    """

    def __init__(self):
        self.db = Database()
    
    def show(self):
        """
        枚举表名
        """
        ret = self.db.exec("select name from sqlite_master where type='table'")
        for name in ret:
            logger.log("INFOR", f"Table name: {name[0]}")
    
    def merging(self, src, dst):
        """
        表合并

        :param str src:  数据来源表名
        :param str dst:  数据接收表名
        """
        self.db.merging_table(src, dst)
    
    # def print(self, name: str):
    #     """
    #     枚举表数据

    #     :param str name:  表名
    #     """
    #     ret = self.db.exec(f"select * from {name}")
    #     for itm in ret:
    #         logger.log("INFOR", f"{itm}")
    
    def export(self, name: str, path: str = settings.result_save_dir):
        """
        将表数据导出为csv

        :param str name:  表名
        :param str path:  保存路径
        """
        self.db.export_csv(name, path)
    
    def request(self, name: str):
        """
        对目标表中存在HTTP服务且无title数据的端口发起资源请求，并更新端口数据

        :param str name:  表名
        """
        targets = self.db.get_http_service(name)
        logger.log("INFOR", f"Total number of request targets: {len(targets)}")
        resp_results = request.run_request(targets)
        conver_data = list()
        for itm in resp_results:
            conver_data.append((itm.get("title"), itm.get("status"), itm.get("ip"), itm.get("port")))
        self.db.update_HTTP_info(name, conver_data)
    
    def __exit__(self):
        self.db.close()


if __name__=='__main__':
    fire.Fire(Control)
