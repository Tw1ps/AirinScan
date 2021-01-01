#!/usr/bin/python3
# coding=utf-8

import fire
from datetime import datetime

from airin import analysis
from airin import netscan
from airin import Database
from airin import request
from airin import export
from airin.config import settings
from airin.config.log import logger


red = '\033[1;31m'
yellow = '\033[01;33m'
blue = '\033[01;34m'
end = '\033[0m'

airinscan_banner = f"""{red}
 _____ _     _     _____             
|  _  |_|___|_|___|   __|___ ___ ___ {yellow}
|     | |  _| |   |__   |  _| .'|   |{blue}
|__|__|_|_| |_|_|_|_____|___|__,|_|_|{end}

"""


class AirinScan(object):
    """
    AirinScan help summary page

    AirinScan is a network scan tool

    Example:
        python3 airinscan.py 192.168.0.1 - run
        python3 airinscan.py 192.168.0.0/24 - run
        python3 airinscan.py 172.16.1.2 192.168.0.0/24 - run
        python3 airinscan.py 192.168.0.1 ./list.txt - run
        python3 airinscan.py ./result.csv --filtr False - run
        python3 airinscan.py ./result.json --req False - run
        python3 airinscan.py ./result.csv --fmt json - run
        python3 airinscan.py ./result.json --path False - run
        python3 airinscan.py ./result.txt --cutmask False - run

    Note:
        " - run" is a fixed format
        --fmt   csv/json (result format)
        --path  Result path (default None, automatically generated)

    :param tuple    targets  :   One or more IP/CIDR or File path of .txt/.csv/.json
    :param bool     filtr    :   Filter scan target (default True)
    :param bool     req      :   HTTP requests page title (defalut True)
    :param str      fmt      :   Result format (default csv)
    :param str      path     :   Result path (default None, automatically generated)
    :param bool     cutmask  :   CIDR where the segmentation mask is greater than the set value (default True)
    """

    def __init__(self, *targets: tuple, filtr: bool = None, req: bool = None, fmt: str = None, path: str = None, cutmask: bool = None, analysis_only: bool = None):
        self.targets = targets
        self.filtr = filtr
        self.req = req
        self.fmt = fmt
        self.path = path
        self.cutmask = cutmask
        self.analysis_only = analysis_only
        self.datas = list()
        self._dict_list = list()
        self._str_list = list()
        self.reduce_datas = dict()
        self._scan_targets = list()
        self._alive_list = list()
        self._port_dict = dict()
        self.http_service_list = list()

    def config_param(self):
        """
        Config parameter
        """
        if self.filtr is None:
            self.filtr = bool(settings.analysis.enable_scan_filter)
        if self.req is None:
            self.req = bool(settings.request.enable_req)
        if self.path is None:
            self.path = settings.result_save_dir
        if self.fmt is None:
            self.fmt = settings.export.result_save_format
        if self.cutmask is None:
            self.cutmask = bool(settings.analysis.enable_cut_cidr)
        if self.analysis_only is None:
            self.analysis_only = False

    def check_param(self):
        """
        Check parameter
        """
        if len(self.targets) == 0:
            logger.log('FATAL', 'You least provide one targets parameter')
            exit(1)

    def load_data(self):
        """
        Load file data
        """
        logger.log("DEBUG", f"Targets arguments: {self.targets}")
        for target in self.targets:
            if target.endswith(".csv"):
                self._dict_list += analysis.load_csv(target)
            elif target.endswith(".json"):
                self._dict_list += analysis.load_json(target)
            elif target.endswith(".txt"):
                self._str_list += analysis.load_txt(target)
            elif analysis.check_ip_fmt(target):
                self._str_list.append(target)
            else:
                logger.log("ALERT", f"Bad arguments: {target}")
        self._str_list = list(set(self._str_list))

    def main(self):
        """
        Main function
        """
        if len(self._str_list) > 0:
            self.reduce_datas.update(analysis.data_reduction(self._str_list))
        if len(self._dict_list) > 0:
            self.reduce_datas.update(analysis.data_reduction(self._dict_list))

        if self.analysis_only is False:
            logger.log("INFOR", "Create scan targets")

            if self.filtr:
                self._scan_targets = analysis.filtr_cidr_targets(self.reduce_datas)
            else:
                self._scan_targets = [i for i in self.reduce_datas]
            self._scan_targets.sort()

            if self.cutmask:
                self._scan_targets = analysis.cut_mask(self._scan_targets, self.reduce_datas)
            logger.log("DEBUG", f"Targets: {self._scan_targets}")

            self._alive_list = netscan.AliveScan(self._scan_targets)
            self._alive_list.sort()

            if len(self._alive_list) > 0:
                self.reduce_datas, _ = analysis.data_integration(self.reduce_datas, self._alive_list)
                targets_files = analysis.create_targets_file(self._alive_list)
                len_targets_files = len(targets_files)

                db = Database()
                db.clean()

                temp_table_name = settings.database.temp_table_name
                for target in targets_files:
                    logger.log("INFOR", f"The last {len_targets_files} files")
                    len_targets_files -= 1
                    self._port_dict = netscan.PortScan([str(target)])
                    self.reduce_datas, conver_data = analysis.data_integration(self.reduce_datas, self._port_dict)
                    logger.log("INFOR", "Save the data to the database")
                    db.insert_table(temp_table_name, conver_data)

                if self.req:
                    self.http_service_list = db.get_http_service(temp_table_name)
                    logger.log("INFOR", f"Total number of request targets: {len(self.http_service_list)}")
                    resp_results = request.run_request(self.http_service_list)
                    self.reduce_datas, conver_data = analysis.http_resp_integration(self.reduce_datas, resp_results)
                    db.update_HTTP_info(temp_table_name, conver_data)

                db.merging_table(temp_table_name, settings.database.table_name)
                db.close()
            else:
                logger.log("ALERT", "No alive host")

        self.datas = analysis.data_conversion(self.reduce_datas)
        logger.log("TRACE", self.datas)
        export.entrance(self.datas, self.path, self.fmt)

    def run(self):
        """
        AirinScan running entrance
        """
        print(airinscan_banner)
        dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f'[*] Starting AirinScan @ {dt}\n')
        logger.log('INFOR', 'Start running AirinScan')

        self.config_param()
        self.check_param()
        self.load_data()
        self.main()

        logger.log('INFOR', 'Finished AirinScan')


if __name__ == '__main__':
    fire.Fire(AirinScan)
