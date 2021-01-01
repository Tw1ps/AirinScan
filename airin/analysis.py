import csv
import json
import time
import copy
import pathlib
import random

from re import match
from IPy import IP

from airin.config import settings
from airin.config.log import logger


def _data_sort(data: dict, reverse: bool = True) -> dict:
    """
    数据排序，将数据按照ip数量排序，用于排序经_distribution处理过的数据

    :param dict data    :  经_distribution处理过的数据
    :param bool reverse :  顺序或倒序
    :return : 经排序的数据
    :rtype  : dict
    """
    try:
        sort_data = sorted(
            data.items(), key=lambda x: len(x[1]), reverse=reverse)
        return dict(sort_data)
    except Exception as identifier:
        logger.log("ERROR", repr(identifier))
    return data


def _distribution(ip_dict: dict, cidr_dict: dict) -> dict:
    results = cidr_dict
    for ip in ip_dict:
        no_cidr = True
        for cidr in cidr_dict:
            if ip in IP(cidr):
                results[cidr][ip] = {"domain": ",".join(ip_dict.get(ip))}
                no_cidr = False
                break
        if no_cidr:
            tmp = ip.split(".")
            tmp[-1] = "0"
            tmp = f'{".".join(tmp)}/24'
            results[tmp] = dict()
            results[tmp][ip] = {"domain": ",".join(ip_dict.get(ip))}

    return _data_sort(results)


def _analysis_str_list(data: list) -> (dict, dict):
    """
    数据分析，将原始数据分配到各个相应的list或dict

    :param list data :  由str组成的list
    :return : 经提取的数据
    :rtype  : (list, dict)
    """
    data = list(set(data))
    ip_dict = dict()
    cidr_dict = dict()
    for itm in data:
        if match("^\d+\.\d+\.\d+\.\d+/\d+$", itm):  # 匹配CIDR
            cidr_dict[itm] = dict()
        elif match("^\d+\.\d+\.\d+\.\d+$", itm):  # 匹配IPv4
            ip_dict[itm] = dict()
        else:
            logger.log("TRACE", f"Bad list item: {itm}")

    try:
        ip_dict.pop("")
    except:
        pass
    try:
        cidr_dict.pop("")
    except:
        pass

    logger.log("TRACE", f"IP dict: {ip_dict}")
    logger.log("TRACE", f"CIDR dict: {cidr_dict}")
    return ip_dict, cidr_dict


def _analysis_dict_list(data: list) -> (dict, dict):
    """
    数据分析，将原始数据分配到各个相应的list或dict

    :param list data:  由dict组成的list
    :return : 经提取的数据
    :rtype  : (dict, dict)
    """
    ip_dict = dict()
    cidr_dict = dict()
    if settings.analysis.ip_field is None:
        logger.log("ERROR", "IP field is not set in settings!")
        return ip_dict, cidr_dict
    for itm in data:
        if settings.analysis.cidr_field:  # 判断是否存在cidr字段设置
            for cidr in itm.get(settings.analysis.cidr_field).split(","):
                cidr_dict[cidr] = dict()
        for ip in itm.get(settings.analysis.ip_field).split(","):
            if settings.analysis.domain_field:
                if ip_dict.get(ip) is None:
                    ip_dict[ip] = dict()
                if itm.get(settings.analysis.domain_field):
                    ip_dict[ip][itm.get(settings.analysis.domain_field)] = None
            else:
                ip_dict[ip] = dict()

    try:
        ip_dict.pop("")
    except:
        pass
    try:
        cidr_dict.pop("")
    except:
        pass

    logger.log("TRACE", f"IP dict: {ip_dict}")
    logger.log("TRACE", f"CIDR dict: {cidr_dict}")
    return ip_dict, cidr_dict


def _data_statistics(data: dict) -> None:
    ipcount = 0
    for itm in data:
        logger.log(
            "INFOR", f"CIDR: {itm}  \tIP count: {len(data.get(itm))}")
        ipcount += len(data.get(itm))

    logger.log("ALERT", f"CIDR total: {len(data)} \tIP total: {ipcount}")
    logger.log("TRACE", f"Data: {data}")


def data_reduction(data: list) -> dict:
    """
    数据整理，将原始数据转换成{CIDR: {IP: {}}}这种格式

    :param list data : 由dict或str组成的list
    :return : 经转换的数据
    :rtype  : dict
    """
    results = dict()
    ip_dict = dict()
    cidr_dict = dict()
    logger.log("INFOR", "Data reduction start")
    if type(data[0]) is str:  # 假定整个list都由str组成
        ip_dict, cidr_dict = _analysis_str_list(data)
        results = _distribution(ip_dict, cidr_dict)
    elif type(data[0]) is dict:  # 假定整个list都由dict组成
        ip_dict, cidr_dict = _analysis_dict_list(data)
        results = _distribution(ip_dict, cidr_dict)
    else:
        logger.log("ALERT", "Bad list")
    _data_statistics(results)
    logger.log("INFOR", "Data reduction finish")

    return results


def cut_mask(targets: list, data: dict, minmask: int = settings.analysis.min_mask) -> list:
    """
    将提交的CIDR划分为如许多个24位子网掩码的CIDR

    :param list targets :  CIDR字符串组成的list
    :param dict data    :  经data_reduction整理的数据
    :param int minmask  :  设置子网掩码最小值
    :return : 由CIDR组成的list
    :rtype  : list
    """
    list_len = len(targets) -1
    while list_len >= 0:
        if int(targets[list_len].split("/")[-1]) < minmask:
            cidr = targets[list_len]
            targets.remove(cidr)
            cidr_tmp = list()
            ip_list = IP(cidr)
            ip_list_len = len(ip_list) - 256
            while ip_list_len >= 0:
                cidr_tmp.append(f"{ip_list[ip_list_len]}/24")
                ip_list_len -= 256
            for ip in data.get(cidr):
                for tmp in cidr_tmp:
                    if ip in IP(tmp):
                        targets.append(tmp)
                        break
        list_len -= 1

    return list(set(targets))


def _integration_list(srcdata: dict, newdata: list) -> dict:
    for itm in srcdata:
        newdata_len = len(newdata) -1
        while newdata_len >= 0:
            if srcdata[itm].get(newdata[newdata_len]):
                newdata.remove(newdata[newdata_len])
            elif newdata[newdata_len] in IP(itm):
                srcdata[itm][newdata[newdata_len]] = dict()
                newdata.remove(newdata[newdata_len])
            newdata_len -= 1
    
    return srcdata, None


def _integration_dict(srcdata: dict, newdata: dict) -> dict:
    conver = list()
    for cidr in srcdata:
        cidr_list = IP(cidr)
        for ip in newdata:
            if ip in cidr_list:
                srcdata[cidr][ip].update(newdata.get(ip))
                for port in newdata[ip].get("ports"):
                    port_info = newdata[ip]["ports"].get(port)
                    conver.append((
                        cidr, 
                        ip, 
                        srcdata[cidr][ip].get("domain"), 
                        port,
                        port_info.get("state"),
                        port_info.get("reason"),
                        port_info.get("name"),
                        port_info.get("product"),
                        port_info.get("version"),
                        port_info.get("extrainfo"),
                        port_info.get("conf"),
                        port_info.get("cpe"),
                        port_info.get("title"),
                        port_info.get("status")
                    ))

    return srcdata, conver
                    

def data_integration(srcdata: dict, newdata: list or dict) -> (dict, list):
    """
    将netscan模块扫描产生的数据整合进旧数据

    :param dict srcdata :  经data_reduction整理的数据
    :param list or dict newdata :  扫描生成的新数据
    :return : 经整理的数据
    :rtype  : (dict, list)
    """
    results = dict()
    data = copy.deepcopy(newdata)
    logger.log("INFOR", "Data integration start")
    logger.log("TRACE", f"New data: {newdata}")
    if type(data) is list:
        data, conver = _integration_list(srcdata, data)
        results.update(data)
        _data_statistics(results)
    elif type(data) is dict:
        data, conver = _integration_dict(srcdata, data)
        results.update(data)
    else:
        logger.log("ERROR", "Bad data")
    logger.log("INFOR", "Data integration finish")
    logger.log("TRACE", f"Integration data: {results}")
    logger.log("TRACE", f"Conversion data: {conver}")
    
    return results, conver


def data_conversion(data: dict) -> list:
    results = list()
    for cidr in data:
        for ip in data[cidr]:
            if data[cidr][ip].get("ports"):
                for port in data[cidr][ip].get("ports"):
                    port_info = data[cidr][ip]["ports"].get(port)
                    results.append({
                        "cidr": cidr, 
                        "ip": ip, 
                        "domain": data[cidr][ip].get("domain"), 
                        "port": port, 
                        "state": port_info.get("state"), 
                        "reason": port_info.get("reason"),
                        "name": port_info.get("name"),
                        "product": port_info.get("product"),
                        "version": port_info.get("version"),
                        "extrainfo": port_info.get("extrainfo"),
                        "conf": port_info.get("conf"),
                        "cpe": port_info.get("cpe"),
                        "title": port_info.get("title"),
                        "status": port_info.get("status")
                    })
            else:
                results.append({
                    "cidr": cidr, 
                    "ip": ip, 
                    "domain": data[cidr][ip].get("domain"), 
                    "port": None, 
                    "state": None, 
                    "reason": None,
                    "name": None,
                    "product": None,
                    "version": None,
                    "extrainfo": None,
                    "conf": None,
                    "cpe": None,
                    "title": None,
                    "status": None
                    })
    
    return results


def http_resp_integration(srcdata: dict, resp_results: list) -> (dict, list):
    results = list()
    for itm in resp_results:
        cidr = itm.get("cidr")
        ip = itm.get("ip")
        port = itm.get("port")
        title = itm.get("title")
        status = itm.get("status")

        srcdata[cidr][ip]["ports"][port]["title"] = title
        srcdata[cidr][ip]["ports"][port]["status"] = status

        results.append((title, status, ip, port))
    
    return srcdata, results


def filtr_cidr_targets(data: dict, top: int = settings.analysis.scan_top, mincount: int = settings.analysis.scan_minipcount) -> list:
    """
    根据设置的参数筛选扫描目标

    :param dict data :  经data_reduction整理的数据
    :param int top   :  筛选data的前top项
    :param int mincount :  筛选IP数量大于mincount的项
    :return : 由CIDR组成的list
    :rtype  : list
    """
    logger.log("DEBUG", f"Targets Filter: top {top}, IP count >= {mincount}")
    targets = list()
    for itm in data:
        if len(data[itm]) >= mincount:
            targets.append(itm)
        top -= 1
        if top <= 0:
            break
    
    logger.log("TRACE", f"Targets: {targets}")
    return targets


def _data_filtr(data: list) -> list:
    """
    初步筛选数据，主要用于筛选load_csv和load_json产生的数据

    :param list data :  由dict组成的list
    :return : 经过滤的数据，结构不变
    :rtype  : list
    """
    results = list()
    try:
        for itm in data:
            if eval(settings.analysis.dict_filtr_arguments):
                results.append(itm)
    except Exception as identifier:
        logger.log("ERROR", repr(identifier))

    return results


def _filtr_cdn(data: list) -> list:
    cdn_cidr_list = settings.analysis.cdn_ip_cidr
    
    for cdn_cidr in cdn_cidr_list:
        data_len = len(data) -1
        cdn_ip_list = IP(cdn_cidr)
        while data_len >= 0:
            if type(data[0]) is dict:  # 假定整个list都由str组成
                for ip in data[data_len].get(settings.analysis.ip_field).split(","):
                    if ip in cdn_ip_list:
                        data.remove(data[data_len])
                        break
            elif type(data[0]) is dict:  # 假定整个list都由dict组成
                if data[data_len] in cdn_ip_list:
                    data.remove(data[data_len])
            data_len -= 1
    
    return data

def load_txt(filepath: str, encode: str = "utf-8") -> list:
    """
    读取txt文件内容并转为list

    :param str filepath :  .txt filepath
    :return : txt to list data
    :rtype  : list
    """
    logger.log("TRACE", f"Read file: {filepath}")
    data = list()
    try:
        with open(filepath, 'r', encoding=encode) as txt_file:
            tmp = txt_file.read()
            data = tmp.split("\n")
        data = list(set(data))  # 去除重复数据
        if len(data):
            data = _filtr_cdn(data)
        logger.log("TRACE", f"Data: {data}")
    except Exception as identifier:
        logger.log("ALERT", identifier)
        if encode != "GBK":
            logger.log("TRACE", "Try GBK encode")
            data = load_txt(filepath, "GBK")

    return data


def create_targets_file(targets: list) -> list:
    targets.sort()
    files_list = list()
    list_len = len(targets) -1
    try:
        while list_len >= 0:
            filename = f'{time.strftime("%Y%m%d%H%M%S", time.localtime())}{random.randint(0,9999)}.txt'
            filepath = settings.temp_save_dir.joinpath(filename)
            f = open(filepath, 'a+')
            for i in range(256):
                f.write(f"{targets[list_len]}\n")
                list_len -= 1
                if list_len < 0:
                    break
            f.close()
            files_list.append(filepath)
    except Exception as identifier:
        logger.log("ERROR", identifier)
    logger.log("TRACE", f"Files: {files_list}")

    return files_list

def load_csv(filepath: str, encode: str = "utf-8") -> list:
    """
    将csv文件转成由dict组成的list

    :param str filepath :  .csv filepath
    :return : csv to json data
    :rtype  : list
    """
    logger.log("TRACE", f"Read file: {filepath}")
    data = list()
    try:
        with open(filepath, mode='r', encoding=encode) as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                data.append(row)
        if settings.analysis.enable_dict_filtr:
            data = _data_filtr(data)
        if len(data):
            data = _filtr_cdn(data)
        logger.log("TRACE", f"Data: {data}")
    except Exception as identifier:
        logger.log("ALERT", identifier)
        if encode != "GBK":
            logger.log("TRACE", "Try GBK encode")
            data = load_csv(filepath, "GBK")

    return data


def load_json(filepath: str, encode: str = "utf-8") -> list:
    """
    将json文件转成由dict组成的list

    :param str filepath :  .json filepath
    :return : file to json data
    :rtype  : list
    """
    logger.log("TRACE", f"Read file: {filepath}")
    data = list()
    try:
        with open(filepath, 'r', encoding=encode) as json_file:
            data = json.load(json_file)
        if settings.analysis.enable_dict_filtr:
            data = _data_filtr(data)
        if len(data):
            data = _filtr_cdn(data)
        logger.log("TRACE", f"Data: {data}")
    except Exception as identifier:
        logger.log("ALERT", identifier)
        if encode != "GBK":
            logger.log("TRACE", "Try GBK encode")
            data = load_json(filepath, "GBK")

    return data


def check_ip_fmt(target: str) -> bool:
    """
    判断target是否为CIDR或IPv4

    :param str target :  string
    :rtype  : bool
    """
    result = False
    if match("^\d+\.\d+\.\d+\.\d+/\d+$", target) or match("^\d+\.\d+\.\d+\.\d+$", target):
        result = True
    
    return result
