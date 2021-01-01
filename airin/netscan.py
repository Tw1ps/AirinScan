import nmap
from re import match

from airin.config import settings
from airin.config.log import logger


"""
netscan负责网络扫描及数据提取
"""


def _NmapStart(target: str, stype: str = "alive") -> dict:
    """
    网络扫描核心函数，直接返回原始数据

    :param str target :  IP/CIDR/FilePath
    :param str stype  :  扫描类型，"alive"/"port"可选，默认"alive"
    :return : nmap scan result
    :rtype  : dict
    """
    nm = nmap.PortScanner()
    arguments = eval(f"settings.netscan.arguments_{stype}")
    arguments += " "  # 加上一个空格隔断后续参数
    if match("\d+\.\d+\.\d+\.\d+", str(target)):  # 匹配IP或CIDR
        arguments += target
    else:
        arguments += f"-iL {target}"  # 作为文件名拼接
    result = nm.scan(hosts=" ", arguments=arguments,
                     sudo=settings.netscan.enable_sudo)
    return result


def _ScanInfo(data: dict) -> None:
    """
    使用日志模块输出扫描结果相关信息

    :param dict data :  来自nmap.PortScanner.scan的原始结果
    """
    command_line = data['nmap']['command_line']
    elapsed = data['nmap']['scanstats']['elapsed']
    uphosts = data['nmap']['scanstats']['uphosts']
    totalhosts = data['nmap']['scanstats']['totalhosts']

    logger.log("INFOR", f"Command line: {command_line}")
    logger.log(
        "ALERT", f"elapsed: {elapsed}  \tuphosts: {uphosts}  \ttotalhosts: {totalhosts}")

    return None


def AliveScan(targets: list) -> list:
    """
    主机存活扫描入口函数

    :param list targets :  IP/CIDR/FilePath into list
    :return : alive host result
    :rtype  : list
    """
    logger.log("INFOR", "Host alive scan start")

    result = list()
    len_targets = len(targets)
    for target in targets:
        logger.log("TRACE", f"Target: {target}")
        logger.log("INFOR", f"The last {len_targets} targets")
        len_targets -= 1

        try:
            data = _NmapStart(target, "alive")
            _ScanInfo(data)
            for host in data.get('scan'):
                result.append(host)

        except Exception as identifier:
            logger.log("ERROR", repr(identifier))

    logger.log("INFOR", "Host alive scan finish")
    return list(set(result))    # 去除重复数据


def _analysis(data: dict) -> dict:
    """
    端口扫描数据提取
    """
    result = dict()
    for host in data.get('scan'):
        if data['scan'][host].get('tcp'):
            if result.get(host) is None:
                result[host] = dict()
            result[host]["ports"] = data['scan'][host].get('tcp')
    return result


def PortScan(targets: list) -> dict:
    """
    端口服务扫描入口函数

    :param list targets :  IP/CIDR/FilePath into list
    :return : port scan result
    :rtype  : dict
    """
    logger.log("INFOR", "Host service scan start")
    logger.log("INFOR", "It could take a long time.(Really long!)")

    result = dict()
    for target in targets:
        logger.log("TRACE", f"Target: {target}")

        try:
            data = _NmapStart(target, "port")
            _ScanInfo(data)
            result.update(_analysis(data))
        except Exception as identifier:
            logger.log("ERROR", repr(identifier))

    logger.log("INFOR", "Host service scan finish")
    return result
