import pathlib


# 路径设置
relative_directory = pathlib.Path(__file__).parent.parent  # airin根目录路径
result_save_dir = relative_directory.parent.joinpath('results')  # 结果保存目录
data_storage_dir = relative_directory.joinpath('data')  # 数据存放目录
temp_save_dir = result_save_dir.joinpath('temp')  # 临时文件保存目录


class analysis:

    # cdn相关文件
    cdn_ip_cidr_file = data_storage_dir.joinpath("cdn_ip_cidr.json")

    # 分割掩码小于min_mask的CIDR
    enable_cut_cidr = True  # 分割CIDR开关（默认True）
    min_mask = 21  # 如果子网掩码小于该值则分割成掩码为24位的子网，为0则不替换

    # 筛选扫描CIDR
    enable_scan_filter = True   # 筛选扫描对象开关（默认True）
    scan_top = 5        # 筛选前scan_top项
    scan_minipcount = 2  # 筛选IP数量大于等于scan_minipcount的项

    # 设置数据提取字段
    ip_field = "ip"            # 指定csv文件或json文件中的ip字段，该字段必须
    cidr_field = "cidr"        # 指定csv文件或json文件中的cidr字段，若无此字段则设为None
    domain_field = "subdomain"  # 指定csv文件或json文件中的domain字段，若无此字段则设为None

    # 筛选符合条件的数据
    enable_dict_filtr = True  # 数据筛选开关（默认True）
    dict_filtr_arguments = [{"field": "cdn", "operator": "==", "value": "0"},
                            {"field": "level", "operator": "<=", "value": "2"},
                            {"field": "alive", "operator": "==", "value": "1"}]


class netscan:
    # 请求端口探测设置
    # 你可以在端口列表添加自定义端口, 或者直接在下面的arguments_port自定义nmap参数
    enable_custom_ports = True    # 若使用此处端口列表则设置为 True
    ports = [80, 81, 280, 300, 443, 591, 593, 832, 888, 901, 981, 1010, 1080,
             1100, 1241, 1311, 1352, 1434, 1521, 1527, 1582, 1583, 1944, 2082,
             2082, 2086, 2087, 2095, 2096, 2222, 2301, 2480, 3000, 3128, 3333,
             4000, 4001, 4002, 4100, 4125, 4243, 4443, 4444, 4567, 4711, 4712,
             4848, 4849, 4993, 5000, 5104, 5108, 5432, 5555, 5800, 5801, 5802,
             5984, 5985, 5986, 6082, 6225, 6346, 6347, 6443, 6480, 6543, 6789,
             7000, 7001, 7002, 7396, 7474, 7674, 7675, 7777, 7778, 8000, 8001,
             8002, 8003, 8004, 8005, 8006, 8008, 8009, 8010, 8014, 8042, 8069,
             8075, 8080, 8081, 8083, 8088, 8090, 8091, 8092, 8093, 8016, 8118,
             8123, 8172, 8181, 8200, 8222, 8243, 8280, 8281, 8333, 8384, 8403,
             8443, 8500, 8530, 8531, 8800, 8806, 8834, 8880, 8887, 8888, 8910,
             8983, 8989, 8990, 8991, 9000, 9043, 9060, 9080, 9090, 9091, 9200,
             9294, 9295, 9443, 9444, 9800, 9981, 9988, 9990, 9999, 10000,
             10880, 11371, 12043, 12046, 12443, 15672, 16225, 16080, 18091,
             18092, 21, 22, 23, 25, 42, 43, 53, 107, 135, 445, 520, 1433, 1434,
             3306, 3389, 3443, 13443, 8834, 18834]

    # netscan模块配置
    enable_proxies = False  # nmap扫描代理开关（默认False）
    # 此处为nmap代理参数
    proxies_list = "http://127.0.0.1:8080,socks4://127.0.0.1:1080"
    # NmapStart函数配置
    enable_sudo = True  # nmap扫描特级权限请求开关（默认True）
    # nmap存活探测参数
    # nmap主机存活探测我添加了sudo请求，原因请看-sn参数说明，可将sudo改为False关闭此请求
    # 扫描时间过久可能会出现多次请求特权模式(sudo)的情况，长时间挂机扫描的话还是用root权限用户执行比较好
    """
    -sn 向目标主机发送一个ICMP响应请求、TCP SYN到端口443、TCP ACK到端口80，以及一个ICMP的时间戳请求；
        如果在非特权模式下运行则只发送TCP SYN到端口443、TCP ACK到端口80
    -n  不进行域名解析
    -T[0-5] 数字越大越快
    --min-hostgroup; --max-hostgroup    调整并行扫描组的大小
    --min-parallelism; --max-parallelism    调整并发数的大小
    """
    arguments_alive = '-T4 -sn -n --min-parallelism 256'    # 牺牲部分可靠性加快速度
    # arguments_alive = '-sn -n --min-hostgroup 1024 --min-parallelism 1024'    # 加大力度
    # nmap端口探测参数
    """
    -sV 扫描服务版本
    --version-intensity <强度>（版本扫描强度）
            强度在1到9之间，一般来说，强度越大，服务越有可能被正确识别
    --version-light 相当于 --version-intensity 2
    --version-all   相当于 --version-intensity 9
    -iL     从文件导入目标，IP以一个或多个空格，制表符或换行符分开
    """
    # arguments_port = '-T4 -n -sV --top-ports 1000'
    arguments_port = '-T4 -sV -n --min-hostgroup 256 --min-parallelism 512'
    # 上面这条参数扫 1681 个IP花了我 2091.12 秒
    # arguments_port = '-T4 -n -sV --top-ports 500 --min-hostgroup 256 --min-parallelism 512'   # 若使用这条参数则将custom_ports改为False
    # 上面这条[*] elapsed: 1849.59  	uphosts: 1118  	totalhosts: 1214


class database:
    db_path = result_save_dir.joinpath("airin.sqlite3")  # 数据库文件路径
    table_name = "AIRIN"  # 主要表，扫描结束后将所有数据添加到该表
    temp_table_name = "TEMP"  # 临时表，每次端口扫描后将相关结果保存在该表，防止意外中断导致数据丢失，每次载入Database模块会清空内容


class request:
    enable_req = True  # 爬取网页标题开关 （默认True）

    # 代理设置
    enable_proxy = False  # 是否使用代理(全局开关，默认False)
    proxy_pool = [{'http': 'http://127.0.0.1:1080',
                   'https': 'https://127.0.0.1:1080'}]  # 代理池

    # 请求设置
    thread_count = None  # 请求线程数量(默认None，则根据内存大小设置)
    # 请求超时秒数(默认connect timout推荐略大于3秒，read秒)
    timeout_second = (3.05, 27)
    ssl_verify = False  # 请求SSL验证(默认False)
    allow_redirect = True  # 请求允许重定向(默认True)
    redirect_limit = 10  # 请求跳转限制(默认10次)
    # 默认请求头 可以在headers里添加自定义请求头
    default_headers = {
        'Accept': 'text/html,application/xhtml+xml,'
        'application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'Cache-Control': 'max-age=0',
        'DNT': '1',
        'Referer': 'https://www.baidu.com/',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'X-Forwarded-For': '127.0.0.1'
    }

class export:
    result_save_format = "csv" # 默认导出文件格式
    result_save_encode = "utf-8" # 默认编码

