import sqlite3
import time
import random
import pandas

from sqlalchemy import create_engine

from airin.config import settings
from airin.config.log import logger


class Database(object):
    def exec(self, sql: str) -> list:
        results = list()
        try:
            logger.log("TRACE", f"Execute the SQL statement: {sql}")
            self.cursor.execute(sql)
            results = self.cursor.fetchall()
        except Exception as identifier:
            logger.log("ERROR", repr(identifier))
        return results

    def execmany(self, sql: str, data: list) -> None:
        try:
            logger.log("TRACE", f"Execute the SQL statement: {sql}")
            logger.log("TRACE", f"Data: {data}")
            self.cursor.executemany(sql, data)
        except Exception as identifier:
            logger.log("ERROR", repr(identifier))

    def create_table(self, table_name: str) -> None:
        logger.log("INFOR", f"Create table: {table_name}")
        self.exec(f"""
        create table {table_name}(
            id          INTEGER PRIMARY KEY AUTOINCREMENT, 
            cidr        TEXT                NOT NULL, 
            ip          TEXT, 
            domain      TEXT, 
            port        INT, 
            state       TEXT, 
            reason      TEXT, 
            name        TEXT, 
            product     TEXT, 
            version     TEXT, 
            extrainfo   TEXT, 
            conf        TEXT, 
            cpe         TEXT, 
            title       TEXT, 
            status      INT);""")

    def insert_table(self, table_name: str, data: list) -> None:
        logger.log("DEBUG", f"Insert {table_name}")
        self.execmany(f"""
        insert into {table_name} (
            cidr, ip, domain, port, state, 
            reason, name, product, version, 
            extrainfo, conf, cpe, title, status
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", data)
        self.connect.commit()

    def update_HTTP_info(self, table_name: str, data: list) -> None:
        logger.log("DEBUG", f"Update {table_name}")
        self.execmany(f"""
        update {table_name} set
            title=?, status=?
        where
            ip=? and port=?""", data)
        self.connect.commit()

    def drop_table(self, table_name: str) -> None:
        logger.log("DEBUG", f"Drop table {table_name}")
        self.exec(f"drop table {table_name}")
        self.connect.commit()

    def check_table(self, table_name: str) -> int:
        logger.log("TRACE", f"Check table: {table_name}")
        ret = self.exec(
            f"select count(name) from sqlite_master where type='table' and name='{table_name}'")
        logger.log("TRACE", f"Return: {ret}")
        return ret[0][0]

    def get_http_service(self, table_name: str) -> list:
        """
        返回端口服务识别为HTTP相关的数据

        :param str table_name :  查询表
        """
        logger.log("DEBUG", f"Search HTTP service from table: {table_name}")
        results = list()
        data = self.exec(
            f"select cidr, ip, port, name from {table_name} where name like '%http%' and state='open' and title is NULL")
        for cidr, ip, port, name in data:
            if "https" in name or port == 443:
                url = f"https://{ip}:{port}"
            else:
                url = f"http://{ip}:{port}"
            results.append({"url": url, "cidr": cidr, "ip": ip, "port": port})
        logger.log("DEBUG", f"HTTP Service list: {results}")
        return results

    def merging_table(self, src: str, dst: str) -> None:
        """
        表合并

        :param str src :  数据来源表名
        :param str dst :  数据接受表名
        """
        logger.log("DEBUG", f"Merging table {src} and {dst}")
        temp_date = self.exec(
            f"select cidr, ip, domain, port, state, reason, name, product, version, extrainfo, conf, cpe, title, status from {src}")
        self.insert_table(dst, temp_date)
        self.clean(src)

    def clean(self, table_name: str = settings.database.temp_table_name) -> None:
        if self.check_table(table_name) > 0:
            self.drop_table(table_name)

    def close(self):
        logger.log("DEBUG", "Close database connect")
        self.connect.commit()
        self.connect.close()

    def export_csv(self, table_name: str, path: str):
        filename = f'all_{table_name}_data_{time.strftime("%Y%m%d%H%M%S", time.localtime())}{random.randint(0,9999)}.csv'
        engine = create_engine(r'sqlite:///'+str(self.db_path), echo=False)
        table = pandas.read_sql_table(table_name=table_name, con=engine)
        table.to_csv(f"{path}/{filename}")
        logger.log("ALERT", f"Create file: {path}/{filename}")

    def __exit__(self):
        self.close()

    def __init__(self):
        self.db_path = settings.database.db_path
        table_name = settings.database.table_name
        temp_table_name = settings.database.temp_table_name

        logger.log("DEBUG", f"Connect database: {self.db_path}")
        self.connect = sqlite3.connect(self.db_path)
        self.cursor = self.connect.cursor()

        if self.check_table(table_name) < 1:
            logger.log("DEBUG", f"Table {table_name} is not find")
            self.create_table(table_name)

        if self.check_table(temp_table_name) < 1:
            self.create_table(temp_table_name)
