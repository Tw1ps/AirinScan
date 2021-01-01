#!/usr/bin/env python3
# coding=utf-8

"""
Example
"""

from airinscan import AirinScan


def airinscan(cidr: str):
    test = AirinScan(cidr)
    test.filtr = False
    test.run()
    data = test.datas


if __name__ == '__main__':
    airinscan('192.168.1.0/24')
