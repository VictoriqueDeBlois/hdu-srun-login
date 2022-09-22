#!/usr/bin/env python
# coding=utf-8
import os
import time


def is_connect_internet(test_ip):
    status = os.system("ping {} -c 8".format(test_ip))
    return status == 0


def login(path):
    os.system('cd {} && ./login_hdu_comp.py'.format(path))


if __name__ == '__main__':
    script_path = os.path.dirname(os.path.abspath(__file__))
    ip = 'www.baidu.com'
    success = False
    while not success:
        if not is_connect_internet(ip):
            login(script_path)
        else:
            success = True
        time.sleep(3)
