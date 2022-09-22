#!/usr/bin/env python
# coding=utf-8
import argparse
import hashlib
import hmac
import json
import math
import re
import sys
import time
import base64

if sys.version[0] == '2':
    import urllib
    import urllib2

    proxy = urllib2.ProxyHandler({})
    opener = urllib2.build_opener(proxy)
    urllib2.install_opener(opener)


    def request_get(url, params=None, headers=None):
        if params is not None:
            params = urllib.urlencode(params)
            url = '%s%s%s' % (url, '?', params)
        if headers is None:
            headers = {}

        req = urllib2.Request(url, headers=headers)
        res = urllib2.urlopen(req)
        res = res.read()
        return res
else:
    from urllib import parse, request

    null_proxy_handler = request.ProxyHandler({})
    opener = request.build_opener(null_proxy_handler)


    def request_get(url, params=None, headers=None):
        if headers is None:
            headers = {}
        if params is not None:
            params = parse.urlencode(params)
            url = '%s%s%s' % (url, '?', params)
        req = request.Request(url, headers=headers)
        res = opener.open(req)
        res = res.read().decode('utf-8')
        return res


class Base64:
    def __init__(self):
        self._PADCHAR = "="
        self._ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"

    @staticmethod
    def _getbyte(s, i):
        x = ord(s[i])
        if x > 255:
            print("INVALID_CHARACTER_ERR: DOM Exception 5")
            exit(0)
        return x

    def get_base64(self, s):
        i = 0
        b10 = 0
        x = []
        imax = len(s) - len(s) % 3
        if len(s) == 0:
            return s
        for i in range(0, imax, 3):
            b10 = (self._getbyte(s, i) << 16) | (self._getbyte(s, i + 1) << 8) | self._getbyte(s, i + 2)
            x.append(self._ALPHA[(b10 >> 18)])
            x.append(self._ALPHA[((b10 >> 12) & 63)])
            x.append(self._ALPHA[((b10 >> 6) & 63)])
            x.append(self._ALPHA[(b10 & 63)])
        i = imax
        if len(s) - imax == 1:
            b10 = self._getbyte(s, i) << 16
            x.append(self._ALPHA[(b10 >> 18)] + self._ALPHA[((b10 >> 12) & 63)] + self._PADCHAR + self._PADCHAR)
        elif len(s) - imax == 2:
            b10 = (self._getbyte(s, i) << 16) | (self._getbyte(s, i + 1) << 8)
            x.append(self._ALPHA[(b10 >> 18)] + self._ALPHA[((b10 >> 12) & 63)] +
                     self._ALPHA[((b10 >> 6) & 63)] + self._PADCHAR)
        else:
            # do nothing
            pass
        return "".join(x)


class XEncoder:
    @staticmethod
    def _force(msg):
        ret = []
        for w in msg:
            ret.append(ord(w))
        return bytes(ret)

    @staticmethod
    def _ordat(msg, idx):
        if len(msg) > idx:
            return ord(msg[idx])
        return 0

    def _sencode(self, msg, key):
        l = len(msg)
        pwd = []
        for i in range(0, l, 4):
            pwd.append(
                self._ordat(msg, i) |
                self._ordat(msg, i + 1) << 8 |
                self._ordat(msg, i + 2) << 16 |
                self._ordat(msg, i + 3) << 24)
        if key:
            pwd.append(l)
        return pwd

    @staticmethod
    def _lencode(msg, key):
        l = len(msg)
        ll = (l - 1) << 2
        if key:
            m = msg[l - 1]
            if m < ll - 3 or m > ll:
                return
            ll = m
        for i in range(0, l):
            msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
                msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
        if key:
            return "".join(msg)[0:ll]
        return "".join(msg)

    def get_xencode(self, msg, key):
        if msg == "":
            return ""
        pwd = self._sencode(msg, True)
        pwdk = self._sencode(key, False)
        if len(pwdk) < 4:
            pwdk = pwdk + [0] * (4 - len(pwdk))
        n = len(pwd) - 1
        z = pwd[n]
        y = pwd[0]
        c = 0x86014019 | 0x183639A0
        m = 0
        e = 0
        p = 0
        q = math.floor(6 + 52 / (n + 1))
        d = 0
        while 0 < q:
            d = d + c & (0x8CE0D9BF | 0x731F2640)
            e = d >> 2 & 3
            p = 0
            while p < n:
                y = pwd[p + 1]
                m = z >> 5 ^ y << 2
                m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
                m = m + (pwdk[(p & 3) ^ e] ^ z)
                pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
                z = pwd[p]
                p = p + 1
            y = pwd[0]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
            z = pwd[n]
            q = q - 1
        return self._lencode(pwd, False)


def get_sha1(value):
    return hashlib.sha1(value.encode()).hexdigest()


def get_md5(password, token):
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()


class Login:
    def __init__(self, username, password):
        self.password = password
        self.username = username
        self.header = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/'
                          '537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36'
        }
        self.init_url = "https://login.hdu.edu.cn"
        self.get_challenge_api = "/cgi-bin/get_challenge"
        self.srun_portal_api = "/cgi-bin/srun_portal"
        self.get_info_api = "/cgi-bin/rad_user_info?callback=test"
        self.n = '200'
        self.type = '1'
        self.ac_id = '0'
        self.enc = "srun_bx1"
        self.ip = ''
        self.token = ''
        self.i = ''
        self.hmd5 = ''
        self.chksum = ''

    def get_chksum(self):
        chkstr = self.token + self.username
        chkstr += self.token + self.hmd5
        chkstr += self.token + self.ac_id
        chkstr += self.token + self.ip
        chkstr += self.token + self.n
        chkstr += self.token + self.type
        chkstr += self.token + self.i
        return chkstr

    def get_info(self):
        info_temp = {
            "username": self.username,
            "password": self.password,
            "ip": self.ip,
            "acid": self.ac_id,
            "enc_ver": self.enc
        }
        i = re.sub("'", '"', str(info_temp))
        i = re.sub(" ", '', i)
        return i

    def init_getip(self):
        init_res = request_get(self.init_url, headers=self.header)
        self.ip = re.search(r'ip\s*:\s*"(.*?)"', init_res).group(1)
        print("ip:" + self.ip)

    def get_token(self):
        get_challenge_params = {
            "callback": "jQuery112404953340710317169_" + str(int(time.time() * 1000)),
            "username": self.username,
            "ip": self.ip,
            "_": int(time.time() * 1000),
        }
        get_challenge_res = request_get(self.init_url + self.get_challenge_api,
                                        params=get_challenge_params,
                                        headers=self.header)
        self.token = re.search('"challenge":"(.*?)"', get_challenge_res).group(1)

    def do_complex_work(self):
        self.i = self.get_info()
        xencode = XEncoder()
        cbase64 = Base64()
        xencoded_info = xencode.get_xencode(self.i, self.token)
        self.i = "{SRBX1}" + cbase64.get_base64(xencoded_info)
        self.hmd5 = get_md5(self.password, self.token)
        self.chksum = get_sha1(self.get_chksum())

    def get_srun_portal_params(self):
        return {
            'callback': 'jQuery11240645308969735664_' + str(int(time.time() * 1000)),
            'action': 'login',
            'username': self.username,
            'password': '{MD5}' + self.hmd5,
            'ac_id': self.ac_id,
            'ip': self.ip,
            'chksum': self.chksum,
            'info': self.i,
            'n': self.n,
            'type': self.type,
            'os': 'windows+10',
            'name': 'windows',
            'double_stack': '0',
            '_': int(time.time() * 1000)
        }

    @staticmethod
    def print_msg(resp, info):
        out = ''
        if info in resp:
            out = info + ": " + resp[info]
            print(out)
        return out

    def login(self):
        srun_portal_params = self.get_srun_portal_params()
        srun_portal_res = request_get(self.init_url + self.srun_portal_api,
                                      params=srun_portal_params,
                                      headers=self.header)
        resp = self.convert_json(srun_portal_res)
        print('==login' + '=' * 13)
        self.print_msg(resp, 'error')
        self.print_msg(resp, 'error_msg')
        self.print_msg(resp, 'suc_msg')
        print('=' * 20)

    def login_test(self):
        res = request_get(self.init_url + self.get_info_api,
                          headers=self.header)
        resp = self.convert_json(res)
        print('==login check' + '=' * 7)
        log = self.print_msg(resp, 'error')
        print('=' * 20)
        return log

    def all_login(self):
        self.init_getip()
        self.get_token()
        self.do_complex_work()
        self.login()
        self.login_test()

    @staticmethod
    def convert_json(resp):
        start = resp.find('(')
        data = resp[start + 1:-1]
        return json.loads(data)


def arg_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('username', help='HDU Student Number', nargs='?', default='')
    parser.add_argument('password', help='HDU Account Password', nargs='?', default='')
    parser.add_argument('-s', '--save', action='store_true',
                        help='save account info. load saved info when username is empty')
    return parser


def save_account(username, password):
    info = username + ' ' + password
    encoded = base64.b64encode(info.encode('utf-8'))
    with open('hdu_account', 'wb') as fp:
        fp.write(encoded)


def load_account():
    with open('hdu_account', 'rb') as fp:
        encoded = fp.readline()
    info = base64.b64decode(encoded).decode('utf-8')
    username, password = info.split(' ')
    if sys.version[0] == '2':
        username = username.encode('utf-8')
        password = password.encode('utf-8')
    return username, password


if __name__ == '__main__':
    _parser = arg_parse()
    args = _parser.parse_args()
    user, pw = args.username, args.password
    if args.username == '':
        try:
            user, pw = load_account()
        except IOError as e:
            print("can't find saved account info")
            _parser.print_help()
            exit(0)
    if args.save:
        save_account(user, pw)
    login = Login(user, pw)
    login.all_login()
