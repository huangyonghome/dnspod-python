#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/10/14 下午5:02
# @Author  : jesse
# @File    : handle_request.py

import auth
import json
import requests

class DNSPodApiException(Exception):
    pass


def submit(path,**kwargs):
    login_token = auth.login_token
    base_url = "dnsapi.cn/"
    data_dict = kwargs
    data_dict.update(dict(login_token=login_token,format="json"))
    headers = {
        "Content-type": "application/x-www-form-urlencoded",
        "Accept": "text/json",
        "User-Agent": "dnspod-python/0.01 (jessehuang; DNSPod.CN API v2.8)"
    }
    url = "https://" + base_url + path

    # 因为请求查询一个域名解析绑定时,允许域名不存在的情况.而不会程序报错中断.
    # 在提交非法参数,或执行报错时,返回具体报错原因

    response = requests.post(url, data=data_dict, headers=headers)
    data = response.text
    ret = json.loads(data)
    return ret

