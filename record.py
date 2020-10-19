#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/10/15 上午9:28
# @Author  : jesse
# @File    : record.py



# dnspod解析记录相关

from handle_request import submit


class DNSPodApiException(Exception):
    pass

class Record():
    '''
    DNS解析记录有以下关键参数:

    domain: 记录所属的域名ID
    ttl: DNS解析记录缓存时间,默认600s
    id:  具体每条DNS记录的解析的id
    value: 解析值
    status: 状态: enable,disable
    sub_domain:  解析名称
    record_type:  解析类型.常见的有 A记录,CNAME记录,TXT记录. 如果没有提供,则默认为@
    mx:    记录优先级.1-20.默认是0
    record_line: 解析线路,默认为中文"默认"
    '''
    def __init__(self,ttl=600,domain=None,record_id=None,value=None,status="enable",sub_domain=None,record_type="@",mx=None,record_line="默认"):
        self.domain = domain             #域名名称
        self.record_id = record_id       #解析记录id
        self.value = value               #解析值
        self.status = status             #解析记录状态
        self.sub_domain = sub_domain     #解析名
        self.record_type = record_type   #解析类型
        self.mx = mx                     #优先级
        self.record_line = record_line   #线路类型
        self.ttl = ttl   #缓存时间

        #提交参数
        self.params = {}

    def list_record(self):
        '''
        获取某个域名下的解析记录列表
        :return:
        '''
        # 调用self.response参数获取域名列表
        self.response = submit("Record.List",domain=self.domain)
        if self.response.get("status", {}).get("code") == "1":
            self.record_list = self.response.get("records")
        else:
            self.record_list = None


    def is_domain_avaliable(self):
        '''
        检查域名是否已经存在
        :return:
        '''
        if not self.domain:
            raise DNSPodApiException("请指定解析的域名名称")
        else:
            self.response = submit("Domain.Info", domain=self.domain)


    def is_record_exists(self):
        '''
        检查要配置的子域名是否已经存在解析记录.如果存在,则保存解析记录的子域名,解析类型和值.
        如果不存在 self.sub_domain_record_list列表为空
        :return:
        '''

        # 清空子域名列表信息.否则在多次查询中,这个列表会保存多次查询记录
        self.sub_domain_record_list = []

        #获取DNS记录列表
        self.list_record()

        if self.record_list:
            for item in self.record_list:
                if item.get("name") == self.sub_domain:
                    record_dict = dict(sub_domain=item.get("name"),record_id=item.get("id"),record_type=item.get('type'),
                                       record_value=item.get('value'),status=item.get('status'))
                    self.sub_domain_record_list.append(record_dict)

    def record_modify(self):
        '''
        修改一条解析记录,需要先判断该解析记录是否存在,以及是否有多个解析记录存在

        提供必要的参数: 域名(或者域名id),解析记录的Id,解析值,解析类型,解析线路.
        可选参数: 解析记录状态,ttl缓存时间,mx优先级,解析名
        :return:
        '''
        self.response = submit("Record.Modify",**self.params)


    def record_remove(self):
        '''
        删除一条解析记录,需要先判断该解析记录是否存在,以及是否有多个解析记录存在
        提供必要的参数: 域名(或者域名id),解析记录的Id
        :return:
        '''

        self.response = submit("Record.Remove",**self.params)

    def record_status(self):
        '''
        开启或者关闭一条解析记录
        提供必要的参数: 域名(或者域名id),解析记录的Id,status:{enable|disable}
        :return:
        '''
        self.response = submit("Record.Status",**self.params)



    def record_create(self):
        '''
        :return:
        '''
        self.response = submit("Record.Create",**self.params)






# def Record_task(self):
#     '''
#     执行具体任务的函数:
#     1.创建解析记录
#     2.修改解析记录的值
#     3.删除解析记录
#     4.设置解析记录状态(开启还是关闭)
#     :return:
#     '''
#
#     record = Record(domain="iqg.pub",value='4.4.5.4',record_type="A",sub_domain="python")
#     record.record_create()
#
#
#
#
#     # 判断是否已经存在子域名的解析记录
#             self.is_record_exists()  #获取解析记录
#
#             if self.sub_domain_record_list:
#                 print("当前已经存在相同的解析记录:")
#                 for item in self.sub_domain_record_list:
#                     print(item)  #打印当前已经存在的解析记录
#
#                 while True:
#                     info = input("是否需要继续添加解析记录:免费版只允许存在2个负载均衡记录.企业基础版允许10个.yes or no:>>>").strip()
#                     if info.isalpha() and info.upper() == "YES":
#                         break
#                     elif info.isalpha() and info.upper() == "NO":
#                         return None
#                     else:
#                         print("您输入不对,请重新输入")
#
#             # 没有同名的子域名记录存在,开始创建DNS解析


if __name__ == '__main__':
    record_ins = Record(domain='iqg.pub')
    record_ins.is_domain_avaliable()
    print(record_ins.response)
    # print(record_ins.record_list)