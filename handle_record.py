#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/10/15 下午4:35
# @Author  : jesse
# @File    : handle_record.py

import re
import sys
from record import Record
from domain import DNSPodApiException


#判断一个字符串是否为IP地址
def is_ip_avaliable(ip):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(ip):
        return True
    else:
        return False


class HandleRecord(Record):
    '''
    处理DNS解析记录工作
    '''
    def __init__(self):
        super().__init__()

    # 检查域名是否存在的装饰器函数,清空sub_domain子域名信息的装饰器函数默认程序运行后的所有操作都在同一个域名下,所以只需要获取一次即可
    # 另外,每次任务开始前都需要清空上次保存的sub_domain子域名和提交参数信息
    def check_domain(f):
        '''
        检查域名是否存在,以及获取域名id.所有工作的前提准备工作
        :return:
        '''

        def inner(self, *args, **kwargs):
            # 判断是否存在域名,如果不存在,则输入
            if not self.domain:
                # 获取域名
                self.domain = input("请输入要配置的域名:>>>").strip()
                # 检查域名是否存在,如果不存在,直接退出.
                self.is_domain_avaliable()
                if self.response.get("status", {}).get("code") != "1":
                    print("域名不存在!请重新输入.")
                    sys.exit(1)

            if self.sub_domain:
                self.sub_domain = None

            if self.params:
                self.params = {}

            f(self, *args, **kwargs)

        return inner

    def auth_paras(self):
        '''
        验证用户输入的参数是否正确
        :param record_type:
        :param value:
        :param ttl:
        :param mx:
        :return:
        '''
        # 判断解析记录类型
        if not self.record_type:
            # 默认为A记录
            self.record_type = "A"

        elif self.record_type.upper() == "CNAME" or self.record_type.upper() == "TXT" or self.record_type.upper() == "A":
            self.record_type = self.record_type.upper()

        else:
            raise DNSPodApiException("解析记录输入错误.请重新输入")

        # 判断value
        if not self.value: raise DNSPodApiException("解析值输入有误,必须指定解析值.请重新输入")

        if self.record_type == "A":
            # 如果解析类型为A记录,则值为一个IP地址
            if not is_ip_avaliable(self.value):
                raise DNSPodApiException("解析值输入错误.如果解析为A记录,则值必须为IP地址,请重新输入")
            else:
                self.value = self.value
        else:
            self.value = self.value

        # 判断ttl
        if not self.ttl:
            self.ttl = 600
        elif str(self.ttl).isdigit():
            self.ttl = int(self.ttl)
        else:
            raise DNSPodApiException("ttl输入错误.ttl必须为数字,请重新输入")

        # 判断mx优先级
        if not self.mx:
            self.mx = None

        elif not str(self.mx).isdigit():
            raise DNSPodApiException("mx输入错误.mx必须为1-20范围内数字,请重新输入")

        elif self.mx < 1 or self.mx > 20:
            raise DNSPodApiException("mx输入错误.mx必须为1-20范围内数字,请重新输入")
        else:
            self.mx = int(self.mx)


    def get_paras(self,paras=None):
        '''
        组装参数
        :return:
        '''
        parameter_info = {}

        # 获取子域名(sub_domain)
        if not self.sub_domain:
            self.sub_domain = input("请输入DNS解析子域名名称(域名前缀):>>>").strip()

        # 如果不传入参数,说明只需读取列表,此时只需要域名和子域名前缀即可
        if not paras:
            return self.sub_domain

        # 如果是添加或者修改一条记录
        else:
            self.record_type = input("请输入你要配置的解析类型.有A记录,CNAME记录,TXT记录等,回车默认为A记录:>>>").strip()
            self.value = input("请输入DNS解析记录值:>>>").strip()
            self.ttl = input("请输入TTL的缓存时间.要求为数字,免费版最低ttl为600,企业基础版最低为10,回车默认为600:>>>").strip()
            self.mx = input("请输入域名解析的优先级,回车默认为None,如果指定优先级则必须为1-20范围区间:>>>").strip()

            # 验证参数格式
            self.auth_paras()

            # 拼接参数.创建和修改DNS记录解析会用到
            self.params = dict(domain=self.domain, sub_domain=self.sub_domain, record_line=self.record_line,
                               record_type=self.record_type, value=self.value, ttl=self.ttl, mx=self.mx)

    @check_domain
    def get_record_info(self,operation):
        '''
        获取某条DNS解析记录的信息,包含DNS解析记录的id,值,状态等
        :return:
        '''
        # 检查子域名的解析记录是否已经存在,并且拿到self.sub_domain_record_list
        self.check_record()

        # 判断解析记录条目.
        if not self.sub_domain_record_list:
            # 如果没有该子域名的任何解析记录,则表示没有选取DNS解析条目
            choise = None

        elif len(self.sub_domain_record_list) == 1:
            # 如果只有一条记录,则直接选取该条记录
            choise = 0

            # 如果有多条DNS解析记录,则获取具体某条DNS解析记录
        else:
            while True:
                choise = input("请选择需要操作的一条DNS解析记录.按q退出:>>>").strip()

                if choise.upper() == "Q":
                     choise = None
                     break
                elif not choise.isdigit():
                    print("请您输入数字")

                elif int(choise) > len(self.sub_domain_record_list) or int(choise) < 0:
                    print("您的选择超出了范围")

                else:
                    choise = int(choise)
                    break

        # 获取DNS解析记录的信息,包含记录id和解析记录状态
        if choise is not None:
            self.record_info = self.sub_domain_record_list[choise]
            # 获取精确的sub_domain.
            self.sub_domain = self.record_info.get("sub_domain")

            #交互式确认
            print("DNS解析条目的修改或删除会立即影响该DNS条目的解析,请谨慎操作.")
            if operation == 'status':
                # 由于DNS解析条目的状态只有2种,所以用三元运算获取需要修改的相反结果
                self.status_oppsite = "disable" if self.record_info.get('status') == "enable" else "enable"
                ack = input("当前DNS解析条目的状态为:{},请确认是否需要更改为:{}? yes or no:>>>".
                            format(self.record_info.get('status'), self.status_oppsite)).strip()

            elif operation == 'delete':
                ack = input("确认是否删除该条记录,删除后不可恢复,请谨慎操作!.yes确认,任意键取消:>>>").strip()

            elif operation == 'modify':
                ack = input("当前DNS解析条目的值为:{},是否确认需要修改!.yes确认,任意键取消:>>>".
                            format(self.record_info.get('record_value'))).strip()
            else:
                ack = None

            # 判断交互式确认结果
            if ack.upper() != "YES":
                print("域名变更操作取消.程序退出")
                sys.exit()

        # 如果没有激活任何DNS解析条目,则清空record_info的信息,因为在多次运行后record_info可能会保留之前的信息
        else:
            self.record_info = None


    def check_record(self):

        # 获取用户输入的子域名
        self.sub_domain = self.get_paras()

        # 检查是否存在子域名的解析记录
        self.is_record_exists()
        if self.sub_domain_record_list:
            print("以下是该子域名:{}相关的DNS解析记录部分信息:".format(self.sub_domain), sep="\n")
            for index,item in enumerate(self.sub_domain_record_list):
                print(index,":",item)

    
    @check_domain
    def list_info(self):
        '''
        获取.并且打印域名下的某个子域名解析记录信息
        :return:
        '''
        self.check_record()
        if not self.sub_domain_record_list:
            print("当前子域名:{}的DNS解析记录不存在!".format(self.sub_domain))

    @check_domain
    def create(self):
        '''
         创建一条解析记录.有两种情况:
            1.解析记录是否已经存在?
            2.是否添加多条同子域名的解析记录.(免费版最多2个,企业基础版10个)

            提供必要的参数: 域名(或者域名id),解析值,解析类型,解析线路.
            可选参数: 解析记录状态,ttl缓存时间,mx优先级,解析名
        :return:
        '''

        # 检查子域名的解析记录是否已经存在,并且拿到self.sub_domain_record_list
        self.check_record()

        # 如果子域名解析记录存在,则询问是否需要继续添加
        if self.sub_domain_record_list:
            ack = input("当前已经存在以上解析记录,是否仍然需要继续添加{}的解析记录.yes or no:>>>".format(self.sub_domain)).strip()
            if ack.upper() != "YES":
                print("操作取消,返回主界面")
                return

        # 如果不存在,或者用户确认,开始添加DNS解析记录

        # 获取多个参数.
        self.get_paras(paras="create")

        #创建DNS解析记录
        self.record_create()
        if self.response.get("status", {}).get("code") == "1":
            print("DNS解析记录创建成功.")
            self.check_record()
        else:
            print("DNS解析记录失败!")
            print(self.response)

    @check_domain
    def modify(self):
        '''
        修改一条DNS记录.
        有两种情况:
            1.解析记录是否已经存在?.如果不存在直接返回
            2.是否添加多条同子域名的解析记录.如果存在多个,要修改哪个?

        相比创建DNS记录解析,多了一个必选参数:record_id.当存在多个解析记录时,需要指定要修改的解析记录
            提供必要的参数: 域名(或者域名id),解析记录id,解析值,解析类型,解析线路.
            可选参数: 解析记录状态,ttl缓存时间,mx优先级,解析名
        :return:
        '''
        #获取record_ionfo
        self.get_record_info("modify")

        # 拿到解析记录的record_info
        if self.record_info:
            # 获取多个参数.
            self.params = []
            self.get_paras(paras="modify")
            # 加上record_id参数
            self.params.update(dict(record_id=self.record_info.get("record_id")))

            #发起请求.返回修改后的DNS解析记录
            self.record_modify()
            if self.response.get("status", {}).get("code") == "1":
                print("DNS记录修改成功")
                self.check_record()
            else:
                print(self.response)

        else:
            print("子域名{}解析记录,并不存在.请您重新检查".format(self.sub_domain))

    @check_domain
    def change_status(self):
        '''
        开启或者关闭一条解析记录
        必选参数:
        domain,record_id,status:{enable|disable}
        :return:
        '''
        # 获取record_info
        self.get_record_info("status")

        if self.record_info:

            self.params = dict(domain=self.domain, record_id=self.record_info.get("record_id"), status=self.status_oppsite)

            # 发起调用
            self.record_status()
            if self.response.get("status", {}).get("code") == "1":
                print("DNS记录状态修改成功!")
                self.check_record()
            else:
                print("DNS记录状态修改失败")
                print(self.response)

        else:
            print("子域名{}解析记录,并不存在.请您重新检查".format(self.sub_domain))


    @check_domain
    def delete(self):
        '''
        删除一条解析记录,需要先判断该解析记录是否存在,以及是否有多个解析记录存在
        提供必要的参数: 域名(或者域名id),解析记录的Id
        :return:
        '''
        # 获取record_info
        self.get_record_info("delete")

        if self.record_info:
            # 拼接参数

            self.params = dict(domain=self.domain, record_id=self.record_info.get("record_id"))

            # 发起调用
            self.record_remove()
            if self.response.get("status", {}).get("code") == "1":
                print("DNS条目删除成功")
            else:
                print(self.response)

        else:
            print("子域名{}解析记录,并不存在.请您重新检查".format(self.sub_domain))


    def run(self):
        print("DNS域名解析视图：")
        while True:
            print("=" * 50,sep="\n")
            print("1.创建解析记录\n"
                  "2.修改解析记录的值\n"
                  "3.删除解析记录\n"
                  "4.设置解析记录状态\n"
                  "5.查看DNS解析记录信息\n"
                  "0.退出\n")
            print("=" * 50,sep="\n")

            res = input("输入序号：").strip()

            if res == "1":
                self.create()
            elif res ==  "2":
                self.modify()
            elif res == "3":
                self.delete()
            elif res == "4":
                self.change_status()
            elif res == "5":
                self.list_info()
            elif res == "0":
                print("退出成功！")
                break
            else:
                print("请选择正确的编号")


if __name__ == "__main__":
    dns_record = HandleRecord()
    dns_record.run()