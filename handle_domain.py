#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/10/16 下午5:21
# @Author  : jesse
# @File    : handle_domain.py

from domain import DNSPodApiException
from domain import Domain

class HandleDomain(Domain):

    def __init__(self):
        super().__init__()


    def get_domain(f):
        def inner(self,*args,**kwargs):
            self.domain = input("请先指定需要操作的域名:>>>").strip()
            f(self,*args,**kwargs)

        return inner

    @get_domain
    def list_info(self):
        '''
        查看域名相关信息
        :return:
        '''
        #发起调用
        self.domain_info()
        if self.response.get("status", {}).get("code") == "1":
            print("域名信息如下:")
            print("域名:{}    域名解析套餐规格:{}     域名状态:{}".
                  format(self.domain,self.grade_title,self.status))
        else:
            print("域名不存在")

    @get_domain
    def create(self):
        '''
        创建一个域名解析绑定,必选参数:domain域名
        需要先判断域名是否已经存在
        :return:
        '''
        #查询域名是否存在
        self.domain_info()

        #判断域名Id是否存在,如果不存在则说明没有该域名
        if not self.domain_id:
            print("开始创建信息")
            self.domain_create()
            print("域名:{}.已成功创建".format(self.domain))

        else:
            print("域名已经存在,无需创建")


    @get_domain
    def change_status(self):
        '''
        设置域名绑定的状态.必选参数domain,status:域名状态，”enable” 、”disable” 分别代表启用和暂停 。
        需要先判断域名是否存在
        :return:
        '''
        # 查询域名是否存在
        self.domain_info()

        #判断是否拿到域名id
        if self.domain_id:
            #由于status只有2种结果,所以可以使用三元运算获取当前状态的相反状态
            status_oppsite = "disable" if self.status == "enable" else "enable"

            print("域名状态关闭会导致整个域名的所有解析不可用,请谨慎操作.")
            ack = input("当前域名状态为:{},请确认是否需要更改为:{}? yes or no:>>>".
                        format(self.status,status_oppsite)).strip()

            if ack.upper() == "YES":
                #拼接参数
                self.params=dict(domain=self.domain,status=status_oppsite)
                # 发起调用
                self.domain_status()
                if self.response.get("status", {}).get("code") == "1":
                    print("域名:{}状态已经变更.当前状态为:{}.".format(self.domain,status_oppsite))
                else:
                    print(self.response)

            else:
                print("域名状态变更操作取消.返回主界面")

        else:
            print("当前域名不存在,请您重新检查")


    def run(self):
        print("DNS域名管理视图：")
        while True:
            print("=" * 50, sep="\n")
            print("1.创建新域名绑定\n"
                  "2.修改域名状态\n"
                  "3.查看域名信息\n"
                  "0.退出\n")
            print("=" * 50, sep="\n")

            res = input("输入序号：").strip()

            if res == "1":
                self.create()
            elif res == "2":
                self.change_status()
            elif res == "3":
                self.list_info()
            elif res == "0":
                print("退出成功！")
                break
            else:
                print("请选择正确的编号")


if __name__ == "__main__":
    dns_domain = HandleDomain()
    dns_domain.run()










