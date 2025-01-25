import logging


class Function:
    """
    challenge中的一个文件中的方法的详情
    """
    def __init__(self, name: str, body: str):
        self.name = name
        self.body = body
        self.call_site_list = []  # 调用站点列表，存储调用的函数名
        self.call_site_args = {}  # 存储每个调用站点对应的传递参数，格式: {调用站点名: [参数1, 参数2, ...]}
        self.tainted_params = []  # 当前函数的污点参数
        self.vuln_call_site = []  # 漏洞调用链站点
        self.type = {
            "input": False,
            "file_read": False,
            "authentication": False,
            "memoryOP": False,
            "command": False,
            "integer": False,
            "other": False
        }
        self.mini_body = ""
        self.node = ""
        logging.info(f"方法 {self.name} 初始化完毕！！！！")

    def setType(self, type_dict: dict):
        self.type.update(type_dict)
        logging.debug(f"设置函数 {self.name} 的类型: {type_dict}")

    def set_all_type(self, bool: bool):
        for key in self.type.keys():
            self.type[key] = bool

    def get_all_type(self):
        return self.type

    def setCallSites(self, call_sites: list[str]):
        self.call_site_list.extend(call_sites)
        logging.debug(f"设置函数 {self.name} 的调用站点: {call_sites}")

    def setCallSiteArgs(self, call_site: str, args: list[str]):
        """
        设置调用站点的传递参数
        :param call_site: 调用站点的名称
        :param args: 调用站点的参数列表
        """
        self.call_site_args[call_site] = args
        logging.debug(f"为函数 {self.name} 的调用站点 {call_site} 设置参数: {args}")

    def setTaintedParams(self, tainted_params: list[str]):
        """
        设置函数的污点参数
        :param tainted_params: 污点参数列表
        """
        self.tainted_params = tainted_params
        logging.debug(f"设置函数 {self.name} 的污点参数: {tainted_params}")

    def setmini_body(self, mini_body: str):
        self.mini_body = mini_body
        logging.debug(f"设置函数 {self.name} 的迷你体: {mini_body}")

    def propagateTaint(self, parent_function: 'Function'):
        """
        污点传播分析：判断当前函数的调用站点是否可以连接到父函数的污点参数
        :param parent_function: 父函数对象
        """
        for call_site, args in self.call_site_args.items():
            # 检查是否有参数是父函数的污点参数
            if any(arg in parent_function.tainted_params for arg in args):
                # 如果有，加入漏洞调用链
                self.vuln_call_site.append(call_site)
                logging.debug(f"函数 {self.name} 的调用站点 {call_site} 被添加到漏洞调用链中。")

    def getVulnCallSites(self):
        """
        获取漏洞调用站点列表
        """
        return self.vuln_call_site