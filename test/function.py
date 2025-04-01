class Function:
    def __init__(self, name, body, param_list):
        self.name = name
        self.body = body
        self.param_list = param_list
        self.tainted_params = []
        self.node = ""
        self.call_site_list = []
        
    def add_tainted_param(self, param):
        if param not in self.tainted_params:
            self.tainted_params.append(param)

class VulnChain:
    """
    表征一个同一个函数的所有漏洞利用链条，
    vuln_function_name是存在漏洞的函数的函数名
    vuln_chain_function是这里存链上的函数结构
    vuln_chain_function_list是链上的所有函数名
    """

    def __init__(self, vuln_function_name: str, vuln_chain_function: list[Function],
                 vuln_chain_function_list: list[str]):  # list[str]
        self.vuln_function_name: str = vuln_function_name
        self.vuln_chain_function = vuln_chain_function  # 改动,这里存链上的函数结构
        self.vuln_chain_function_list = vuln_chain_function_list  # 漏洞调用链，从输入源函数到漏洞函数
        self.mini_chain=''
        self.score = 0