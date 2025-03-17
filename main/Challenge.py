import json
import logging
from typing import List
from networkx import DiGraph
from tree_sitter import Language, Node, Parser, Query, Tree
import os
import networkx as nx
import matplotlib.pyplot as plt

import libs.llmService
from libs.objects import ChallengeFile, Function, VulnChain
from libs.utils import FileParser, Merger, VulChainGenerator

"""表示一个挑战，即一道题(如0,1,2),可能包含多个文件,存储在文件列表中，每一类漏洞文件夹下有多个题目漏洞"""


class Challenge:

    def __init__(self, challenge_dir: str, vuln_type: str):
        logging.info(f"开始初始化题目：{challenge_dir}")
        self.vuln_type: str = vuln_type  # 自漏洞类型
        logging.debug(f"题目类型：{self.vuln_type}")
        self.challenge_dir: str = challenge_dir  # 自文件夹路径
        logging.debug(f"题目路径：{self.challenge_dir}")

        self.file_list: list[ChallengeFile] = self.get_file_list()  # self.file_list是一个列表每一个元素都是ChallengeFile类型
        """
        ChallengeFile表示challenge中的一个文件,路径和内容
        """
        logging.debug(f"找到 {len(self.file_list)} 个文件")
        self.function_analyser: libs.llmService.FunctionAnalyser = libs.llmService.FunctionAnalyser()
        self.file_parser: FileParser = FileParser()
        self.vul_chain_generator: VulChainGenerator = VulChainGenerator()
        self.vul_checker: libs.llmService.VulnChecker = libs.llmService.VulnChecker()
        self.ParamsAndBodyTravel: libs.llmService.ParamsAndBodyTravel = libs.llmService.ParamsAndBodyTravel()
        self.CodeChainTravel: libs.llmService.CodeChainTravel = libs.llmService.CodeChainTravel()
        self.all_funtion_list: list[Function] = []  # 一个challenge下面所有的方法，这有问题吧？
        self.call_graph = nx.DiGraph()  # nx.DiGraph 是 NetworkX 提供的一个类，用于创建和操作有向图。
        self.vuln_chain_dict: dict[str, list[VulnChain]] = {}  # (sink函数名) 是字典中的 key，而 vuln_chain 是字典中的 value

        self.da_li_chu_qi_ji_mode = False

    def code_chain_generate(self):
        """
        遍历vuln_chain_dict取出每一条链子组装成code_chain_dict,
        """
        for function_name, vuln_chain_list in self.vuln_chain_dict.items():
            for vuln_chain in vuln_chain_list:  # 在这里处理每个 VulnChain 对象
                # chain = CodeChain()#需要的是sink函数的名字，参数，
                sink = vuln_chain.vuln_chain_function[-1]  # 这里取最后一个也就是sink点
                self.CodeChainTravel.chain_generate(vuln_chain)
                input_chain = self.CodeChainTravel.to_json(vuln_chain, sink)
                output = self.CodeChainTravel.analysis_chain(input_chain)
                challenge_dir_name = os.path.basename(self.challenge_dir)
                output_dir = os.path.join("F:/juliet/datacon_model/result", self.vuln_type,
                                          f"{challenge_dir_name}.json")
                # 确保目标文件夹存在
                os.makedirs(os.path.dirname(output_dir), exist_ok=True)
                # 将 JSON 数据追加到文件中
                with open(output_dir, "a", encoding="utf-8") as file:
                    # 写入 JSON 数据，确保格式正确
                    json.dump(output, file, indent=4, ensure_ascii=False)
                    print("JSON 数据已写入指定路径")
                    print("JSON 数据已写入当前文件夹中的 result.json 文件")

    def travel_Params_And_Body(self):
        """
        这个方法将Function中的node补充完成
        """
        for function_name, vuln_chain_list in self.vuln_chain_dict.items():
            for vuln_chain in vuln_chain_list:  # 在这里处理每个 VulnChain 对象
                self.ParamsAndBodyTravel.audit_vulnerability_chain(vuln_chain)

    def get_file_list(self):
        """
        读取题目下的所有文件，一个题目就是一个challenge，返回元素为文件路径和内容的包装
        """
        file_path_list = []
        for root, dirs, files in os.walk(self.challenge_dir):
            for file in files:
                file_path = os.path.join(root, file)
                file_path_list.append(file_path)

        # 获取一个challenge下所有的file的内容
        file_list = []
        for file_path in file_path_list:
            logging.debug(f"开始读取文件{file_path}...")
            try:
                with open(file_path) as f:
                    file_content = f.read()
                logging.debug(f"文件{file_path}读取成功！！！")
            except Exception as e:
                logging.error(f"读取文件 {file_path} 时出错，原因: {e}")
                file_content = ""
                logging.error(f"文件 {file_path}设置为空，程序继续...")

            file = ChallengeFile(file_path, file_content)  # 将文件内容和路径打包
            file_list.append(file)
        return file_list

    # 文件方法解析
    def parse_files(self):
        """
        使用FileParser()，借助大模型解析文件中的方法，并去重，然后将方法列表加入给 self.all_funtion_list
        """
        all_funtion_dict: dict[str:Function] = dict()  # 定义了一个名为 all_funtion_dict 的字典
        logging.debug("开始进行文件方法解析...")
        for file in self.file_list:
            self.file_parser.parser(file)
            logging.debug(f"文件{file.file_path}方法解析完毕！！！")
            if file.function_list.count != 0:  # 方法列表
                logging.info(f"文件{file.file_path}共找到{len(file.function_list)}个方法！！！")
                for function in file.function_list:  # 避免字典中元素重复
                    # 先判断当前函数是否已经在列表内，如果已经在了，则直接合并两个function,再把合并后的function写入字典
                    if (function.name in all_funtion_dict):
                        old_function = all_funtion_dict[function.name]
                        new_function = Merger.merge_function(function, old_function)
                        all_funtion_dict[function.name] = new_function
                    # 如果没有则直接加入
                    else:
                        all_funtion_dict[function.name] = function
        # 从dict里面写入all_funtion_list，确保函数名不会重复
        for key in all_funtion_dict:
            self.all_funtion_list.append(all_funtion_dict[key])  # self.all_funtion_list 最终包含所有去重后的函数对象
        logging.debug("当前题目文件全部解析完成！！！")
        logging.info(f"共解析到{len(self.all_funtion_list)}个方法!!!")

    # 方法语义理解
    def analysis_functions(self):
        """
        借助大模型理解方法语意
        """
        # 题目的方法列表为空，开启大力出奇迹模式
        if (self.all_funtion_list.__len__ == 0 or self.da_li_chu_qi_ji_mode):
            logging.error("没有解析出任何方法！！！开启大力出奇迹模式！！！")
            self.da_li_chu_qi_ji_mode = True
            return
        logging.info("开始进行基于大模型的方法语义解析...")
        for function in self.all_funtion_list:
            self.function_analyser.analysis(function, self.vuln_type)

    def generate_call_graph(self):
        """
        生成方法调用图，有向图，所有函数的调用链
        """
        # 题目的方法为空，开启大力出奇迹模式
        if (self.all_funtion_list.__len__ == 0 or self.da_li_chu_qi_ji_mode):
            logging.error("没有解析出任何方法！！！开启大力出奇迹模式！！！")
            self.da_li_chu_qi_ji_mode = True
            return

        """生成函数调用图"""
        for function in self.all_funtion_list:
            self.call_graph.add_node(function.name,
                                     content=function)  # content=function：节点存储的额外信息（Function 对象），可用于后续查询。
            logging.debug(f"添加{function.name}节点到调用图!!!")

        for function in self.all_funtion_list:
            for call_site in function.call_site_list:
                if (self.call_graph.has_node(call_site)):  # 检查调用目标（call_site）是否已作为节点添加到调用图中
                    self.call_graph.add_edge(function.name,
                                             call_site)  # 如果目标函数存在于调用图中，添加一条从 function.name 到 call_site 的有向边，表示当前函数调用了目标函数
                    logging.debug(f"已添加{function.name}到{call_site}的边！！！")
                else:
                    logging.debug(f"方法{call_site}不在属于调用图中的节点，可能是外部函数，已忽略边添加！！！")

    def generate_vul_chains(self):

        # 调用图中没有节点，开启大力出奇迹模式
        if (self.call_graph.nodes.__len__ == 0 or self.da_li_chu_qi_ji_mode):
            logging.error("调用图中没有任何节点！！！开启大力出奇迹模式！！！")
            self.da_li_chu_qi_ji_mode = True
            return

        logging.info("开始调用链切片！！！")
        # 生成漏洞利用链,漏洞利用链中可能有重复的函数，所以需要判断同一个函数名字
        vuln_chain_list: list[VulnChain] = []
        vuln_chain_list = VulChainGenerator().generate(self.call_graph, self.vuln_type)

        logging.info(f"切片完成,题目{self.challenge_dir}共找到{len(vuln_chain_list)}条调用链!!!")
        "先对漏洞利用链字典做初始化"
        for vuln_chain in vuln_chain_list:
            self.vuln_chain_dict[vuln_chain.vuln_function_name] = []
        "再添加所有的结果"
        for vuln_chain in vuln_chain_list:
            self.vuln_chain_dict[vuln_chain.vuln_function_name].append(vuln_chain)
        "vuln_chain.vuln_function_name(sink函数名) 是字典中的 key，而 vuln_chain 是字典中的 value"

    """
    检查漏洞利用链条,bool判断
    """

    def check_vul_chains(self):

        # 漏洞利用链可能为0，这个时候切换到大力出奇迹，完全交给ai检查
        if self.vuln_chain_dict.__len__() == 0 or self.da_li_chu_qi_ji_mode:
            logging.error("没有备选漏洞利用链条！！！开启大力出奇迹模式！！！")
            self.da_li_chu_qi_ji_mode = True
            return

        logging.info(f"开始进行漏洞利用链检查...")
        for key in self.vuln_chain_dict.keys():
            flag = False
            vuln_chain_list: dict[str:list[VulnChain]]
            vuln_chain_list = self.vuln_chain_dict[key]
            for vuln_chain in vuln_chain_list:
                if flag:
                    break
                logging.info(f"开始检查漏洞利用链{vuln_chain.vuln_chain_function_list}")
                is_vuln = self.vul_checker.bool_check(vuln_chain, self.vuln_type)
                if (is_vuln):
                    logging.info(f"找到漏洞！！！漏洞函数名:{vuln_chain.vuln_function_name}")
                    self.results[key] = vuln_chain
                    flag = True

        if self.results.count == 0:
            logging.error("没有找到任何漏洞...")
            # todo:开启大力飞转模式

    """
    检查漏洞利用链条，可能性评分判断
    """

    def check_vul_chains_by_score(self):

        # 维护一个漏洞名:分数的列表
        result_dict: dict[str:int] = {}
        # 漏洞利用链可能为0，这个时候切换到大力出奇迹，完全交给ai检查
        if self.vuln_chain_dict.__len__() == 0 or self.da_li_chu_qi_ji_mode:
            logging.error("没有备选漏洞利用链条！！！开启大力出奇迹模式！！！")
            self.da_li_chu_qi_ji_mode = True
            return

        # 漏洞检查，直接给vuln chain赋分
        logging.info(f"开始进行漏洞利用链检查...")
        for key in self.vuln_chain_dict.keys():
            vuln_chain_list: list[VulnChain]
            vuln_chain_list = self.vuln_chain_dict[key]
            for vuln_chain in vuln_chain_list:
                logging.info(f"开始检查漏洞利用链{vuln_chain.vuln_chain_function_list}")
                score = self.vul_checker.int_check(vuln_chain, self.vuln_type)
                vuln_chain.set_score(score)

        # 检查每一个function的最高分,然后把结果写到中间
        for key in self.vuln_chain_dict.keys():
            max_score = 0
            vuln_chain_list: list[VulnChain]
            vuln_chain_list = self.vuln_chain_dict[key]
            for vuln_chain in vuln_chain_list:
                if vuln_chain.score > max_score:
                    max_score = vuln_chain.score
            result_dict[key] = max_score

        for key in result_dict.keys():
            if result_dict[key] >= 3:
                self.results[key] = 3

        if len(self.results) == 0:
            logging.error("没有找到任何漏洞...将加入可能性为2的进入结果")
            count = 0
            for key in result_dict.keys():
                # 有可能有很多结果，所以只放三个进去
                if result_dict[key] == 2 and count < 3:
                    self.results[key] = 2
                    count += 1
            # todo:开启大力飞转模式

    """
    检查漏洞利用链条，可能性评分判断,换了一种评分模式
    """

    def check_vul_chains_by_score_new(self):

        # 漏洞利用链可能为0，这个时候切换到大力出奇迹，完全交给ai检查
        if self.vuln_chain_dict.__len__() == 0 or self.da_li_chu_qi_ji_mode:
            logging.error("没有备选漏洞利用链条！！！开启大力出奇迹模式！！！")
            self.da_li_chu_qi_ji_mode = True
            return
        # 要检查一遍，是不是在function name里面,所以拿到funtionnamelist
        function_name_list = []  # 函数名称列表
        for function in self.all_funtion_list:
            function_name_list.append(function.name)
        logging.info(f"全部的函数名:{function_name_list}")
        # 记录函数名和得三分的字典
        function_name_count = {name: 0 for name in function_name_list}  # 初始化一个字典 键：函数名称 值：初始评分（0）
        # 漏洞检查，直接给vuln chain赋分
        logging.info(f"开始进行漏洞利用链检查...")
        for key in self.vuln_chain_dict.keys():
            vuln_chain_list: list[VulnChain]  # 这只是一个类型提示，不会影响程序运行。
            vuln_chain_list = self.vuln_chain_dict[key]  # 将当前键 key 对应的值（一个漏洞链列表VulnChain）赋值给变量 vuln_chain_list
            for vuln_chain in vuln_chain_list:
                logging.info(f"开始检查漏洞利用链{vuln_chain.vuln_chain_function_list}")
                llm_function_name, vul_chain_function_name, score = self.vul_checker.int_check_new(vuln_chain,
                                                                                                   self.vuln_type)
                # 记录总得分
                if (llm_function_name in function_name_list):
                    function_name_count[llm_function_name] += score
                elif (vul_chain_function_name in function_name_list):
                    function_name_count[vul_chain_function_name] += score

        sorted_function_name_count = sorted(function_name_count.items(), key=lambda item: item[1], reverse=True)
        top_three_functions = sorted_function_name_count[:10]
        logging.info(f"分数最高的前十个函数: {top_three_functions}")

        top_functions = []
        for i, (function_name, score) in enumerate(sorted_function_name_count):
            if i == 0 or score > sorted_function_name_count[i - 1][1] / 2:
                top_functions.append(function_name)
            else:
                break
            if len(top_functions) >= 3:
                break
        # 如果不足三个，打印实际提取的数量
        if len(top_functions) < 3:
            logging.info(f"注意：只有 {len(top_functions)} 个函数满足条件")
        self.results = top_functions

    def save_result(self, output_dir):
        # 如果最后保存结果的时候，前面任意缓解出现了致命问题，则直接调用大力出奇迹。
        if (self.da_li_chu_qi_ji_mode):
            self.da_li_chu_qi_ji()
            return
        logging.debug(f"正在保存结果···")
        output_path = os.path.join(output_dir, self.vuln_type, "answer.txt")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        logging.info(f"写入如下结果{self.results}")
        with open(output_path, 'a') as f:
            for result in self.results:
                f.write(result + "\n")
        logging.info(f"保存结果成功！保存{len(self.results)}条结果！！！")
        pass

    def da_li_chu_qi_ji(self):
        # todo
        pass
