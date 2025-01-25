import copy
import logging
import traceback
import json
import re
import time
import tree_sitter_c
from tree_sitter import Language, Parser, Query, Node, Tree
import os
import networkx as nx
import matplotlib.pyplot as plt
import tree_sitter_go
import tree_sitter_java
import tree_sitter_php
import tree_sitter_python
import tree_sitter_typescript

from . import llmbase
from .config import Config
from .objects import ChallengeFile, Function, VulnChain
from .llmService import FunctionParser
from .prompt import FunctionParsePrompt


class FileParser:
    """
    对题目文件进行最基础的解析，不同类型的文件解析方式和结果都不同
    对于c文件，能够拿到完整的方法名，方法体，调用点
    对于go文件，能够拿到方法名，方法体，调用点
    对于其他利用括号匹配的文件类型，只能拿到方法体。
    具体：为function_list成员赋值包含这个文件中所有函数的信息
    """

    def __init__(self):
        pass

    def parser(self, file: ChallengeFile) -> list[Function]:
        """根据文件后缀判断类型，根据这个类型去找相应方法解析文件"""
        file_type = file.file_type
        if file_type == ".c":
            self.parser_c_file(file)
        elif file_type == ".cc" or file_type == ".cpp":
            self.parser_cpp_file(file)
        elif file_type == ".go":
            self.parser_go_file(file)
        elif file_type == ".ts":
            self.parser_ts_file(file)
        elif file_type == ".php":
            self.parser_php_file(file)
        elif file_type == ".py":
            self.parser_py_file(file)
        elif file_type == ".java":
            self.parser_java_file(file)
            # 其它类型的文件不做分析，如果一道题目下只有着一种类型的文件，则直接开启大力出奇迹模式。
        else:
            pass

    def parser_c_file(self, file: ChallengeFile):
        function_list = CFileParser().parse(file)
        file.function_list = function_list

    def parser_cpp_file(self, file: ChallengeFile):
        logging.info(f"无法为特定类型文件{file.file_path}构建语法树，采用括号匹配算法")
        function_list = BlockFileParser().parse(file)
        self.normalize(function_list)
        file.function_list = function_list

    def parser_go_file(self, file: ChallengeFile):
        function_list = GoFileParser().parse(file)
        self.normalize(function_list)
        file.function_list = function_list

    def parser_ts_file(self, file: ChallengeFile):
        function_list = TsFileParser().parse(file)
        self.normalize(function_list)
        file.function_list = function_list

    def parser_php_file(self, file: ChallengeFile):
        function_list = PhpFileParser().parse(file)
        file.function_list = function_list

    def parser_py_file(self, file: ChallengeFile):
        function_list = PyFileParser().parse(file)
        self.normalize(function_list)
        file.function_list = function_list

    def parser_java_file(self, file: ChallengeFile):
        function_list = JavaFileParser().parse(file)
        self.normalize(function_list)
        file.function_list = function_list

    def parser_other_file(self, file):
        raise Exception("不支持的格式类型！！！")

    """
    出去方法体中的,把后一位作为真正的方法名
    """

    def normalize(self, function_list: list[Function]):
        for function in function_list:
            name_list = function.name.split(".")
            function.name = name_list[-1]
            for call_site in function.call_site_list:
                call_site_name_list = call_site.split(".")
                call_site = call_site_name_list[-1]


"""
C语言切片
"""


class CFileParser:
    language: Language = Language(tree_sitter_c.language())
    parser: Parser = Parser(language)

    # 完成文件的初步解析，返回函数列表
    def parse(self, file: ChallengeFile) -> list[Function]:
        """打开文件读取内容生成语法树，返回方法列表"""
        tree = None
        try:
            with open(file.file_path, "r", encoding="utf-8") as cFile:
                code = cFile.read()
                tree = self.parser.parse(bytes(code, "utf-8"))
            if tree != None:
                logging.debug(f"{file.file_path}文件语法树构建成功！！！")
                functions: list[Function] = self.getFunctions(tree)
            else:
                raise ValueError("语法树为空")
        except Exception as e:
            logging.error(f"{file.file_path}文件语法树构建失败！！！")
            logging.error(traceback.format_exc())
        return functions

    def getFunctions(self, tree: Tree) -> list[Function]:
        """传入方法的语法树,返回方法列表"""

        logging.debug("正在查询文件AST中所有的方法节点...")
        functions = []
        query = Query(self.language, """(function_definition) @function""")
        functionNodes = query.captures(tree.root_node)["function"]
        logging.debug("正在查询文件AST中所有的方法节点，并构建Function列表...")

        for functionNode in functionNodes:
            fn = self.getFunctionName(functionNode).decode("utf-8")
            fc = self.getFunctionCallSites(functionNode)
            if (fn != None and fc != None):
                functionName = self.getFunctionName(functionNode).decode("utf-8")
                functionBody = functionNode.text
                fc = self.getFunctionCallSites(functionNode)
                functionCallSites = self.getFunctionCallSites(functionNode)
                function = Function(functionName, functionBody)
                function.setCallSites(functionCallSites)
                functions.append(function)
        if (functions.count == 0):
            logging.warning("方法构建失败，匹配到的方法为0")
        else:
            logging.info(f"方法构建成功！！！共构建{len(functions)}个方法！！！")
        return functions

    def getFunctionName(self, node: Node) -> str:
        """传入方法的语法树的函数节点,返回方法的名字"""
        try:
            # 先拿到function_declarator节点
            function_declarator_queryer = Query(
                self.language, """	(function_declarator)@function_declarator"""
            )
            function_declarator = function_declarator_queryer.captures(node)["function_declarator"][0]
            # 再通过function_declarator节点拿到方法名
            function_name_queryer = Query(
                self.language, """	(identifier)@function_name"""
            )
            name = function_name_queryer.captures(function_declarator)["function_name"][
                0
            ].text
            logging.info(f"提取到了文件的{name}方法！！！！")
            return name
        except Exception as e:
            logging.error("提取方法名失败！！！！原因:{e}")
            logging.error(traceback.format_exc())
            return None

    def getFunctionCallSites(self, node: Node) -> list[str]:
        try:
            """传入方法语法树的函数节点，返回函数中的调用点"""
            call_site_queryer = Query(self.language, """function:(identifier)@callSite""")
            call_site_node_dict = call_site_queryer.captures(node)
            if (call_site_node_dict.get("callSite")):
                call_site_node_list = call_site_node_dict["callSite"]
                if call_site_node_list:
                    call_site_name_list = []
                    for call_site_node in call_site_node_list:
                        call_site_name_list.append(call_site_node.text.decode("utf-8"))
                    logging.info(f"共提取到了{len(call_site_name_list)}个调用点！{call_site_name_list}")
                    return call_site_name_list
            else:
                logging.warning("没有提取到调用点!")
                return []
        except Exception as e:
            return None

    def get_block(self, tree: Tree):
        root_node = tree.root_node


"""
切片包含括号，但是没有类的语言类型(cc)
"""


class BlockFileParser:

    # 完成文件的初步解析，返回函数列表
    def parse(self, file: ChallengeFile) -> list[Function]:
        try:
            with open(file.file_path, "r", encoding="utf-8") as GoFile:
                code = GoFile.read()
                functions: list[Function] = self.getFunctions(code)
                return functions
        except Exception as e:
            logging.error(f"{file.file_path}文件解析失败！！！")
            logging.error(traceback.format_exc())
            return []

    """获取函数的"""

    def getFunctions(self, code: str):
        logging.info("正在对文件进行代码切片...")
        code_list = self.extract_code_blocks(code)
        functions = []
        logging.info("代码切片成功！！！")
        for code_body in code_list:
            functionName, functionCallSites = FunctionParser().get_function_name_and_callsites(code_body)
            functionBody = code_body
            function = Function(functionName, functionBody)
            function.setCallSites(functionCallSites)
            functions.append(function)
        if (functions.count == 0):
            logging.warning("方法构建失败，匹配到的方法为0")
        else:
            logging.info(f"方法构建成功!!!共构建")
        return functions

    def extract_code_blocks(self, code):
        """
        根据括号匹配提取代码块。

        :param code: 输入的代码字符串，假设每行代码由换行符'\n'分隔
        :return: 包含提取出的代码块的列表，每个元素是一个字符串，表示一个完整的代码块
        """
        code_blocks = []
        stack = []
        lines = code.split('\n')  # 将输入的代码按行分割
        in_string = False
        string_char = ''
        in_comment = False

        for line_number, line in enumerate(lines, start=1):
            i = 0
            while i < len(line):
                char = line[i]
                if in_string:
                    if char == string_char and (i == 0 or line[i - 1] != '\\'):
                        in_string = False
                elif in_comment:
                    if char == '*' and i + 1 < len(line) and line[i + 1] == '/':
                        in_comment = False
                        i += 1  # Skip the '/' character
                else:
                    if char == '"' or char == "'":
                        in_string = True
                        string_char = char
                    elif char == '{':
                        # 如果栈为空，则当前是函数开头
                        if not stack:
                            start_line = line_number - 1
                        stack.append(line_number)
                    elif char == '}':
                        if stack:
                            start_line = stack.pop() - 1
                            if not stack:
                                end_line = line_number - 1
                                code_block = '\n'.join(lines[start_line - 1:end_line + 1])
                                code_blocks.append(code_block)
                    elif char == '/' and i + 1 < len(line) and line[i + 1] == '*':
                        in_comment = True
                        i += 1  # Skip the '*' character

                i += 1

        return code_blocks


"""
go语言分析器，只能设置方法名和方法体，无法分析调用点
"""


class GoFileParser:
    language = Language(tree_sitter_go.language())  # 调整路径以指向Go语言库
    parser = Parser(language)

    def parse(self, file: ChallengeFile) -> list[Function]:
        tree = None
        try:
            with open(file.file_path, "r", encoding="utf-8") as GoFile:
                code = GoFile.read()
                tree = self.parser.parse(bytes(code, "utf-8"))
            if tree != None:
                logging.info(f"{file.file_path}文件语法树构建成功！！！")
                functions: list[Function] = self.getFunctions(tree)
            else:
                raise ValueError("语法树为空")
        except Exception as e:
            logging.error(f"{file.file_path}文件语法树构建失败！！！")
            logging.error(traceback.format_exc())
        return functions

    def getFunctions(self, tree) -> list[Function]:
        """解析文件，返回函数列表，go这里函数调用点为空，需要后续语法解析的阶段补上函数调用点"""
        try:
            functions = []
            query = Query(self.language, """(method_declaration) @function""")
            function_nodes = query.captures(tree.root_node)["function"]
            for function_node in function_nodes:
                function_body = function_node.text
                function_name, function_call_sites = FunctionParser().get_function_name_and_callsites(function_body)
                function = Function(function_name, function_body)
                function.setCallSites(function_call_sites)
                functions.append(function)
            if not functions:
                logging.warning("方法构建失败，匹配到的方法为0")
            else:
                logging.info(f"方法构建成功!!!共构建 {len(functions)} 个方法")
            return functions
        except Exception as e:
            logging.error(f"An error occurred during analysis: {e}")
            return []


"""
typescript语言分析器，只能设置方法名和方法体，无法分析调用点
"""


class TsFileParser:
    language = Language(tree_sitter_typescript.language_typescript())
    parser = Parser(language)

    def parse(self, file: ChallengeFile) -> list[Function]:
        tree = None
        try:
            with open(file.file_path, "r", encoding="utf-8") as GoFile:
                code = GoFile.read()
                tree = self.parser.parse(bytes(code, "utf-8"))
            if tree != None:
                logging.info(f"{file.file_path}文件语法树构建成功！！！")
                functions: list[Function] = self.getFunctions(tree)
            else:
                raise ValueError("语法树为空")
        except Exception as e:
            logging.error(f"{file.file_path}文件语法树构建失败！！！")
            logging.error(traceback.format_exc())
        return functions

    def getFunctions(self, tree) -> list[Function]:
        """解析文件，返回函数列表，go这里函数调用点为空，需要后续语法解析的阶段补上函数调用点"""
        try:
            functions = []
            query = Query(self.language, """( method_definition)@function""")
            function_nodes = query.captures(tree.root_node)["function"]
            for function_node in function_nodes:
                function_body = function_node.text
                function_name, function_call_sites = FunctionParser().get_function_name_and_callsites(function_body)

                function = Function(function_name, function_body)
                function.setCallSites(function_call_sites)
                functions.append(function)
            if not functions:
                logging.warning("方法构建失败，匹配到的方法为0")
            else:
                logging.info(f"方法构建成功!!!共构建 {len(functions)} 个方法")
            return functions
        except Exception as e:
            logging.error(f"An error occurred during analysis: {e}")
            return []


"""
php语言分析器，只能设置方法名和方法体，无法分析调用点
"""


class PhpFileParser:
    language = Language(tree_sitter_php.language_php())
    parser = Parser(language)

    def parse(self, file: ChallengeFile) -> list[Function]:
        tree = None
        try:
            with open(file.file_path, "r", encoding="utf-8") as GoFile:
                code = GoFile.read()
                tree = self.parser.parse(bytes(code, "utf-8"))
            if tree != None:
                logging.info(f"{file.file_path}文件语法树构建成功！！！")
                functions: list[Function] = self.getFunctions(tree)
            else:
                logging.error(f"{file.file_path}文件语法树构建失败")
                raise ValueError("语法树为空")
        except Exception as e:
            logging.error(f"{file.file_path}文件语法树构建失败！！！")
            logging.error(traceback.format_exc())
        return functions

    def getFunctions(self, tree) -> list[Function]:
        """解析文件，返回函数列表，go这里函数调用点为空，需要后续语法解析的阶段补上函数调用点"""
        try:
            functions = []
            query = Query(self.language, """(method_declaration)@function""")
            function_nodes = query.captures(tree.root_node)["function"]
            for function_node in function_nodes:
                function_body = function_node.text
                function_name, function_call_sites = FunctionParser().get_function_name_and_callsites(function_body)
                function = Function(function_name, function_body)
                function.setCallSites(function_call_sites)
                functions.append(function)
            if not functions:
                logging.warning("方法构建失败，匹配到的方法为0")
            else:
                logging.info(f"方法构建成功!!!共构建 {len(functions)} 个方法")
            return functions
        except Exception as e:
            logging.error(f"An error occurred during analysis: {e}")
            return []


"""
python语言分析器，只能设置方法名和方法体，无法分析调用点
"""


class PyFileParser:
    language = Language(tree_sitter_python.language())
    parser = Parser(language)

    def parse(self, file: ChallengeFile) -> list[Function]:
        tree = None
        try:
            with open(file.file_path, "r", encoding="utf-8") as GoFile:
                code = GoFile.read()
                tree = self.parser.parse(bytes(code, "utf-8"))
            if tree != None:
                logging.info(f"{file.file_path}文件语法树构建成功！！！")
                functions: list[Function] = self.getFunctions(tree)
            else:
                raise ValueError("语法树为空")
        except Exception as e:
            logging.error(f"{file.file_path}文件语法树构建失败！！！")
            logging.error(traceback.format_exc())
        return functions

    def getFunctions(self, tree) -> list[Function]:
        """解析文件，返回函数列表，go这里函数调用点为空，需要后续语法解析的阶段补上函数调用点"""
        try:
            functions = []
            query = Query(self.language, """(function_definition)@function""")
            function_nodes = query.captures(tree.root_node)["function"]
            for function_node in function_nodes:
                function_body = function_node.text
                function_name, function_call_sites = FunctionParser().get_function_name_and_callsites(function_body)
                function = Function(function_name, function_body)
                function.setCallSites(function_call_sites)
                functions.append(function)
            if not functions:
                logging.warning("方法构建失败，匹配到的方法为0")
            else:
                logging.info(f"方法构建成功!!!共构建 {len(functions)} 个方法")
            return functions
        except Exception as e:
            logging.error(f"An error occurred during analysis: {e}")
            return []


"""
java语言分析器，只能设置方法名和方法体，无法分析调用点
"""


class JavaFileParser:
    language = Language(tree_sitter_java.language())
    parser = Parser(language)

    def parse(self, file: ChallengeFile) -> list[Function]:
        tree = None
        try:
            with open(file.file_path, "r", encoding="utf-8") as GoFile:
                code = GoFile.read()
                tree = self.parser.parse(bytes(code, "utf-8"))
            if tree != None:
                logging.info(f"{file.file_path}文件语法树构建成功！！！")
                functions: list[Function] = self.getFunctions(tree)
            else:
                raise ValueError("语法树为空")
        except Exception as e:
            logging.error(f"{file.file_path}文件语法树构建失败！！！")
            logging.error(traceback.format_exc())
        return functions

    def getFunctions(self, tree) -> list[Function]:
        """解析文件，返回函数列表，go这里函数调用点为空，需要后续语法解析的阶段补上函数调用点"""
        try:
            functions = []
            query = Query(self.language, """(method_declaration)@function""")
            function_nodes = query.captures(tree.root_node)["function"]
            for function_node in function_nodes:
                function_body = function_node.text
                function_name, function_call_sites = FunctionParser().get_function_name_and_callsites(function_body)
                function = Function(function_name, function_body)
                function.setCallSites(function_call_sites)
                functions.append(function)
            if not functions:
                logging.warning("方法构建失败，匹配到的方法为0")
            else:
                logging.info(f"方法构建成功!!!共构建 {len(functions)} 个方法")
            return functions
        except Exception as e:
            logging.error(f"An error occurred during analysis: {e}")
            return []


"""
合并器，所有的合并操作在这里面做
"""


class Merger:
    "合并两个同名方法，函数体是添加到后面，调用站点也是直接加到后面"

    def merge_function(function1: Function, function2: Function):
        # 检查是否是同名方法
        if (function1.name != function2.name):
            logging.error(f"合并的两个方法名字不同！以方法1名字为准！")
        new_function_body = function1.body + function2.body
        # call site需要分两次合并，第一次取值，第二次合并,这里用copy确保不会对其他的方法有影响
        new_function_callsites = function1.call_site_list.copy()
        new_function_callsites.extend(function2.call_site_list)
        new_function = Function(function1.name, new_function_body)
        new_function.setCallSites(new_function_callsites)
        return new_function


"""
漏洞利用链生成器
"""


class VulChainGenerator:

    def __init__(self):
        self.llm = llmbase.LLM()
        self.firstArgs_prompt = FunctionParsePrompt.firstArgs  # 还没添加

    def generate(self, call_graph: nx.DiGraph, vuln_type: str) -> list[VulnChain]:
        try:
            vuln_chain_list: list[VulnChain] = []
            vuln_chain_list = self.generate_by_type(call_graph, vuln_type)
            return vuln_chain_list
        except Exception as e:
            logging.error(f"调用图切片发生错误: {e}")
            logging.error(traceback.format_exc())
            return []

    """
    根据不同的漏洞类型，生成不同的切片
    1.source - sink类型
        任意文件访问    缓冲区溢出   命令注入   
    """

    def generate_by_type(self, call_graph: nx.DiGraph, vuln_type: str) -> list[VulnChain]:

        try:
            if vuln_type == "Arbitrary_file_access":
                vuln_chain_list = self.gen_source_sink_type_vulchain("input", "file_read", call_graph)
            elif vuln_type == "Authentication_bypass":
                vuln_chain_list = self.gen_source_sink_type_vulchain("input", "authentication", call_graph)
            elif vuln_type == "Buffer_overflow":
                vuln_chain_list = self.gen_source_sink_type_vulchain("input", "memoryOP", call_graph)
            elif vuln_type == "Command_injection":
                vuln_chain_list = self.gen_source_sink_type_vulchain("input", "command", call_graph)
            elif vuln_type == "Integer_overflow":
                vuln_chain_list = self.gen_source_sink_type_vulchain("input", "integer", call_graph)
            elif vuln_type == "others":
                vuln_chain_list = self.gen_source_sink_type_vulchain("input", "others", call_graph)
            else:
                logging.error(f"未知漏洞类型{vuln_type}!!!开启大力出奇迹模式！！！")
                raise Exception("未知漏洞模式，即将开启大力出奇迹")
            return vuln_chain_list
        except Exception as e:
            logging.error(f"调用图切片发生错误: {e}")
            logging.error(traceback.format_exc())
            return None

    def gen_source_sink_type_vulchain(self, source_type: str, sink_type: str, call_graph: nx.DiGraph):
        """
        生成 外界输入-漏洞发生点类型的漏洞利用链
        "input","file_read",call_graph
        """
        # 可能有三种情况:
        # 1.外部处理函数和漏洞函数是同一个函数
        # 2.外部处理函数和漏洞函数不是同一个函数
        # 3.没有外部处理函数或者漏洞函数
        input_function_list = self.get_target_function_from_cg(call_graph, source_type, True)  # 获取输入类型列表，源函数
        vul_function_list = self.get_target_function_from_cg(call_graph, sink_type, False)  # 获取漏洞类型列表，目标函数
        vuln_chain_list: list[VulnChain] = []
        # 两类节点都有的情况
        if input_function_list.count != 0 and vul_function_list.count != 0:
            for vul_function in vul_function_list:#針對每一個sink點去找所有的input
                for input_function in input_function_list:
                    # 外部处理节点和文件读取节点是同一个节点
                    if input_function.name == vul_function.name:
                        vul_function_new = copy.deepcopy(vul_function)#解决了交错的问题
                        vul_chain = VulnChain(
                            vul_function_new.name, [vul_function_new], [vul_function_new.name]
                        )
                        vuln_chain_list.append(vul_chain)
                        logging.info(
                            f"找到单函数的漏洞利用链:{vul_function.name}"
                        )

                    # 外部处理节点和文件读取节点不是同一个节点
                    else:
                        """
                        拿到input到文件访问的所有路径列表,这里只返回方法名，所以要去function
                        """
                        path_list = list(nx.all_simple_paths(
                            call_graph, input_function.name, vul_function.name
                        ))  # 使用 NetworkX 的 all_simple_paths 方法，查找从源函数到目标函数的所有路径。
                        if len(path_list) == 0:
                            logging.info(f"未找到从 {input_function.name} 到 {vul_function.name} 的路径")
                        else:
                            for function_name_list in path_list:
                                vuln_chain_body: list[Function] = []
                                for function_name in function_name_list:
                                    function_node = call_graph.nodes[function_name]
                                    function = function_node["content"]
                                    if function.body == "":
                                        logging.error(f"函数'{function_name}'没有提取到方法体！！！")
                                        continue
                                    vul_function_new = copy.deepcopy(function)  # 解决了交错的问题
                                    vuln_chain_body.append(vul_function_new)  # 对于每一个调用链将所有方法的方法体拼起来

                                vul_chain = VulnChain(vul_function.name, vuln_chain_body,
                                                      function_name_list)  # function_name_list是一个列表是一条调用链,这个地方不改function_name_list会不会有问题后面再吧
                                vuln_chain_list.append(vul_chain)
                                logging.info(f"找到漏洞利用链: 漏洞函数{vul_function.name}")
                                logging.info(f"漏洞路径{function_name_list}")
        # 只有一类节点
        else:
            # 只有文件访问节点，则直接把文件访问节点作为调用链返回
            if vul_function_list.count != 0:
                for vul_function in vul_function_list:
                    vul_function_new = copy.deepcopy(vul_function)
                    body = vul_function_new
                    name = vul_function.name
                    vul_chain = VulnChain(name, [body], [name])
                    vuln_chain_list.append(vul_chain)
                    logging.info(f"没有找到外部处理函数节点，将文件读取节点作为漏洞链:{vul_function.name}")
            else:
                raise Exception("没有找到疑似漏洞的函数！")
        # 如果漏洞利用链条为空，则直接把那些有疑似的全部加入到结果里面
        a = 1
        if len(vuln_chain_list) == 0:
            for vul_function in vul_function_list:
                body = vul_function
                name = vul_function.name
                vul_chain = VulnChain(name, [body], [name])
                vuln_chain_list.append(vul_chain)
        return vuln_chain_list

    def get_target_function_from_cg(self, call_graph: nx.DiGraph, taget_type, switch: bool) -> list[
        Function]:  # taget_type是input或fileread
        """
        在调用中找到目标属性为True的Function节点
        属性列表见 objects.Function()
        get_target_function_from_cg 的核心功能就是从调用图中找到指定属性（如 input 为 True）的所有函数。
        设置一个开关，为true寻找input，为false去sink函数中标记污点参数
        """
        if switch:
            target_function_list = []
            for node in call_graph.nodes(data=True):
                function = node[1].get("content")
                if function.type.get(taget_type) == True:
                    target_function_list.append(function)

        else:
            target_function_list = []
            for node in call_graph.nodes(data=True):
                function = node[1].get("content")
                if function.type.get(taget_type) == True:
                    result = {
                        "function_body": function.body,
                        "target_type": taget_type
                    }
                    try:
                        count=0
                        llm_output = self.llm.communicate(self.firstArgs_prompt, result)
                        js_obj = self.resolve_output(llm_output)
                        while count <= Config.retry_times:
                            count += 1  # 提示词还没写
                            if js_obj is None:
                                logging.info(f"大模型结果解析sink函數危險參數失败，第{count}次尝试重新请求大模型:")
                                time.sleep(5)  # 增加延迟时间，指数回退
                                llm_output = self.llm.communicate(self.firstArgs_prompt, result)
                                js_obj = self.resolve_output(llm_output)
                            else:
                                function.tainted_params = js_obj

                    except Exception as e:
                            logging.error(f"无法解析function.tainted_params，第{count}次尝试重新请求大模型:")
                    target_function_list.append(function)
        return target_function_list

    def resolve_output(self, content: str):
        # 解析大模型返回结果，有可能为None
        if content is None:
            return None

        logging.debug("开始解析大模型返回结果")

        # 正则模式：匹配可能存在的Markdown格式的JSON数组（方括号）
        pattern = r"```json\s*(\[[\s\S]*?\])\s*```"  # 只匹配JSON数组（方括号）

        try:
            # 尝试匹配Markdown格式的JSON数组代码块
            match = re.search(pattern, content, re.DOTALL)
            if match:
                # 提取匹配的 JSON 部分并转换为字典或列表
                json_str = match.group(1).strip()
                json_obj = json.loads(json_str)
            else:
                # 如果没有Markdown格式，则直接尝试解析纯JSON格式
                json_obj = json.loads(content)

            # 确保返回的是一个符合格式要求的列表（数组）
            if isinstance(json_obj, list):
                return json_obj  # 返回解析后的数组
            else:
                logging.error("返回的不是一个有效的数组")
                return None

        except json.JSONDecodeError as e:
            logging.error("JSON格式解析错误:", e)
            return None
