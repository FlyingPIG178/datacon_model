import json
import logging
import re
import time
from typing import Tuple, Dict, List, Any

from . import llmbase
from .TaintAnalyzer import TaintAnalyzer
from .extractor import TaintExtractor
from .objects import Function, VulnChain
from .prompt import IntVulnCheckPrompt, FunctionAnalysisPrompt, BoolVulnCheckPrompt, FunctionParsePrompt
from .config import Config


class FunctionParser:
    def __init__(self):
        # todo  完成提示词
        self.llm = llmbase.LLM()
        self.function_parse_prompt = FunctionParsePrompt.function_parse_prompt

    """
    通过大模型拿到方法的方法名和调用点,大模型返回可能为None,需要设置次数判断并重传
    """

    def get_function_name_and_callsites(self, function_body) -> Tuple[str, list[str], list[str]]:
        count = 0
        # 如果json是None，则说明无法正确解析，重新和大模型沟通,上线次数写到了config里面
        while count <= Config.retry_times:
            count += 1
            llm_output = self.llm.communicate(self.function_parse_prompt, function_body)
            json_result = self.resolve_output(llm_output)
            # time.sleep(5)
            if json_result is None:
                logging.error(f"大模型结果无法转化为json格式，第{count}次尝试重新请求大模型:")
            else:
                # 返回结果成功了，也不一定能正常解析，所以这里要加一个try
                try:
                    function_name = json_result["function_name"]
                    call_sites = json_result["call_sites"]
                    param_list = json_result["param_list"]
                    return function_name, call_sites, param_list
                except Exception as e:
                    logging.error(f"无法解析function_name和call_sites，第{count}次尝试重新请求大模型:")
                break

    def resolve_output(self, content: str):
        # 解析大模型返回结果，有可能为None
        if content == None:
            return None
        logging.info("开始解析大模型返回结果")
        pattern = r"```json\s*({.*?})\s*```"
        # 如果匹配到了md格式的``，则正则匹配，没有的话就直接json.loads()解析
        try:
            match = re.search(pattern, content, re.DOTALL)
            if match:
                json_str = match.group(1).strip()
                json_obj = self.fix_json_escape(json_str)
                json_obj = json.loads(json_obj)
            else:
                content = self.fix_json_escape(content)
                json_obj = json.loads(content)
            return json_obj
        except json.JSONDecodeError as e:
            logging.error("JSON格式解析错误:", e)
            return None

    def fix_json_escape(self, json_str: str) -> str:
        """
        将 JSON 字符串中的所有 \' 改为 '。
        """
        return json_str.replace(r"\'", "'")
    # def split_code(self,code,length):

    # def parse_largefunc(self, code):
    #     p = FunctionParsePrompt()
    #     output = ""
    #     segments = split_code(code, 8000-token_num())


class FunctionAnalyser:
    """
    函数语义分析器，用来分析一个函数的语义
    每种漏洞类型对应一个提示词（prompt），用于引导 LLM 生成相关分析，在init中
    """

    def __init__(self):
        # todo  完成提示词
        self.llm = llmbase.LLM()
        self.Arbitrary_file_access_prompt = FunctionAnalysisPrompt.Arbitrary_file_access_prompt
        self.Authentication_bypass_prompt = FunctionAnalysisPrompt.Authentication_bypass_prompt
        self.Buffer_overflow_prompt = FunctionAnalysisPrompt.Buffer_overflow_prompt
        self.Command_injection_prompt = FunctionAnalysisPrompt.Command_injection_prompt
        self.Integer_overflow_prompt = FunctionAnalysisPrompt.Integer_overflow_prompt
        self.others_prompt = FunctionAnalysisPrompt.others_prompt

    def analysis(self, function: Function, vuln_type: str):
        """
        分析方法的语义，传入方法和漏洞类型，直接修改方法中的语义字典，不返回,对function参数获取Object::Function中的字典信息
        """
        count = 0
        flag = True
        while (flag and count < Config.retry_times):
            flag = False
            # 这里可能遇到返回的json解析成功，但是key解析失败的情况，所以需要try一下，失败了重新跑
            try:
                logging.info(f"开始对{function.name}进行针对{vuln_type}类型漏洞语义分析...")
                if vuln_type == "Arbitrary_file_access_CWE_22":
                    json_result = self.type_analysis(self.Arbitrary_file_access_prompt, function)
                elif vuln_type == "Authentication_bypass_CWE_287":
                    json_result = self.type_analysis(self.Authentication_bypass_prompt, function)
                elif vuln_type == "Buffer_overflow_CWE_119":
                    json_result = self.type_analysis(self.Buffer_overflow_prompt, function)
                elif vuln_type == "Command_injection_CWE_78":
                    json_result = self.type_analysis(self.Command_injection_prompt, function)
                elif vuln_type == "Integer_overflow_CWE_190":
                    json_result = self.type_analysis(self.Integer_overflow_prompt, function)
                elif vuln_type == "others":
                    json_result = self.type_analysis(self.others_prompt, function)
                    # 如果分析失败，则这个方法的type属性全部设置为真，
                if (json_result == None):
                    logging.error(f"大模型结果解析失败，{function.name}的特征将被全部置为假！！！")
                    function.set_all_type(False)
                else:
                    logging.info("大模型结果解析成功！！！")
                    # 首先判断是否存在函数名和调用点，如果没有说明文件解析步骤不支持，则把大模型部分分析的调用点补进去

                    # 根据不同的漏洞类型，设置不同的属性
                    if vuln_type == "Arbitrary_file_access_CWE_22":
                        function.type["input"] = json_result["input"]
                        function.type["file_read"] = json_result["file_read"]
                    elif vuln_type == "Authentication_bypass_CWE_287":
                        function.type["input"] = json_result["input"]
                        function.type["authentication"] = json_result["authentication"]
                    elif vuln_type == "Buffer_overflow_CWE_119":
                        function.type["input"] = json_result["input"]
                        function.type["memoryOP"] = json_result["memoryOP"]
                    elif vuln_type == "Command_injection_CWE_78":
                        function.type["input"] = json_result["input"]
                        function.type["command"] = json_result["command"]
                    elif vuln_type == "Integer_overflow_CWE_190":
                        function.type["input"] = json_result["input"]
                        function.type["integer"] = json_result["integer"]
                    elif vuln_type == "others":
                        function.type["input"] = json_result["input"]
                        function.type["others"] = json_result["others"]
            except Exception as e:
                logging.info(f"字典匹配解析失败！原因:{e}")
                logging.info(f"尝试重新解析...")
                flag = True

    def type_analysis(self, prompt, function: Function):
        """
        调用网上大模型获取函数信息字典，信息内容参考Object::Function
        """
        count = 0
        llm_output = self.llm.communicate(prompt, function.body)  # 超時也是none
        js_obj = self.resolve_output(llm_output)  # 确保函数名正确
        # js_obj获取了函数信息字典
        # 如果json是None，则说明无法正确解析，重新和大模型沟通，最多十次
        while count < Config.retry_times:
            count += 1
            if js_obj is None:
                logging.info(f"大模型结果解析失败，第{count}次尝试重新请求大模型:")
                # time.sleep(5)  # 增加延迟时间，指数回退
                llm_output = self.llm.communicate(prompt, function.body)
                js_obj = self.resolve_output(llm_output)
            else:
                return js_obj
        logging.error(f"针对{function.name}大模型返回值为:{js_obj}")
        return js_obj

    def resolve_output(self, content: str):
        # 解析大模型返回结果，有可能为None
        if content == None:
            return None
        logging.debug("开始解析大模型返回结果")
        pattern = r"```json\s*({.*?})\s*```"  # 匹配 Markdown 格式的 JSON 代码块。如果匹配到了md格式的``，则正则匹配，没有的话就直接json.loads()解析
        try:
            match = re.search(pattern, content, re.DOTALL)  # 在 content 中搜索符合正则表达式的内容。
            if match:
                """
                提取匹配的 JSON 部分：match.group(1)。
                去掉首尾多余的空白字符：strip()。
                使用 json.loads 将 JSON 字符串转化为字典对象。
                """
                json_str = match.group(1).strip()
                json_obj = json.loads(json_str)
            else:  # 如果直接是json格式就直接转化为字典
                json_obj = json.loads(content)
            return json_obj
        except json.JSONDecodeError as e:
            logging.error("JSON格式解析错误:", e)
            return None


class VulnChecker:
    """
    漏洞检查器，检查传入的vulchain是否确实是漏洞
    """

    def __init__(self):
        # todo 完成提示词
        self.llm = llmbase.LLM()
        self.Arbitrary_file_access_prompt = BoolVulnCheckPrompt.Arbitrary_file_access_prompt
        self.Authentication_bypass_prompt = BoolVulnCheckPrompt.Authentication_bypass_prompt
        self.Buffer_overflow_prompt = BoolVulnCheckPrompt.Buffer_overflow_prompt
        self.Command_injection_prompt = BoolVulnCheckPrompt.Command_injection_prompt
        self.Integer_overflow_prompt = BoolVulnCheckPrompt.Integer_overflow_prompt
        self.others_prompt = BoolVulnCheckPrompt.others_prompt

    """
    只返回是有还是没有，返回bool值
    """

    def bool_check(self, vuln_chain: VulnChain, vuln_type: str) -> bool:
        if vuln_type == "Arbitrary_file_access_CWE_22":
            json_result = self.type_check(self.Arbitrary_file_access_prompt, vuln_chain)
        elif vuln_type == "Authentication_bypass_CWE_287":
            json_result = self.type_check(self.Authentication_bypass_prompt, vuln_chain)
        elif vuln_type == "Buffer_overflow_CWE_119":
            json_result = self.type_check(self.Buffer_overflow_prompt, vuln_chain)
        elif vuln_type == "Command_injection_CWE_78":
            json_result = self.type_check(self.Command_injection_prompt, vuln_chain)
        elif vuln_type == "Integer_overflow_CWE_190":
            json_result = self.type_check(self.Integer_overflow_prompt, vuln_chain)
        elif vuln_type == "others":
            json_result = self.type_check(self.others_prompt, vuln_chain)

        if (json_result == None):
            logging.error(f"大模型结果解析失败，漏洞链条{vuln_chain.vuln_function_name}将被认为是漏洞！！！")
            result = True
            return result
        else:
            logging.debug("大模型结果解析成功！！！")
            func_name = json_result["function_name"]
            result = json_result["is_vuln"]
            vuln_cause = json_result["reason"]
            logging.info(f"漏洞函数名称：{func_name}")
            logging.info(f'漏洞链条：{vuln_chain.vuln_chain_function_list}')
            logging.info(f'漏洞判定结果：{result}')
            logging.info(f'漏洞成因：{vuln_cause}')
        # 这里有可能传过来的漏洞名称和模型判断出来的漏洞名称不一致
        if func_name != str(vuln_chain.vuln_function_name):
            logging.error(f"方法{vuln_chain.vuln_function_name}和模型判断漏洞方法不一致！模型判断方法为:{func_name}")
            logging.error(f"将认为它不是漏洞！")
            return False
        return result

    """
    根据类型做检查
    """

    def type_check(self, prompt: str, vuln_chain: VulnChain):
        logging.debug(f"开始进行检查")
        count = 0
        logging.debug(vuln_chain.vuln_chain_body)
        while (count < Config.retry_times):
            count += 1
            llm_output = self.llm.communicate(prompt, vuln_chain.vuln_chain_body)
            logging.debug(f"大模型返回结果:{llm_output}")
            json_result = self.resolve_output(llm_output)
            if json_result is not None:
                return json_result
            logging.warning(f"漏洞判断结果解析失败，尝试第{count}/{Config.retry_times}次重试...")
        logging.error("所有重试均失败，返回None")
        return None

    """
    二次检查是否有漏洞，采取打分机制,返回当前漏洞的评分，评分按照最有可能有漏洞的方式来进行
    """

    def int_check(self, vuln_chain: VulnChain, vuln_type: str) -> int:
        if vuln_type == "Arbitrary_file_access_CWE_22":
            json_result = self.type_check(IntVulnCheckPrompt.Arbitrary_file_access_prompt, vuln_chain)
        elif vuln_type == "Authentication_bypass_CWE_287":
            json_result = self.type_check(IntVulnCheckPrompt.Authentication_bypass_prompt, vuln_chain)
        elif vuln_type == "Buffer_overflow_CWE_119":
            json_result = self.type_check(IntVulnCheckPrompt.Buffer_overflow_prompt, vuln_chain)
        elif vuln_type == "Command_injection_CWE_78":
            json_result = self.type_check(IntVulnCheckPrompt.Command_injection_prompt, vuln_chain)
        elif vuln_type == "Integer_overflow_CWE_190":
            json_result = self.type_check(IntVulnCheckPrompt.Integer_overflow_prompt, vuln_chain)
        elif vuln_type == "others":
            json_result = self.type_check(IntVulnCheckPrompt.others_prompt, vuln_chain)

        if (json_result == None):
            logging.error(f"大模型结果解析失败，漏洞链条{vuln_chain.vuln_function_name}将被认为是2分！！！")
            score = 2
            return score
        else:
            logging.debug("大模型结果解析成功！！！")
            func_name = json_result["function_name"]
            score = json_result["score"]
            vuln_cause = json_result["reason"]
            logging.info(f"漏洞函数名称：{func_name}")
            logging.info(f'漏洞链条：{vuln_chain.vuln_chain_function_list}')
            logging.info(f'漏洞分数：{score}')
            logging.info(f'漏洞成因：{vuln_cause}')
        # 这里有可能传过来的漏洞名称和模型判断出来的漏洞名称不一致
        if func_name != str(vuln_chain.vuln_function_name):
            logging.error(
                f"方法{vuln_chain.vuln_function_name}和模型判断漏洞方法不一致！模型判断方法为:{func_name}，将以{vuln_chain.vuln_function_name}方法为准")
        return score

    """
    二次检查是否有漏洞，采取打分机制,返回当前漏洞的评分，评分按照最有可能有漏洞的方式来进行
    """

    def int_check_new(self, vuln_chain: VulnChain, vuln_type: str) -> int:
        if vuln_type == "Arbitrary_file_access_CWE_22":
            json_result = self.type_check(IntVulnCheckPrompt.Arbitrary_file_access_prompt, vuln_chain)
        elif vuln_type == "Authentication_bypass_CWE_287":
            json_result = self.type_check(IntVulnCheckPrompt.Authentication_bypass_prompt, vuln_chain)
        elif vuln_type == "Buffer_overflow_CWE_119":
            json_result = self.type_check(IntVulnCheckPrompt.Buffer_overflow_prompt, vuln_chain)
        elif vuln_type == "Command_injection_CWE_78":
            json_result = self.type_check(IntVulnCheckPrompt.Command_injection_prompt, vuln_chain)
        elif vuln_type == "Integer_overflow_CWE_190":
            json_result = self.type_check(IntVulnCheckPrompt.Integer_overflow_prompt, vuln_chain)
        elif vuln_type == "others":
            json_result = self.type_check(IntVulnCheckPrompt.others_prompt, vuln_chain)

        if (json_result == None):
            logging.error(f"大模型结果解析失败，漏洞链条{vuln_chain.vuln_function_name}将被认为是2分！！！")
            score = 3
            func_name = vuln_chain.vuln_function_name
            return func_name, vuln_chain.vuln_function_name, score
        else:
            # 这里有可能找不到key值
            try:
                func_name = json_result["function_name"]
                score = json_result["score"]
                vuln_cause = json_result["reason"]
                logging.debug("大模型结果解析成功！！！")
            except:
                logging.error("解析key值失败，设置为默认值")
                func_name = ""
                score = 2
                vuln_cause = ""
            logging.info(f"漏洞函数名称：{func_name}")
            logging.info(f'漏洞链条：{vuln_chain.vuln_chain_function_list}')
            logging.info(f'漏洞分数：{score}')
            logging.info(f'漏洞成因：{vuln_cause}')
        # 这里有可能传过来的漏洞名称和模型判断出来的漏洞名称不一致
        if func_name != str(vuln_chain.vuln_function_name):
            logging.error(f"方法{vuln_chain.vuln_function_name}和模型判断漏洞方法不一致！模型判断方法为:{func_name}。")
        return func_name, vuln_chain.vuln_function_name, score

    def resolve_output(self, content: str):
        # 解析大模型返回结果，有可能为None
        if content == None:
            return None
        logging.info("开始解析大模型返回结果")
        pattern = r"```json\s*({.*?})\s*```"
        # 如果匹配到了md格式的``，则正则匹配，没有的话就直接json.loads()解析
        try:
            match = re.search(pattern, content, re.DOTALL)
            if match:
                json_str = match.group(1).strip()
                json_obj = json.loads(json_str)
            else:
                json_obj = json.loads(content)
            return json_obj
        except json.JSONDecodeError as e:
            return None


class SummaryExtractor:

    def extract_function(function: Function):
        function_body = function.body
        token_number = llmbase.token_num(function_body)
    # if function_body > 2500:


"""

"""


class ParamsAndBodyTravel:
    def __init__(self, functions):
        self.all_funtion_list = {func.name: func for func in functions}
        self.processed_functions = set()  # 全局集合，用于记录已处理的函数

    def audit_vulnerability_chain(self, vuln_chain: [VulnChain]):
        """
        先反转vuln_chain因为vuln_chain是单链结构所以直接顺序遍历找父节点
        reverse_traverse越界判断（parent是否存在）在处理节点处处理：抛出异常说明到结尾

        然后正向遍历forward_traverse
        """
        # 反向遍历：从链的尾部开始，依次遍历到链头
        for i in range(len(vuln_chain.vuln_chain_function) - 1, 0, -1):
            child = vuln_chain.vuln_chain_function[i]
            parent = vuln_chain.vuln_chain_function[i - 1]
            self.reverse_traverse(child, parent)  # 反向遍历：传递 child 和 parent

        # 现在这里修改结合test内容
        return self.analyze(vuln_chain.vuln_chain_function[0], vuln_chain)  # 正向遍历：逐个传递 function

    def extract_taint_actions(self, function):
        extractor = TaintExtractor(function)
        extractor.extract()

        # 检查是否为 bytes 类型并转换为字符串
        if isinstance(function.node, bytes):
            function.node = function.node.decode('utf-8')

        if function.node:
            return function.node.splitlines()
        return []

    def build_call_tree(self, function, vuln_chain):
        # 判断是否已经处理过
        if function.name in self.processed_functions:
            print(f"⚠️ Detected duplicate function {function.name}, skipping.")
            return None  # 不再返回任何信息

        # 标记为已处理
        self.processed_functions.add(function.name)
        taint_actions = self.extract_taint_actions(function)

        node = {
            "function": function.name,
            "taint_params": function.tainted_params,
            "taint_actions": taint_actions,
            "calls": []
        }

        # 使用vuln_chain_function_list来确定调用顺序
        if vuln_chain and function.name in vuln_chain.vuln_chain_function_list:
            current_index = vuln_chain.vuln_chain_function_list.index(function.name)
            if current_index + 1 < len(vuln_chain.vuln_chain_function_list):
                next_function_name = vuln_chain.vuln_chain_function_list[current_index + 1]
                if next_function_name in self.all_funtion_list:
                    child_function = self.get_function_by_name(vuln_chain.vuln_chain_function, next_function_name)
                    child_node = self.build_call_tree(child_function, vuln_chain)
                    if child_node is not None:
                        node["calls"].append(child_node)

        self.find_and_append_clean_functions(node, function, vuln_chain)
        return node

    def get_function_by_name(self, function_list, target_name):
        for func in function_list:
            if func.name == target_name:
                return func
        return None

    def find_and_append_clean_functions(self, node, function, vuln_chain):
        for action in node["taint_actions"]:
            # 去掉正则匹配，直接获取调用的函数名
            called_function_name = action.split('(')[0].strip()

            # 检查函数是否存在且不在漏洞链中
            if called_function_name in self.all_funtion_list and (
                    not vuln_chain or called_function_name not in vuln_chain.vuln_chain_function_list):
                clean_function = self.all_funtion_list[called_function_name]

                # 获取实参列表
                args_str = action[action.find('(') + 1:action.find(')')]
                call_args_list = [arg.strip() for arg in args_str.split(',')]

                # 构造 clean 的形参 和 handler 的实参的映射
                param_binding = {
                    param_name: arg_name
                    for param_name, arg_name in zip(clean_function.param_list, call_args_list)
                }

                # 判断 clean 函数哪些参数是污点
                tainted_param_indices = [
                    idx for idx, param in enumerate(clean_function.param_list)
                    if param_binding.get(param) in function.tainted_params
                ]

                if not tainted_param_indices:
                    continue  # 没有污点参数则跳过

                print(
                    f"✅ Detected function call with tainted parameters: {called_function_name}, Positions: {tainted_param_indices}")

                # 标记对应位置的参数为污点参数
                for i in tainted_param_indices:
                    if i < len(clean_function.param_list):
                        param_name = clean_function.param_list[i]
                        print(f"⚠️ Marking {param_name} as tainted in function {called_function_name}.")
                        clean_function.add_tainted_param(param_name)

                # 构建调用树
                clean_node = self.build_call_tree(clean_function, vuln_chain)
                if clean_node is not None:
                    node['calls'].insert(0, clean_node)

    def analyze(self, entry_point, vuln_chain):
        try:
            return self.build_call_tree(entry_point, vuln_chain)
        except RecursionError as e:
            print(f"❗ Fatal RecursionError: {e}")
            return None

    def reverse_traverse(self, child: Function, parent: Function):
        """
        """
        if not child.tainted_params or not child.param_list:
            return

        tainted_args = set()
        try:
            parent_body = parent.body.decode("utf-8").strip().splitlines()
        except Exception as e:
            print(f"解码失败: {e}")
            return

        # 正则匹配调用 child.name 的位置，并捕获参数
        pattern = re.compile(rf"{re.escape(child.name)}\s*\((.*?)\)")

        for line in parent_body:
            match = pattern.search(line)
            if not match:
                continue

            args = [arg.strip() for arg in match.group(1).split(",")]

            # 根据参数位置匹配 child 的污点参数
            for i, formal_param in enumerate(child.param_list):
                if formal_param in child.tainted_params and i < len(args):
                    real_arg = args[i]
                    print(f"检测到污点参数传递: {formal_param} -> {real_arg}")
                    tainted_args.add(real_arg)

        if tainted_args:
            parent.tainted_params.extend(list(tainted_args))
            parent.tainted_params = list(set(parent.tainted_params))
            print(f"更新后的污点参数: {parent.tainted_params}")

    # 定义函数：接受两个 Function 对象，生成 JSON


class CodeChainTravel:
    def __init__(self):
        # todo  完成提示词
        self.llm = llmbase.LLM()
        self.CodeChainTravelPrompt = FunctionParsePrompt.code_chain_travel_prompt  # 还没添加,将codechain交给大模型判断漏洞原因

    def resolve_output(self, content: str):
        # 解析大模型返回结果，有可能为None
        if content == None:
            return None
        logging.info("开始解析大模型返回结果")
        pattern = r"```json\s*({.*?})\s*```"
        # 如果匹配到了md格式的``，则正则匹配，没有的话就直接json.loads()解析
        try:
            match = re.search(pattern, content, re.DOTALL)
            if match:
                json_str = match.group(1).strip()
                json_obj = self.fix_json_escape(json_str)
                json_obj = json.loads(json_obj)
            else:
                content = self.fix_json_escape(content)
                json_obj = json.loads(content)
            return json_obj
        except json.JSONDecodeError as e:
            logging.error("JSON格式解析错误:", e)
            return None

    def fix_json_escape(self, json_str: str) -> str:
        """
        将 JSON 字符串中的所有 \' 改为 '。
        """
        return json_str.replace(r"\'", "'")

    def generate_prompt(self, node_data, vuln_type):
        """
        根据漏洞链数据生成提示词
        """
        return self.CodeChainTravelPrompt.format(
            node_data=json.dumps(node_data, indent=2),
            vuln_type=vuln_type
        )

    def analysis_chain(self, node_data, vuln_type):
        """
        使用 LLM 分析漏洞链并返回结果，将分析结果附加到原始 JSON 数据
        """
        try:
            prompt = self.generate_prompt(node_data, vuln_type)
            count = 0
            llm_output = self.llm.communicate(prompt, None)
            llm_output = self.resolve_output(llm_output)
            while count <= Config.retry_times:
                if llm_output is None:
                    logging.info(f"大模型结果漏洞分析失败，第{count}次尝试重新请求大模型:")
                    count = count + 1
                    # time.sleep(5)  # 增加延迟时间，指数回退
                    llm_output = self.llm.communicate(prompt, None)
                    llm_output = self.resolve_output(llm_output)
                else:
                    print("大模型分析成功。")
                    node_data["漏洞分析"] = llm_output.get("漏洞分析", {})
                    return node_data
                if llm_output is not None:
                    print("大模型分析成功。")
                    node_data["漏洞分析"] = llm_output.get("漏洞分析", {})
                    return node_data

                count += 1
                logging.info(f"大模型结果解析失败，第 {count} 次重试...")
                llm_output = self.llm.communicate(prompt)

            logging.error("所有重试均失败，无法获取大模型结果。")
            return node_data

        except Exception as e:
            logging.error(f"LLM 分析时出现异常: {str(e)}")
            return node_data
