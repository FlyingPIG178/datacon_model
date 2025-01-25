import json
import logging
import re
import time
from typing import Tuple, Dict, List, Any

from . import llmbase
from .objects import Function, VulnChain, CodeChain
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

    def get_function_name_and_callsites(self, function_body) -> Tuple[str, list[str]]:
        count = 0
        # 如果json是None，则说明无法正确解析，重新和大模型沟通,上线次数写到了config里面
        while count <= Config.retry_times:
            count += 1
            llm_output = self.llm.communicate(self.function_parse_prompt, function_body)
            json_result = self.resolve_output(llm_output)
            time.sleep(5)
            if json_result is None:
                logging.error(f"大模型结果无法转化为json格式，第{count}次尝试重新请求大模型:")
            else:
                # 返回结果成功了，也不一定能正常解析，所以这里要加一个try
                try:
                    function_name = json_result["function_name"]
                    call_sites = json_result["call_sites"]
                    return function_name, call_sites
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
                json_obj = json.loads(json_str)
            else:
                json_obj = json.loads(content)
            return json_obj
        except json.JSONDecodeError as e:
            logging.error("JSON格式解析错误:", e)
            return None

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
                if vuln_type == "Arbitrary_file_access":
                    json_result = self.type_analysis(self.Arbitrary_file_access_prompt, function)
                elif vuln_type == "Authentication_bypass":
                    json_result = self.type_analysis(self.Authentication_bypass_prompt, function)
                elif vuln_type == "Buffer_overflow":
                    json_result = self.type_analysis(self.Buffer_overflow_prompt, function)
                elif vuln_type == "Command_injection":
                    json_result = self.type_analysis(self.Command_injection_prompt, function)
                elif vuln_type == "Integer_overflow":
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
                    if vuln_type == "Arbitrary_file_access":
                        function.type["input"] = json_result["input"]
                        function.type["file_read"] = json_result["file_read"]
                    elif vuln_type == "Authentication_bypass":
                        function.type["input"] = json_result["input"]
                        function.type["authentication"] = json_result["authentication"]
                    elif vuln_type == "Buffer_overflow":
                        function.type["input"] = json_result["input"]
                        function.type["memoryOP"] = json_result["memoryOP"]
                    elif vuln_type == "Command_injection":
                        function.type["input"] = json_result["input"]
                        function.type["command"] = json_result["command"]
                    elif vuln_type == "Integer_overflow":
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
                time.sleep(5)  # 增加延迟时间，指数回退
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
        if vuln_type == "Arbitrary_file_access":
            json_result = self.type_check(self.Arbitrary_file_access_prompt, vuln_chain)
        elif vuln_type == "Authentication_bypass":
            json_result = self.type_check(self.Authentication_bypass_prompt, vuln_chain)
        elif vuln_type == "Buffer_overflow":
            json_result = self.type_check(self.Buffer_overflow_prompt, vuln_chain)
        elif vuln_type == "Command_injection":
            json_result = self.type_check(self.Command_injection_prompt, vuln_chain)
        elif vuln_type == "Integer_overflow":
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
        if vuln_type == "Arbitrary_file_access":
            json_result = self.type_check(IntVulnCheckPrompt.Arbitrary_file_access_prompt, vuln_chain)
        elif vuln_type == "Authentication_bypass":
            json_result = self.type_check(IntVulnCheckPrompt.Authentication_bypass_prompt, vuln_chain)
        elif vuln_type == "Buffer_overflow":
            json_result = self.type_check(IntVulnCheckPrompt.Buffer_overflow_prompt, vuln_chain)
        elif vuln_type == "Command_injection":
            json_result = self.type_check(IntVulnCheckPrompt.Command_injection_prompt, vuln_chain)
        elif vuln_type == "Integer_overflow":
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
        if vuln_type == "Arbitrary_file_access":
            json_result = self.type_check(IntVulnCheckPrompt.Arbitrary_file_access_prompt, vuln_chain)
        elif vuln_type == "Authentication_bypass":
            json_result = self.type_check(IntVulnCheckPrompt.Authentication_bypass_prompt, vuln_chain)
        elif vuln_type == "Buffer_overflow":
            json_result = self.type_check(IntVulnCheckPrompt.Buffer_overflow_prompt, vuln_chain)
        elif vuln_type == "Command_injection":
            json_result = self.type_check(IntVulnCheckPrompt.Command_injection_prompt, vuln_chain)
        elif vuln_type == "Integer_overflow":
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
    def __init__(self):
        # todo  完成提示词
        self.llm = llmbase.LLM()
        self.params_travel_prompt = FunctionParsePrompt.params_travel_prompt  # 还没添加
        self.body_travel_prompt = FunctionParsePrompt.body_travel_prompt  # 还没添加

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

        # 正向遍历：从链头开始，依次遍历到链尾
        for function in vuln_chain.vuln_chain_function:
            self.forward_traverse(function)  # 正向遍历：逐个传递 function

    def extract_tainted_code(self, function: Function):
        # 假设这个方法会返回包含污点参数的代码片段
        result = self.to_json(function, function, False)
        # 这里使用调用大模型，传入提示词和代码体比如结果就是vuln_codes
        """传入参数为：提示词，self.body,self.tainted_params"""
        count = 0
        while count <= Config.retry_times:
            count += 1
            llm_output = self.llm.communicate(self.body_travel_prompt, result)
            json_result = self.resolve_output(llm_output)
            time.sleep(5)
            if json_result is None:
                logging.error(f"大模型获取污点代码片段结果无法转化为json格式，第{count}次尝试重新请求大模型:")
            else:
                # 返回结果成功了，也不一定能正常解析，所以这里要加一个try
                try:
                    codes = json_result["codes"]
                    for code in codes:
                        function.node += code + "\n"
                    break
                except Exception as e:
                    logging.error(f"无法解析function_name和call_sites，第{count}次尝试重新请求大模型:")
                break

    def resolve_output(self,content: str):
        # 解析大模型返回结果，有可能为None
        if content is None:
            return None

        logging.debug("开始解析大模型返回结果")

        # 正则模式：匹配可能存在的Markdown格式的JSON对象（大括号）
        pattern = r"```json\s*({.*?})\s*```"  # 只匹配JSON对象（大括号）

        try:
            # 尝试匹配Markdown格式的JSON代码块
            match = re.search(pattern, content, re.DOTALL)
            if match:
                # 提取匹配的 JSON 部分并转换为字典或列表
                json_str = match.group(1).strip()

                json_obj = json.loads(json_str)
            else:
                # 如果没有Markdown格式，则直接尝试解析纯JSON格式
                json_obj = json.loads(content)

            # 确保返回的是一个符合格式要求的字典
            if isinstance(json_obj, dict):
                return json_obj  # 返回解析后的字典
            else:
                logging.error("返回的不是一个有效的字典")
                return None

        except json.JSONDecodeError as e:
            # 错误信息格式化
            logging.error("JSON格式解析错误: %s", e)
            return None

    def forward_traverse(self, function: Function):
        """
        正向遍历，提取与污点参数相关的代码片段
        实际是调用self. extract_tainted_code
        将当前Fuction的污点参数数组和代码片段交给大模型提取相关代码片段
        所得代码片段加入self.node
        参数为当前函数体，当前函数污点参数，提示词
        结果:为当前函数添加污点参数相关代码
        """
        self.extract_tainted_code(function)

    def reverse_traverse(self, child: Function, parent: Function):
        """
        反向递归遍历，传递当前子节点的污点参数给父节点。这里还要处理，如何让ai明白形参和实参的区别并联系起来
        只会处理一个父节点（vuln_chain是单链表结构）。
        这里需要在处理节点代码处反向遍历vuln_chain,将相邻节点传给这个函数
        越界判断（parent是否存在）在处理节点处处理
        结果:为父节点添加五点参数列表
        现在直接把child和parent传进去，具体需要什么值具体调用
        """
        if parent:
            # 将当前子节点的污点参数传递给父节点
            """
            传入参数为child.tainted_params,parent
            """
            result = self.to_json(child, parent, True)
            try:
                count = 0
                while count <= Config.retry_times:
                    llm_output = self.llm.communicate(self.params_travel_prompt,
                                                      result)  # 大模型判断parent中和child的污点参数有关的参数parent_param
                    js_obj = self.resolve_output2(llm_output)
                    count += 1  # 提示词还没写
                    if js_obj is None:
                        logging.info(f"大模型结果解析污点参数传递失败，第{count}次尝试重新请求大模型:")
                        time.sleep(5)  # 增加延迟时间
                        llm_output = self.llm.communicate(self.params_travel_prompt, result)
                        js_obj = self.resolve_output2(llm_output)
                    else:
                        parent.add_tainted_param(js_obj)#再看看
                        break
            except Exception as e:
                logging.error(f"无法传递无污点参数，第{count}次尝试重新请求大模型:")

    # 定义函数：接受两个 Function 对象，生成 JSON
    def resolve_output2(self, content: str):
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

    def to_json(self, child: Function, parent: Function, switch: bool) -> dict[str, str | Any] | dict[str, str | Any]:
        """
        开关为true传递污点参数，开关为False提取和污点参数有关的代码
        """
        if switch:
            result = {
                "function_snippet": parent.body,
                "called_function_name": child.name,
                "tainted_parameters": child.tainted_params
            }
        else:
            result = {
                "function_snippet": parent.body,
                "tainted_parameters": parent.tainted_params
            }
        return result


class CodeChainTravel:
    def __init__(self):
        # todo  完成提示词
        self.llm = llmbase.LLM()
        self.CodeChainTravelPrompt = FunctionParsePrompt.code_chain_travel_prompt  # 还没添加,将codechain交给大模型判断漏洞原因

    def chain_generate(self, vulnChain: VulnChain):
        """链条，sink信息"""
        vulnChain.generate_mini_chain()

    def to_json(self, chain: VulnChain, sink: Function):
        """
        json组成为chain的VulnCodes，sink的name和sink的参数列表
        """
        vuln_entry = {
            "VulnCode": chain.mini_chain,
            "sink": {
                "name": sink.name,
                "call_site_list": sink.tainted_params
            }
        }
        return json.dumps(vuln_entry, indent=4, ensure_ascii=False)

    def analysis_chain(self, input: str):  # 可以用json不
        llm_output = self.llm.communicate(self.CodeChainTravelPrompt, input)
        return llm_output
