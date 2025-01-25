import glob
import logging
import os

from tree_sitter import Language, Parser
import tree_sitter_c
import tree_sitter_cpp
from Challenge import Challenge
from libs.objects import Function, VulnChain
from libs.utils import BlockFileParser
from main import run_single_vul_type
from main import run_single_challenge
from libs.llmService import FunctionAnalyser, FunctionParser, VulnChecker
from libs.prompt import FunctionAnalysisPrompt, IntVulnCheckPrompt
from libs.llmbase import LLM, token_num 


logging.basicConfig(filename="/home/nstl/datacon/function_log",filemode='a',level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def calToken(text):
    a = token_num(text)
    print(a)

def Arbitrary_file_access_test():
    run_single_vul_type("Arbitrary_file_access")

def Authentication_bypass_test():
    run_single_vul_type("Authentication_bypass")

def Buffer_overflow_test():
    run_single_vul_type("Buffer_overflow")

def Command_injection_test():
    run_single_vul_type("Command_injection")

def Integer_overflow_test():
    run_single_vul_type("Integer_overflow")

def others_test():
    run_single_vul_type("others")

def test_target_challenge(challenge_dir,challenge_type):
    challenge = Challenge(challenge_dir,challenge_type)
    #进行文件解析，初始化方法列表，只提取方法体，方法名和调用点空起来，全部交给大模型判断
    run_single_challenge(challenge)

def Arbitrary_file_access_test():
    run_single_vul_type("Arbitrary_file_access")

def Challenge_test(target_dir,vuln_type):
    Challenge()

def functionAnalysisTest():
    f = Function("dhcp6_get_options",function_content)
    prompt = FunctionAnalysisPrompt.Buffer_overflow_prompt
    result = FunctionAnalyser().type_analysis(prompt,f)
    print(result)


def vul_chain_test():
    v = VulnChain("dhcp6_get_options",vuln_chain_content,["dhcp6_get_options"])
    result = VulnChecker().type_check(IntVulnCheckPrompt.Buffer_overflow_prompt,v)
    print(result)


#括号匹配切片测试
def cc_cut_test():
    bfp = BlockFileParser()
    c = Challenge("/home/nstl/datacon/examples/dataset_example/Buffer_overflow/1","NONE")
    functions:list[Function]
    functions = bfp.parse(c.file_list[0])
    for function in functions:
        print("===============================================")
        print(function.name)
        print(function.body)
        print(function.call_site_list)


sysprompt= """
    #设定
    你是一个分析经验丰富的代码逆向分析人员，能够精准优化和还原函数。
    #输入
    ##函数代码片段：<包含了反编译伪代码，C，C++>
    #任务
    1.找到代码中容易引发内存安全的操作
    2.找到代码中，和这些不安全的内存操作相关的控制流信息和数据流信息
    3.根据这些数据流和控制流信息，仅仅提取出与他们有关的代码片段
    4. 让我们一步步地进行推理。
    #输出结果
    请务必严格按照以下JSON格式返回分析结果，请确保生成格式正确的结果：
    ```json
        优化后的代码
    }```
    #限制
    1. 输出结果以JSON的纯文本形式返回,除json外不要返回任何内容,确保JSON格式标准化，输出前后无多余空行或注释，严格按照要求格式输出。
    """




def process_c_file(file):
    language: Language = Language(tree_sitter_cpp.language())
    parser: Parser = Parser(language)

    with open(file, "r", encoding="utf-8") as cFile:
        code = cFile.read()
        tree = parser.parse(bytes(code, "utf-8"))
    root_node = tree.root_node
    for node in root_node.children:
        logging.info("===============================================")
        logging.info(node.text)

def traverse_c_files():
    # 使用 glob 模块找到所有 .c 文件
    c_files = glob.glob(os.path.join("/home/nstl/datacon/example/dataset_example/", '**/*.c'), recursive=True)
    # 遍历每个 .c 文件
    for file_path in c_files:
        process_c_file(file_path)
        logging.info("===============================================")
        logging.info("===============================================")
        logging.info("===============================================")
        logging.info("===============================================")

def da_li_chu_qi_ji(challenge:Challenge):
        pass

if __name__ == "__main__":
    #test_target_challenge("/home/nstl/datacon/example/dataset_example/Command_injection/3","Command_injection")
    #Command_injection_test()
    #calToken(fucker)
    #Integer_overflow_test()
    #others_test()
    #Buffer_overflow_test()
    traverse_c_files()