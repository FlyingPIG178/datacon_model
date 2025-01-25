import os
import logging
import sys
import traceback
from Challenge import Challenge, Function
from libs.config import Config

# 配置日志记录
import logging

test_mode = Config().test_mode
root_path = "F:/juliet/datacon_model/vlun_demo"
output_path = "F:/juliet/datacon_model/result"

if (test_mode):
    logging.basicConfig(filename="./log", filemode='a', level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    root_path = "/home/nstl/datacon/example/dataset_example"
    output_path = "/home/nstl/datacon/main/test_result/result6"
else:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# 解析 /vlun_demo 文件夹，拿到六类漏洞下所有的测试信息。

def main():

    vulTypes = [
        "Arbitrary_file_access",
        "Authentication_bypass",
        "Buffer_overflow",
        "Command_injection",
        "Integer_overflow",
        "others"
    ]
    for vulType in vulTypes:
        run_single_vul_type(vulType)


def run_single_vul_type(vulType):
    """
    求解一类题目
    """
    # 拿到该漏洞类型下的所有题目
    challenges = get_challenges(root_path, vulType)
    for challenge in challenges:
        try:
            logging.info("开始分析" + vulType + "类型题目: " + challenge.challenge_dir)
            run_single_challenge(challenge)
        except Exception as e:
            logging.error(f"解析题目 {challenge.challenge_dir}失败！ {e}")
            logging.error(traceback.format_exc())


def run_single_challenge(challenge: Challenge):
    """
    求解单个题目
    """
    try:
        if (len(challenge.file_list) > 5):
            logging.error(f"该挑战文件总数量为:{len(challenge.file_list)},文件数量过大！开启大力出奇迹模式！")
            challenge.da_li_chu_qi_ji()
            return
        # 进行文件解析，初始化方法列表，只提取方法体，方法名和调用点空起来，全部交给大模型判断
        challenge.parse_files()
        # 基于大模型的方法语义分析，获取Object::Function信息
        challenge.analysis_functions()
        # 生成调用图，有向图
        challenge.generate_call_graph()
        # 基于调用图进行漏洞切片，得到的是从源函数（处理输入的函数）到漏洞执行函数的切片
        challenge.generate_vul_chains()
        # 基于大模型进行漏洞调用链检查
        challenge.check_vul_chains_by_score_new()
        # 结果保存
        challenge.save_result(output_path)
    except Exception as e:
        logging.error(f"解析题目 {challenge.challenge_dir}失败!")
        logging.error(traceback.format_exc())
        logging.error("开启大力出奇迹模式!!!")
        challenge.da_li_chu_qi_ji()


def get_challenges(root_path, vuln_type) -> list[Challenge]:
    """
    找到特定类型题目文件夹下的所有题目，生成challenge对象列表并返回
    """
    challenges = []
    dir_path = os.path.join(root_path, vuln_type)  # 题目路径
    logging.debug(f"开始检索目标题目路径{dir_path}")
    for root, dirs, files in os.walk(dir_path):  # root：当前遍历的目录路径，dirs：当前目录中的子目录列表。files：当前目录中的文件列表。
        for dir in dirs:
            if root == dir_path:  # 只处理主目录下的（dir_path）
                challenge_path = os.path.join(root, dir)  # /vlun_demo/Arbitrary_file_access 文件夹下的六类漏洞文件夹的路径
                challenge = Challenge(challenge_path, vuln_type)
                challenges.append(challenge)
    logging.info(f'目标路径{dir_path}检索完毕，共发现{len(challenges)}个题目！！！')
    return challenges


if __name__ == '__main__':
    main()