import os
import logging
import traceback
from Challenge import Challenge
from libs.config import Config

# 设置日志格式（只设置一次）
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def analyze_challenge(root_path: str, vuln_type: str, filename: str):
    """
    对某个具体漏洞类型下的指定题目进行分析

    :param root_path: 数据根目录
    :param vuln_type: 漏洞类型文件夹名，例如 Command_injection_CWE_78
    :param filename: 某个具体题目的文件夹名，例如 "1"、"s01"
    """
    challenge = get_challenge(root_path, vuln_type, filename)

    if not challenge:
        logging.error(f"无法获取 Challenge: {os.path.join(root_path, vuln_type, filename)}")
        return

    try:
        logging.info(f"开始分析 {vuln_type} 类型题目: {challenge.challenge_dir}")
        run_single_challenge(challenge)
    except Exception as e:
        logging.error(f"解析题目 {challenge.challenge_dir} 失败！ {e}")
        logging.error(traceback.format_exc())


def run_single_challenge(challenge: Challenge):
    """
    分析单个 Challenge 实例
    """
    try:
        challenge.parse_files()
        challenge.analysis_functions()
        challenge.generate_call_graph()
        challenge.generate_vul_chains()
        challenge.travel_Params_And_Body()
        challenge.code_chain_generate()
        # challenge.check_vul_chains_by_score_new()
        # challenge.save_result(output_path)
    except Exception as e:
        logging.error(f"解析题目 {challenge.challenge_dir} 失败!")
        logging.error(traceback.format_exc())
        logging.error("开启大力出奇迹模式!!!")
        challenge.da_li_chu_qi_ji()


def get_challenge(root_path, vuln_type, filename) -> Challenge | None:
    """
    获取单个 Challenge 对象
    """
    file_path = os.path.join(root_path, vuln_type, filename)
    if not os.path.isdir(file_path):
        logging.error(f"题目路径不存在: {file_path}")
        return None

    logging.debug(f"开始加载 Challenge：{file_path}")
    challenge = Challenge(file_path, vuln_type)
    logging.info(f"Challenge 加载成功：{file_path}")
    return challenge

if __name__ == '__main__':
    analyze_challenge(
        root_path="F:/juliet/datacon_model/vlun_demo",
        vuln_type="Command_injection_CWE_78",
        filename="1"
    )