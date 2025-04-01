import os
import logging
import traceback
from Challenge import Challenge
from libs.config import Config

# 配置日志记录
config = Config()
test_mode = config.test_mode
def analyze_vulnerability_type(vul_type: str, root_path: str):
    """
    分析指定类型的漏洞题目
    """
    challenges = get_challenges(root_path, vul_type)
    for challenge in challenges:
        try:
            logging.info(f"开始分析 {vul_type} 类型题目: {challenge.challenge_dir}")
            analyze_single_challenge(challenge)
        except Exception as e:
            logging.error(f"解析题目 {challenge.challenge_dir} 失败！ {e}")
            logging.error(traceback.format_exc())


def analyze_single_challenge(challenge: Challenge):
    """
    分析单个题目
    """
    try:
        challenge.parse_files()
        challenge.analysis_functions()
        challenge.generate_call_graph()
        challenge.generate_vul_chains()
        challenge.travel_Params_And_Body()
        challenge.code_chain_generate()
        # challenge.save_result(output_path)
    except Exception as e:
        logging.error(f"解析题目 {challenge.challenge_dir} 失败!")
        logging.error(traceback.format_exc())
        logging.error("开启大力出奇迹模式!!!")
        challenge.da_li_chu_qi_ji()


def get_challenges(root_path, vuln_type) -> list[Challenge]:
    """
    获取指定类型题目的 Challenge 列表
    """
    challenges = []
    dir_path = os.path.join(root_path, vuln_type)
    logging.debug(f"开始检索路径 {dir_path}")
    for root, dirs, files in os.walk(dir_path):
        for dir in dirs:
            if root == dir_path:
                challenge_path = os.path.join(root, dir)
                challenge = Challenge(challenge_path, vuln_type)
                challenges.append(challenge)
    logging.info(f'路径 {dir_path} 检索完毕，共发现 {len(challenges)} 个题目。')
    return challenges


def run_analysis(root_path: str, vul_types: list[str]):
    """
    主函数：执行多个漏洞类型的分析，仅需传入根目录和漏洞类型列表
    """
    for vul_type in vul_types:
        analyze_vulnerability_type(vul_type, root_path)


# 保留命令行入口
if __name__ == '__main__':
    default_root = (
        "F:/juliet/datacon_model/vlun_demo"
    )
    default_vul_types = [
        "Command_injection_CWE_78",
    ]
    run_analysis(default_root, default_vul_types)
