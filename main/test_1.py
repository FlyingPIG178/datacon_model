from Challenge import Challenge
from libs.objects import Function
from libs.utils import BlockFileParser
from main import run_single_vul_type
from Challenge import ChallengeFile
from libs.utils import FileParser
import os



def Arbitrary_file_access_test():
    run_single_vul_type("Arbitrary_file_access")


def Challenge_test(target_dir,vuln_type):
    Challenge()


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

#计算单类题目分数
def get_score(ans_path, out_path):
    with open(ans_path, 'r') as file:
        ans = file.readlines()
    with open(out_path, 'r') as file:
        out = file.readlines()
    ans_set = set(ans)
    out_set = set(out)
    TP = len(ans_set & out_set)
    if TP == 0:
        return 0
    FN = len(ans_set - out_set)
    FP = len(out) - TP
    Precision = TP/(TP+FP)
    Recall = TP/(TP+FN)
    score = (2*Precision*Recall)/(Precision+Recall)
    print(f'TP {TP};FN {FN}; FP {FP}')
    return score

#计算最终分数
def get_final_score(out_dir):
    file_list = ['Arbitrary_file_access','Authentication_bypass','Buffer_overflow','Command_injection','Integer_overflow','others']
    ans_root = '/home/nstl/datacon/example/answer_example/'
    file_name = '/answer.txt'
    score = 0
    for file in file_list:
        print(f'{file} Score:')
        ans_dir = ans_root + file + file_name
        out_dir = out_root + file + file_name
        temp = get_score(ans_dir,out_dir)
        print(temp)
        score += temp
    print('Total Score:')
    print(score/6)
    return score/6

parse_prompt = '''
#设定：你是一个

'''



if __name__ == "__main__":
    out_root = '/home/nstl/datacon/main/test_result/result6/'
    get_final_score(out_root)
