#计算最终分数
def get_final_score(out_root):
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


get_final_score("/home/nstl/datacon/upload/results/")