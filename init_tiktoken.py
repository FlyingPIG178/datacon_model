# init_tiktoken.py
import tiktoken

# 这里可以添加你需要的初始化逻辑
print("tiktoken version:", tiktoken.__version__)

#计算大模型输入内容的token数
def token_num(text):
    try:
        # 加载编码器
        encoding = tiktoken.get_encoding("cl100k_base")
        # 编码文本
        tokens = encoding.encode(text)
        # 获取 token 数
        num_tokens = len(tokens)
        return num_tokens
    except Exception as e:
        return None


print(token_num("this is a test!!!"))