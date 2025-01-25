#!/usr/local/bin/python3
import traceback
import requests
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
import os
import json
import time
import warnings
import re
import time
from langchain.memory import ConversationTokenBufferMemory, ConversationSummaryMemory
from langchain.chains import ConversationChain
import json
import networkx as nx
import matplotlib.pyplot as plt
import tiktoken
from .config import Config
import logging

#测试模式使用官方api
test_mode =  Config().test_mode
if (not test_mode):
    openai_api_key=os.getenv('API_KEY')
    openai_api_base=os.getenv('API_BASE')
    model_name='tq-gpt'
else:
    openai_api_key= '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'
    openai_api_base='https://api.openai.com/v1'
    model_name='gpt-4'
#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

class LLM():

    def __init__(self):
        self.llm_with_memory = LLM_MEMORY()
        self.llm_without_memory = LLM_WITHOUT_MEMORY()

    
    def communicate(self,system_message,humen_message) -> str:
        """
        调用大模型api输入pro和用户输入，返回大模型的回复
        """
        total_message = str(system_message) + str(humen_message)
        token_number = token_num(total_message)
        output = ""
        if(token_number > 8000):
            logging.warning("token量大于8000！！！直接pass掉！！！")
            logging.debug(total_message)
            return None
        else:
            logging.debug("token量小于8000，采用无记忆会话！！！")  
            logging.debug(system_message)   
            logging.debug(humen_message)
            output = self.llm_without_memory.chat(system_message,str(humen_message))
        #output可能为None
        
        logging.info(f"大模型返回：{output}")

        return output
    """
    根据prompt的编写：
    判断调用链中是否存判断该函数代码是否包含网络报文的处理，如web请求处理、网络协议请求处理、api请求处理、数据库请求处理等来部网络消息的处理。在对不受信任的外部数据的解析和处理（如web请求处理、网络协议请求处理、api请求处理、数据库请求处理等来自外部消息的请求处理。
    结合Object::Fuction的定义，是调用api获取函数信息字典
    """

   





#调用大模型进行单次对话，SystemMessage设定中的指令遵循能力较好
class LLM_WITHOUT_MEMORY():
    def __init__(self) -> None:
        #初始化大模型
        self.llm = ChatOpenAI(
        streaming=True,
        verbose=True,
        # key和base开赛后提供
        #openai_api_key = openai_api_key,
        #openai_api_base = openai_api_base,
        #model_name = model_name,
        openai_api_key='sk-X2p7786OjJhhTPlkxr70F8QdK2qmxrK4PsA4inmJWqxyhAeu',
        openai_api_base='https://api.moonshot.cn/v1',
        model_name='moonshot-v1-8k',
        timeout=300
        )
        self.count = 0

    #同时输入SystemMessage和HumanMessage    
    def chat(self,syscontent,humancontent):
        """
        系统消息，定义对话的上下文或模型的角色.用户消息，表示用户的输入内容
        """
        try:
            Message1 = SystemMessage(syscontent)
            Message2 = HumanMessage(humancontent)
            Message = [Message1, Message2]
            output = self.llm(Message)
            """
            传递消息列表
            消息列表 Message 被作为输入传递给 self.llm。
            模型根据消息的类型和内容，理解上下文并生成响应。
            
            模型生成响应
            模型会逐条读取 Message 中的消息。
            根据 SystemMessage 确定自己的角色。
            根据 HumanMessage 提供的用户输入生成回答。
            
            返回响应
            模型的返回值是一个对象，包含生成的响应内容：
            output.content：表示模型生成的文本内容。
            """
            #time.sleep(20)
            return output.content
        except Exception as e:
            return None

#调用大模型进行多轮对话，记忆会占用8k限制，且指令遵循能力弱
class LLM_MEMORY():
    def __init__(self) -> None:
        #初始化大模型
        self.llm = ChatOpenAI(
        streaming=True,
        verbose=True,
        # key和base开赛后提供
        openai_api_key='sk-X2p7786OjJhhTPlkxr70F8QdK2qmxrK4PsA4inmJWqxyhAeu',
        openai_api_base='https://api.moonshot.cn/v1',
        model_name='moonshot-v1-8k',
        timeout=300
        )
        self.count = 0
        #初始化会话记忆，先前的会话会以Summary的形式存储下来
        self.memory = ConversationSummaryMemory(llm=self.llm)
        #初始化保留记忆的会话链
        self.conversation = ConversationChain(llm = self.llm,memory = self.memory)
        self.output = None

    #输入内容，进行多轮对话
    def chat(self,system_message,humen_message) -> str:
        count = 0
        try:
            message_list =  self.split_string_by_length(humen_message,2000)
            self.output = self.conversation(system_message)
            for message in message_list:
                logging.info(message)
                while count <= Config.retry_times:
                    self.output = self.conversation(message)
                    logging.info("输出如下")
                    logging.info(self.output)
                    if ( self.output['response'] !=None):
                        break
            self.output = self.conversation( "综合上述所有代码内容，再次按以下要求输出结果\n" + system_message)
            return self.output['response']
        except Exception as e:  
            return None
        
    def split_string_by_length(self,s, x):
        """
        将字符串 s 切割为长度不超过 x 的子串，并返回一个列表。
        :param s: 输入字符串
        :param x: 子串的最大长度
        :return: 包含子串的列表
        """
        # 计算需要切割的次数
        num_slices = (len(s) + x - 1) // x
        # 使用列表推导式生成子串列表
        return [s[i * x:(i + 1) * x] for i in range(num_slices)]

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





#计算大模型输入内容的token数
def token_num(text):
    try:
        # 加载编码器
        encoding = tiktoken.get_encoding("cl100k_base")
        # 编码文本
        tokens = encoding.encode(text)#分词结果：["Hello", ",", " world", "!"]加载编码器 cl100k_base。4token
        # 获取 token 数
        num_tokens = len(tokens)
        return num_tokens
    except Exception as e:
        print(f"ERROR. {e}")
        return None


#提取大模型输出中的内容，转化为json对象
def out2json(content):
    # 使用正则表达式提取JSON部分，正则表达式我也改了
    #   原本的匹配字符串  r"```json\n({.*?})\n```"
    pattern = r"```json\s*({.*?})\s*```"
    match = re.search(pattern, content, re.DOTALL)
    if match:
        #我在这里加了.strip()改掉了空字符
        json_str = match.group(1).strip()
        #print(json_str)
        try:
            json_obj = json.loads(json_str)
            return json_obj
        except json.JSONDecodeError as e:
            print("JSON 解析错误:", e)
            return None
    else:
        print("未找到匹配的JSON部分")
        return None

