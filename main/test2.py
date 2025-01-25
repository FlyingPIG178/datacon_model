import json
import logging
import re


def resolve_output(content: str):
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

if __name__ == '__main__':
    content="""
    '```json
{
    "codes": [
        "if filter_input(user_input):\\n        user_input = requests.get(url)",
        "print(f\\"{user_input}\\")",
        "output = execute_command(user_input)",
        "print(output)"
    ]
}
```'
    """
    json_result = resolve_output(content)
    codes = json_result["codes"]