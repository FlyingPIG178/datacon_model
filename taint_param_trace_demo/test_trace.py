
import re

class Function:
    def __init__(self, name, body, param_list):
        self.name = name
        self.body = body  # 函数体字符串
        self.param_list = param_list  # 形参列表
        self.tainted_params = []
        self.node = ""

    def add_tainted_param(self, param):
        if param not in self.tainted_params:
            self.tainted_params.append(param)

def trace_taint_to_parent(child: Function, parent: Function):
    if not child.tainted_params or not hasattr(child, "param_list"):
        return

    tainted_args = set()
    pattern = re.compile(rf"{child.name}\s*\((.*?)\)")

    lines = parent.body.strip().splitlines()
    for line in lines:
        match = pattern.search(line)
        if not match:
            continue

        args = [arg.strip() for arg in match.group(1).split(",")]
        for i, formal_param in enumerate(child.param_list):
            if formal_param in child.tainted_params and i < len(args):
                real_arg = args[i]
                tainted_args.add(real_arg)

    if tainted_args:
        parent.tainted_params.extend(list(tainted_args))
        parent.tainted_params = list(set(parent.tainted_params))

# 模拟代码结构
parent_body = """
def parent():
    user = "admin"
    secret = input()
    child(user, secret)
"""

child_body = """
def child(param1, param2):
    eval(param2)
"""

# 创建 Function 对象
parent_fn = Function(name="parent", body=parent_body, param_list=[])
child_fn = Function(name="child", body=child_body, param_list=["param1", "param2"])
child_fn.tainted_params = ["param2"]  # 模拟 param2 是 tainted 参数

# 执行静态参数传递分析
trace_taint_to_parent(child_fn, parent_fn)

# 输出结果
print("✅ 传递完成后，parent 中的 tainted 参数为：", parent_fn.tainted_params)
