import networkx as nx
def reconstruct_execution_order(edges):
    """
    根据输入的调用顺序，模拟函数调用栈，并构建实际执行的调用顺序
    """
    call_stack = []  # 模拟函数调用栈
    execution_order = []  # 记录最终的调用顺序
    visited = set()  # 记录已处理的函数

    for caller, callee in edges:
        if caller == callee:  # 跳过自调用
            continue

        if callee not in call_stack:  # 只在第一次调用时加入栈
            call_stack.append(callee)

        if caller not in visited:
            execution_order.append(caller)
            visited.add(caller)

        if callee not in visited:
            execution_order.append(callee)
            visited.add(callee)

        # 处理返回情况
        if (callee, caller) in edges:
            while call_stack and call_stack[-1] == caller:  # 遇到返回点时出栈
                call_stack.pop()

    return execution_order

#读取用户输入的调用关系
edges = []
print("请输入调用关系（格式：A B 表示 A 调用 B，输入 'done' 结束）：")
while True:
    user_input = input("输入调用关系 (或 'done' 结束)：").strip()
    if user_input.lower() == "done":
        break
    try:
        caller, callee = user_input.split()
        edges.append((caller, callee))  # 按照输入顺序存储调用关系
    except ValueError:
        print("输入格式错误，请输入两个函数名（例如：A B）")

#构建调用图
call_graph = nx.DiGraph()
call_graph.add_edges_from(edges)

#重构执行顺序
execution_order = reconstruct_execution_order(edges)

#输出最终调用顺序
print("\n🔹 函数执行顺序：", " -> ".join(execution_order))

