from function import Function, VulnChain
from analyzer import TaintAnalyzer
from extractor import TaintExtractor
import json

with open('../vlun_demo/Command_injection_CWE_78/1/sample_code.py', 'r', encoding='utf-8') as f:
    code = f.read()

entry_function = Function("entry", code, ["command"])
entry_function.tainted_params = ["command"]
entry_function.call_site_list = ["process"]

process_function = Function("process", code, ["data"])
process_function.tainted_params = ["data"]
process_function.call_site_list = ["sanitize", "execute"]

sanitize_function = Function("sanitize", code, ["s"])
sanitize_function.tainted_params = [""]
sanitize_function.call_site_list = []

execute_function = Function("execute", code, ["cmd"])
execute_function.tainted_params = ["cmd"]
execute_function.call_site_list = []

functions = [entry_function, process_function, sanitize_function, execute_function]

# 构建漏洞调用链封装
vuln_chain = VulnChain(
    vuln_function_name="execute",
    vuln_chain_function=[entry_function, process_function, execute_function],
    vuln_chain_function_list=["entry", "process", "execute"]
)

analyzer = TaintAnalyzer(functions)
result = analyzer.analyze(entry_function,vuln_chain)

with open('output/result.json', 'w', encoding='utf-8') as f:
    json.dump(result, f, indent=2)
print("✅ Analysis complete. Result saved to output/result.json")
