
from taint_extractor import TaintExtractor

class Function:
    def __init__(self, name, body, tainted_params, language):
        self.name = name
        self.body = body
        self.tainted_params = tainted_params
        self.language = language
        self.node = ""

# 模拟 C/Java 函数体
function_body = """
void foo(String input) {
    if (check(input)) {
        run(input);
        cleanup();
    }
    log("done");
}
"""

fn = Function(
    name="foo",
    body=function_body,
    tainted_params=["input"],
    language="java"
)

TaintExtractor(fn).extract()

print("=== 提取的污点相关代码片段 ===")
print(fn.node)
