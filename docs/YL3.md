###### **第三章 作品实现**
###### 3.1 系统开发环境

表3-1 软件程序开发工具与框架

|        开发环境        |        具体配置         |
| :--------------------: | :---------------------: |
|      前端开发工具      | Vite/VScode/trae/cursor |
|      前端包管理器      |          pnpm           |
|      前端开发框架      |          Vue3           |
|      后端开发工具      |     Pycharm/VScode      |
| 后端虚拟环境与包管理器 |           UV            |
|      后端开发框架      |         aiohttp         |



---

## 3.2 系统核心模块搭建

系统核心模块以 `vuln_detector.py` 为主控脚本，通过 `Challenge` 对象驱动漏洞检测流程。核心分析引擎采用模块化设计，这种设计理念极大地提升了系统的可维护性、可扩展性以及团队协作效率。每个模块职责明确，内聚性高，从而降低了系统复杂度。数据以 `ChallengeFile`、`Function` 和 `VulnChain` 三种核心对象在模块间高效流转，确保了数据的一致性和可追溯性。系统支持多语言代码解析（结合AST和LLM），能够从不同编程语言的源代码中准确提取信息，并在此基础上生成精确的函数调用图。随后，通过先进的污点传播分析和LLM智能分析，系统能够识别并确认潜在的漏洞，最终输出结构化的、易于理解的漏洞报告。 `Challenge` 对象在整个系统中扮演着核心枢纽的角色，负责管理和协调所有的分析操作和状态数据，确保每个漏洞检测任务的独立性和完整性。

### **3.2.1 核心分析引擎与主控框架**

系统的核心分析引擎以后端框架的形式组织，负责驱动整个漏洞检测流程。该框架从指定的代码库（即“challenge”）入手，通过一系列模块化的分析步骤，最终识别并报告潜在的安全漏洞。本节将详细介绍框架的程序入口、整体分析流程以及作为数据流转核心的关键对象定义，阐明它们如何协同工作以实现高效、准确的漏洞检测。

#### **程序入口**

系统的分析任务由 `vuln_detector.py` 脚本启动。该脚本作为主控程序，负责初始化配置、设置日志，并调用核心分析流程。以下代码片段是一个调用的示例，其 `__main__` 函数是整个漏洞检测项目的起点：

```python
if __name__ == '__main__':
    analyze_challenge(
        root_path="F:/juliet/datacon_model/vlun_demo",
        vuln_type="Command_injection_CWE_78",
        filename="1"
    )
```

上述代码展示了如何启动一次分析任务。`analyze_challenge` 函数接收三个关键参数：`root_path`（数据集根目录）、`vuln_type`（漏洞类型）和 `filename`（具体的题目/代码库名称）。这些参数的设计是为了精确控制分析范围，支持针对性地对特定漏洞类型和文件进行快速验证或批量分析，极大地提升了分析的灵活性和效率。

#### **整体分析流程 **

`analyze_challenge` 函数首先会初始化一个 `Challenge` 对象，该对象封装了针对单个代码库的所有分析操作和状态数据。`Challenge` 对象的设计确保了每个分析任务的独立性和可控性，有效地管理了分析过程中产生的所有中间数据和状态。

```python
def analyze_challenge(root_path: str, vuln_type: str, filename: str):
    """
    对某个具体漏洞类型下的指定题目进行分析
    """
    challenge = get_challenge(root_path, vuln_type, filename)

    if not challenge:
        logging.error(f"无法获取 Challenge: {os.path.join(root_path, vuln_type, filename)}")
        return
    try:
        logging.info(f"开始分析 {vuln_type} 类型题目: {challenge.challenge_dir}")
        run_single_challenge(challenge)
    except Exception as e:
        logging.error(f"解析题目 {challenge.challenge_dir} 失败！ {e}")
        logging.error(traceback.format_exc())
```

`get_challenge` 函数负责根据路径实例化 `Challenge` 对象。随后，`run_single_challenge` 函数被调用，它编排了详细的分析步骤，构成了漏洞检测的核心逻辑。

```python
def run_single_challenge(challenge: Challenge):
    """
    分析单个 Challenge 实例
    """
    try:
        challenge.parse_files()
        challenge.analysis_functions()
        challenge.generate_call_graph()
        challenge.generate_vul_chains()
        challenge.travel_Params_And_Body()
        challenge.code_chain_generate()
    except Exception as e:
        # ... 异常处理
```

如上所示，`run_single_challenge` 按照预设顺序调用 `Challenge` 对象的各个方法。整个流程涵盖了从文件解析、函数分析、调用图构建、漏洞链生成到最终代码链分析的完整过程。这种模块化的设计使得每一分析阶段都高度内聚，职责清晰，便于维护和扩展，同时也便于对特定阶段进行独立的测试和优化。

表3-2 分析流程方法介绍

| 方法                                 | 功能                           | 输入                                     | 输出                                                         |
| ------------------------------------ | ------------------------------ | ---------------------------------------- | ------------------------------------------------------------ |
| `challenge.parse_files()`            | 文件内容的读取和解析           | 原始文件路径和内容                       | 生成 `ChallengeFile` 对象列表                                |
| `challenge.analysis_functions()`     | 函数分析                       | `ChallengeFile` 对象列表                 | 填充 `Function` 对象详细信息（如函数体、参数等），为后续分析准备。 |
| `challenge.generate_call_graph()`    | 生成调用图                     | 已解析的 `Function` 对象列表             | 构建 `networkx.DiGraph` 格式的函数调用图。                   |
| `challenge.generate_vul_chains()`    | 切割生成漏洞链                 | 函数调用图和已标记语义的 `Function` 对象 | 识别并生成 `VulnChain` 对象列表。                            |
| `challenge.travel_Params_And_Body()` | 污点参数的传播与污点行为提取   | `VulnChain` 对象列表                     | 带有污点参数标记和相关代码片段的函数调用树（JSON格式）。     |
| `challenge.code_chain_generate()`    | 最终的漏洞链分析以及报告的生成 | 污点函数调用树和漏洞类型                 | 包含LLM最终评估结果的结构化漏洞报告（JSON文件）。            |

#### **核心对象**

在整个分析流程中，数据以三种核心对象的形式存在和流转，分别是 `ChallengeFile`、`Function` 和 `VulnChain`。这些对象在 `objects.py` 中定义，构成了整个系统的基本数据单元和信息载体，确保了数据在不同模块间的标准化传递。

- **`ChallengeFile`**

  `ChallengeFile` 对象代表了被分析代码库中的一个源文件，封装了文件的基本信息，如路径、内容和类型，并存储了从该文件中解析出的所有函数列表。其设计目的是将原始文件内容结构化为可操作的函数单元。

  **属性描述**：
  
  - `file_path`：文件的绝对路径。
  - `file_content`：文件的完整源码内容。
  - `function_list`：从该文件解析出的 `Function` 对象列表。

  ```python
  class ChallengeFile:
      """表示challenge中的一个文件"""
      def __init__(self, file_path, file_content):
          logging.info(f"开始初始化文件{file_path}...")
          self.file_path = file_path
          self.file_content :str = file_content
          self.file_type = os.path.splitext(file_path)[1]
          self.function_list :list[Function]= []
  ```

  在 `Challenge` 初始化阶段，系统会遍历题目文件夹下的所有文件，并为每个文件创建一个 `ChallengeFile` 实例，存入 `file_list` 列表中，为后续的精细化分析做准备。

- **`Function`**

  `Function` 对象是代码分析的基本单元，代表一个独立的函数。它存储了函数的名称、源码（`body`）、参数列表（`param_list`）和其内部的函数调用点（`call_site_list`）。

  **属性描述**：
  
  - `name`：函数的名称。
  - `body`：函数的源码。
  - `param_list`：函数的参数列表。
  - `type`：存储函数语义标签的字典。
  - `tainted_params`：存储在该函数内被识别为污点的参数名列表。
  - `node`：存储与污点参数相关的代码切片。

  ```python
  class Function:
      """
      challenge中的一个文件中的方法的详情
      """
      def __init__(self, name: str, body: str, param_list: list):
          self.name = name
          self.body = body
          self.call_site_list = []
          self.param_list = param_list
          self.type = {
              "input": False, 
              "file_read": False, 
              "authentication": False,
              "memoryOP": False, 
              "command": False, 
              "integer": False, 
              "other": False}
          self.mini_body = ""
          self.node = ""  
          self.tainted_params = []  
  ```

- **`VulnChain`**

  `VulnChain` 对象代表一条潜在的漏洞利用链。它封装了从一个或多个 `Function` 对象串联而成的调用路径。

  **属性描述**：
  
  - `vuln_function_name`：漏洞链的终点（`sink`）函数名。
  - `vuln_chain_function_list`：按调用顺序排列的函数名列表，构成一条完整路径。
  - `vuln_chain_function`：`Function` 对象列表
  
  ```python
  class VulnChain:
      """
      表征一个同一个函数的所有漏洞利用链条，
      ...
      """
      def __init__(self, vuln_function_name: str, vuln_chain_function: list[Function],
                   vuln_chain_function_list: list[str]):  
          self.vuln_function_name: str = vuln_function_name
          self.vuln_chain_function = vuln_chain_function  
          self.vuln_chain_function_list = vuln_chain_function_list  
          self.mini_chain = ''
          self.score = 0
  ```
  
  该对象的核心是 `vuln_chain_function_list`和 `vuln_chain_function`，它以 `sink` 函数的名称为标识，是后续污点传播分析和最终漏洞判定的直接输入。
  
  ### **3.2.2 多语言代码解析与调用图生成模块**
  
  在核心框架之下，系统采用了一种结合了抽象语法树（AST）和大型语言模型（LLM）的混合分析策略，以实现对多种编程语言的源代码解析和函数级别调用关系的提取。此模块是后续所有分析的基础，其精确性和完整性直接影响到整个漏洞检测流程的有效性。其核心目标是构建一个精确、全面且易于遍历的函数调用图（Call Graph），为后续的漏洞链识别和污点分析奠定坚实基础。
  
  #### **统一文件解析器**
  
  为了适配不同语言，系统设计了一个统一的文件解析器 `FileParser`。它作为解析模块的入口，根据文件后缀名分发给相应的语言解析器。这种策略模式（Strategy Pattern）的设计理念极大地提升了系统的可维护性和可扩展性。它意味着添加对新语言的支持变得异常简单：只需实现一个新的解析类，而无需修改 `FileParser` 的核心分发逻辑。这显著降低了系统耦合度，使得系统能够灵活应对不断变化的编程语言生态。
  
  ```python
  class FileParser:
      """
      对题目文件进行最基础的解析，不同类型的文件解析方式和结果都不同
      ...
      """
      def parser(self, file: ChallengeFile) -> list[Function]:
          """根据文件后缀判断类型，根据这个类型去找相应方法解析文件"""
          file_type = file.file_type
          if file_type == ".c":
              self.parser_c_file(file)
          elif file_type == ".cc" or file_type == ".cpp":
              self.parser_cpp_file(file)
          # ... 其他语言的分发逻辑
  ```
  
  在 `Challenge.py` 的 `parse_files` 方法中，系统会遍历所有 `ChallengeFile` 对象，并调用 `FileParser` 的 `parser` 方法，从而启动对每个文件的解析流程，确保所有代码文件都能被正确地识别和处理。
  
  #### **基于Tree-sitter的语法分析**
  
  对于C、Go、Java等拥有成熟Tree-sitter文法支持的编程语言，系统优先采用基于抽象语法树（AST）的精确分析方法。Tree-sitter作为一个高性能的增量解析器，能够将源代码解析成具体的、层次分明的语法树。这种方法相比于正则表达式或简单的文本匹配，能够提供高度精确的语法结构信息，有效避免误判，并支持对复杂代码结构的深层分析，是构建可靠调用图的关键。
  
  (1) **构建语法树**
  
  首先，针对目标文件，`CFileParser`（或其他语言对应的Parser）会读取文件内容，并调用 `parser.parse` 方法生成一棵详细的语法树 `Tree`。这棵树精确地反映了代码的语法结构。
  
  ```python
  class CFileParser:
      language: Language = Language(tree_sitter_c.language())
      parser: Parser = Parser(language)
  
      # 完成文件的初步解析，返回函数列表
      def parse(self, file: ChallengeFile) -> list[Function]:
          tree = None
          try:
              with open(file.file_path, "r", encoding="utf-8") as cFile:
                  code = cFile.read()
                  tree = self.parser.parse(bytes(code, "utf-8"))
              # ...
  ```
  
  (2) **查询函数节点**
  
  随后，系统利用Tree-sitter强大的查询语言（Query Language）在已构建的AST中定位所有的函数定义节点。Tree-sitter的查询语言允许我们以类似于CSS选择器的方式，精确地匹配AST中的特定节点类型和模式，例如，通过`(function_definition) @function`可以高效地找到所有函数定义的位置。通过这种方式，系统能够可靠且准确地提取出每个函数的源码（即函数体）
  
  ```python
  def getFunctions(self, tree: Tree) -> list[Function]:
      """传入方法的语法树,返回方法列表"""
      logging.debug("正在查询文件AST中所有的方法节点...")
      functions = []
      query = Query(self.language, """(function_definition) @function""")
      functionNodes = query.captures(tree.root_node)["function"]
      # ...
  ```
  
  通过这种方式，系统能够可靠地提取出每个函数的源码，为后续创建 `Function` 对象奠定基础。
  
  #### **LLM辅助的函数信息提取 **
  
  尽管AST能够准确识别函数体，但要从多种语言（尤其是那些没有现成Tree-sitter解析器或代码风格不规范的语言，例如反编译伪代码）中准确地提取函数名、参数列表和内部函数调用点（Call Sites）仍然是一个复杂且耗时的任务。因此，系统引入了大型语言模型（LLM）作为强大的辅助手段，以弥补传统AST解析器在跨语言泛化能力和语义理解上的不足。LLM能够通过其强大的自然语言理解能力，处理更为“模糊”或非结构化的代码片段，从而提取出所需的信息。
  
  (1) **定义LLM任务提示（Prompt）**
  
  在 `prompt.py` 中，系统精心设计了专门用于函数信息提取的提示词 `function_parse_prompt`。该提示词通过以下方式引导LLM的行为：
  
  - **角色设定：** 要求LLM扮演“分析经验丰富的代码安全分析人员”，赋予其专业的分析视角。
  - **输入明确：** 明确指出LLM将接收“函数代码片段”（支持多种语言）。
  - **任务清晰：** 精确定义LLM需要完成的三项任务：识别函数名、找出所有被调用的函数（不包括系统函数和类名）、以及提取函数参数列表。
  - **推理引导：** 加入“让我们一步步地进行推理”的指令，鼓励LLM进行更深层次的逻辑思考，以提高结果的准确性。
  - **严格输出格式：** 最关键的是，强制LLM以严格的JSON格式返回分析结果，并明确定义了每个字段的含义和格式。这种**强制性的结构化输出**是确保LLM结果可编程解析和利用的关键，同时也有助于**减少幻觉和格式错误**。
  
  ~~~python
  class FunctionParsePrompt:
      function_parse_prompt = """
      #设定
      你是一个分析经验丰富的代码安全分析人员，能够精准分析函数。
      #输入
      ##函数代码片段：<包含了反编译伪代码，C，C++，java，python，go，js等语言>
      #任务
      1.查看当前上传的函数代码片段的函数名是什么
      2.分析该函数代码片段调用了哪些函数，准确找出其调用所有的函数，并在结果中输出函数名。
      4.函数名中，不要包含系统函数，不要包含类名等信息。如 a.b(c,e)，则只返回'b'，务必不要返回多余的东西。
      3. 让我们一步步地进行推理。
      #输出结果
      请务必严格按照以下JSON格式返回分析结果，请确保生成格式正确的结果：
      ```json
      {
          function_name:上传的函数名称，
          call_sites:[函数名1,函数名2,函数名3,......,函数名n](被调用的函数名列表,不包括系统函数)
          param_list:["函数参数1,函数参数2....,函数参数n"](上传函数的参数列表)
      }```
      #限制
      1. 输出结果以JSON的纯文本形式返回,除json外不要返回任何内容,确保JSON格式标准化，输出前后无多余空行或注释，严格按照要求格式输出。
      """
  ~~~
  
  (2) **调用LLM服务**
  
  `llmService.py` 中的 `FunctionParser` 类负责调用LLM。它将从AST中提取出的函数体作为输入，结合上述精心设计的提示词，发送给LLM进行分析，并对LLM返回的JSON结果进行解析。该模块内置了重试机制（`Config.retry_times`），以应对LLM偶发的格式错误或通信失败，从而增强了系统的鲁棒性。
  
  ```python
  class FunctionParser:
      def get_function_name_and_callsites(self, function_body) -> Tuple[str, list[str], list[str]]:
          count = 0
          while count <= Config.retry_times:
              count += 1
              llm_output = self.llm.communicate(self.function_parse_prompt, function_body)
              json_result = self.resolve_output(llm_output)
              # ... 解析与重试逻辑
  ```
  
  (3) **信息整合**
  
  在各语言的`*FileParser`（例如`PyFileParser`）中，从AST获取的函数体首先会被送入`FunctionParser`进行LLM辅助分析。LLM返回的函数名、调用点和参数列表随后被用来实例化`Function`对象。这种AST+LLM的混合模式充分结合了AST的结构化准确性和LLM的跨语言泛化能力和语义理解优势，实现了对多语言代码的有效解析，即使面对非标准或反编译代码也能高效提取关键信息，从而构建出更全面、准确的函数模型。
  
  ```python
  # 以PyFileParser为例
  def getFunctions(self, tree) -> list[Function]:
      # ...
      for function_node in function_nodes:
          function_body = function_node.text
          function_name, function_call_sites, function_param_list = FunctionParser().get_function_name_and_callsites(function_body)
          function = Function(function_name, str(function_body),function_param_list)
          function.setCallSites(function_call_sites)
          functions.append(function)
      return functions
  ```
  
  #### **函数调用图构建**
  
  在所有文件的所有函数都被成功解析并实例化为`Function`对象后，`Challenge`类便会启动全局的函数调用图构建任务。该图使用 `networkx.DiGraph` 库实现，这是一种强大的有向图数据结构，其节点代表着系统中的每一个函数，而有向边则清晰地表示了函数之间的调用关系。
  
  ```python
  def generate_call_graph(self):
      """生成函数调用图"""
      for function in self.all_funtion_list:
          self.call_graph.add_node(function.name,
                                   content=function)
          logging.debug(f"添加{function.name}节点到调用图!!!")
  
      for function in self.all_funtion_list:
          for call_site in function.call_site_list:
              if (self.call_graph.has_node(call_site)):
                  self.call_graph.add_edge(function.name,
                                           call_site)
                  logging.debug(f"已添加{function.name}到{call_site}的边！！！")
  ```
  
  该调用图完整且精确地表示了被分析代码库内部的函数调用关系，是程序控制流的关键抽象。其准确性和完整性直接影响到后续污点传播分析的有效性。`networkx`库的选择还提供了丰富的图算法，便于进行高效的路径查找和拓扑分析。
  
  #### **调用链切片**
  
  函数调用图构建完成后，系统需要从中切分出有意义的、可能构成漏洞的特定调用路径。这一任务由 `VulChainGenerator` 模块完成。它根据预设的“source-sink”模型，从庞大的调用图中精确提取所有从“源”（source）函数到“汇”（sink）函数的简单路径。
  
  这里的“source”通常指代数据进入系统的入口点，例如用户输入、文件读取、网络请求等，这些数据可能未经处理而带有“污点”。而“sink”则通常指代可能引发安全漏洞的危险操作，例如执行系统命令、文件写入、数据库查询、内存操作等，这些操作如果被污点数据控制，将导致漏洞。
  
  ```python
  class VulChainGenerator:
      # ...
      def gen_source_sink_type_vulchain(self, source_type: str, sink_type: str, call_graph: nx.DiGraph):
          # ...
          input_function_list = self.get_target_function_from_cg(call_graph, source_type, True)
          vul_function_list = self.get_target_function_from_cg(call_graph, sink_type, False)
          # ...
          for vul_function in vul_function_list:
              for input_function in input_function_list:
                  # ...
                  if input_function.name != vul_function.name:
                      path_list = list(nx.all_simple_paths(
                          call_graph, input_function.name, vul_function.name
                      ))
  ```
  
  在上述流程中，`source_type`（如`input`）和`sink_type`（如`command`）是在下一阶段由LLM分析函数语义后动态标记的。`nx.all_simple_paths` 函数在图论中至关重要，它能够高效地找出图中从一个 `source` 节点到一个 `sink` 节点的所有不重复的、简单的（即不包含重复节点）路径。每一条这样的路径都被系统认为是一条潜在的漏洞链，并被封装成一个 `VulnChain` 对象。这些 `VulnChain` 对象作为面向安全分析的业务抽象，将图论路径转化为可供后续模块进行深入污点分析和漏洞确认的直接输入，极大地简化了后续处理的复杂性。
  
  ### **3.2.3 污点分析与传播模块**
  
  在识别出潜在的漏洞调用链（`VulnChain`）后，系统并未立即判定其为漏洞，而是启动了更为精细的污点分析与传播模块。这是从“可能存在”到“确实存在”漏洞的关键步骤。该模块的核心任务是模拟污点数据在调用链中的流动过程，从`source`（污染源）到`sink`（危险函数），并精确地提取出与污点数据处理直接相关的代码片段。此过程旨在显著减少误报（false positives），因为仅仅存在调用链不足以证明漏洞，还需要数据流的验证。它为后续LLM的精准评估提供了上下文最丰富且高度精炼的“证据链”输入。该模块由 `llmService.py` 中的 `ParamsAndBodyTravel` 类主导实现。
  
  #### **函数语义理解：为函数打上`source`和`sink`标签**
  
  污点分析的第一步是准确识别污染的起点（`source`）和终点（`sink`）。传统静态分析工具在此方面往往面临挑战，因为它们通常依赖于庞大的、难以维护的规则库，且难以适应新的框架、自定义函数或反编译代码。本系统通过 `FunctionAnalyser` 类，利用LLM对每个`Function`对象进行深入的语义理解，为其自动打上关键的安全标签。LLM凭借其强大的语义理解能力和泛化能力，能够识别出隐藏的、非标准化的 `source` 和 `sink`，甚至可以推断出函数行为的危险性。
  
  (1) **定义语义分析提示（Prompt）**
  
  针对每种漏洞类型，`prompt.py`中都定义了专门的语义分析提示词。这些提示词是经过精心设计的，它们通过**明确的角色设定、详尽的规则描述和清晰的输出格式**，引导LLM进行精准的判断。例如，对于命令注入漏洞，`Command_injection_prompt`会指示LLM判断一个函数是否处理外部输入（标记为`input`）以及是否执行系统命令（标记为`command`）。提示词中列举了不同语言的典型危险函数和输入函数，为LLM提供了具体的判断依据。
  
  ~~~python
  # prompt.py 中的部分提示词
  class FunctionAnalysisPrompt:
      Command_injection_prompt = """
  #设定
  你是一个跨语言代码安全分析专家，擅长精准判断命令注入漏洞和数据流风险。
  ##任务
  请根据以下原则分析函数代码：
  
  1. ## 命令执行（command）标记规则
  仅当函数内部调用了系统标准库或官方内置的命令执行函数时，才标记 command:true。
  语言危险函数如下但不限于：
  Python 的命令执行函数包括：
  - os.system
  ...
  C/C++ 的命令执行函数包括：
  - system
  ...
  Java 的命令执行函数包括：
  - Runtime.getRuntime().exec()
  ...
  Go 的命令执行函数包括：
  - os/exec.Command
  ...
  JavaScript (Node.js) 的命令执行函数包括：
  - child_process.exec
  ...
  若调用的不是上述危险函数（例如仅仅是用户自定义函数），请标记 command:false。
  2.  ## 输入数据处理（input）标记规则
  - 仅当函数内部存在主动的外部数据读取行为时，才标记 input:true。
  - 判断标准：
    - 包括但不限于以下函数或 API：
      - Python: input(), sys.stdin, request.get(), request.data
        ...
  - 如果该函数仅作为参数传递、中转处理、或字符串操作，没有主动读取外部输入数据，请标记 input:false
  
  ##输出格式
  仅输出符合规范的纯JSON数据：
  ```json
  {
      "input": bool,  # 是否处理外部输入或网络消息
      "command": bool # 是否调用了系统内置的命令执行函数
  }```
  #限制
  1. 输出结果以JSON的纯文本形式返回,除json外不要返回任何内容,确保JSON格式标准化，输出前后无多余空行或注释，严格按照要求格式输出。
          """
  ~~~
  
  (2) **执行语义分析**
  
  `FunctionAnalyser` 的 `analysis` 方法会根据当前任务的漏洞类型选择对应的提示词，并将函数体发送给LLM进行分析。LLM返回的结果（如 `{"input": true, "command": false}`）会被用来更新`Function`对象的`type`字典。这个`type`字典就是函数的语义标签，它将`input`为`true`的函数识别为`source`，将`command`（或其他危险操作）为`true`的函数识别为`sink`。这个`type`字典是后续污点分析进行起点和终点匹配的依据，是连接语义理解和污点传播的核心桥梁。
  
  ```python
  # llmService.py
  class FunctionAnalyser:
      def analysis(self, function: Function, vuln_type: str):
          # ...
          if vuln_type == "Command_injection_CWE_78":
              json_result = self.type_analysis(self.Command_injection_prompt, function)
          # ...
  ```
  
  #### **反向遍历：污点参数标记 **
  
  在`source`和`sink`被识别后，系统从`sink`函数开始，沿着`VulnChain`进行反向遍历，以确定污点是如何从调用链的下游传播到上游的。这种“溯源”的逻辑至关重要，它比从所有输入向前追踪效率更高且目标性更强。`ParamsAndBodyTravel`中的`reverse_traverse`方法负责此任务。
  
  ```python
  # llmService.py
  class ParamsAndBodyTravel:
      def audit_vulnerability_chain(self, vuln_chain: [VulnChain]):
          # ...
          # 反向遍历：从链的尾部开始，依次遍历到链头
          for i in range(len(vuln_chain.vuln_chain_function) - 1, 0, -1):
              child = vuln_chain.vuln_chain_function[i]
              parent = vuln_chain.vuln_chain_function[i - 1]
              self.reverse_traverse(child, parent)
          # ...
  ```
  
  `reverse_traverse`方法的核心逻辑是：检查父函数（`parent`）是如何调用子函数（`child`）的。如果父函数传递给子函数的实参，对应了子函数中已被标记为污点（`tainted_params`）的形参，那么这个实参在父函数中也被认为是污点。通过正则表达式(`re.compile`)，系统能够动态地识别函数调用中的实际参数，并将其与形式参数进行映射，实现参数级别精确的污点传播。
  
  ```python
  # llmService.py
  def reverse_traverse(self, child: Function, parent: Function):
      # ...
      # 正则匹配调用 child.name 的位置，并捕获参数
      pattern = re.compile(rf"{re.escape(child.name)}\s*\((.*?)\)")
  
      for line in parent_body:
          match = pattern.search(line)
          if not match:
              continue
  
          args = [arg.strip() for arg in match.group(1).split(",")]
  
          # 根据参数位置匹配 child 的污点参数
          for i, formal_param in enumerate(child.param_list):
              if formal_param in child.tainted_params and i < len(args):
                  real_arg = args[i]
                  # ...
                  tainted_args.add(real_arg)
  
      if tainted_args:
          parent.tainted_params.extend(list(tainted_args))
  ```
  
  通过这个自下而上的过程，污点标记会从`sink`函数逐级向上游函数的参数进行传播，直到`source`函数。`tainted_params`列表则作为污点分析的核心状态，不断扩展，记录每个函数中被污染的参数，从而描绘出完整的污点传播路径。
  
  #### **正向遍历：递归构建调用树**
  
  反向遍历完成污点参数的标记后，系统会从`source`函数开始进行正向遍历，递归地构建一个详细的调用树。这一步的目的是，在定位了污点参数后，将抽象的污点路径具体化为一个可视化的、包含具体代码片段的“漏洞证据树”。这棵树以JSON格式表示，清晰地展示了污点数据的完整流动路径和处理过程，是为LLM提供高度精炼且上下文丰富输入的核心数据结构。
  
  ```python
  # llmService.py
  def build_call_tree(self, function, vuln_chain):
      # ...
      taint_actions = self.extract_taint_actions(function)
  
      node = {
          "function": function.name,
          "taint_params": function.tainted_params,
          "taint_actions": taint_actions,
          "calls": []
      }
      # ... 递归调用
      child_node = self.build_call_tree(child_function, vuln_chain)
      if child_node is not None:
          node["calls"].append(child_node)
  ```
  
  每个树节点代表一个函数调用，包含了函数名、当前函数的污点参数，以及最关键的`taint_actions`——即与污点参数相关的代码切片。`calls`数组则递归包含了该函数调用的下一级函数节点，形成了完整的调用层次结构。JSON格式的调用树具有机器可读、层级清晰的优点，极大地便利了LLM对污点传播上下文的理解，也为最终报告的生成和可视化打下了基础。
  
  #### **污点代码切片提取**
  
  为了得到 `taint_actions`，系统使用了 `TaintExtractor` 类。该提取器是污点分析模块中的一个关键组件，专门负责从一个函数体中，仅抽取出与已知污点参数（`tainted_params`）直接相关的代码行或代码块。这一步骤的目的是显著降噪，避免将整个函数体发送给LLM，从而减少LLM处理的token数量，提高分析效率和准确性，并有效降低成本。它支持两种模式以适应不同语言的代码风格：基于缩进（如Python）和基于大括号（如C/Java）。
  
  ```python
  # extractor.py
  class TaintExtractor:
      def extract(self):
          if not self.function.tainted_params:
              return
          # ...
          if self.language in ["c", "cpp", "java", "go", "js"]:
              self.extract_with_brace_blocks()
          else:
              self.extract_with_indent_blocks()
  ```
  
  例如，对于大括号语言（如C/C++/Java/Go/JS），`extract_with_brace_blocks` 方法会智能地分析每个代码块。只有当某个代码块内出现了污点参数时，整个块才会被提取。这种精确的切片机制确保了LLM能够聚焦于最核心的污点处理逻辑，而无需处理无关的代码。
  
  ```python
  # extractor.py
  def extract_with_brace_blocks(self):
      # ...
      while i < len(lines):
          line = lines[i]
          # ...
          if self._contains_open_brace(line):
              # ... 识别代码块
              if any(any(param in l for param in self.function.tainted_params) for l in block_lines):
                  result_lines.extend(block_lines)
          # ...
  ```
  
  通过这种方式，系统极大地减少了需要分析的代码量，将无关逻辑排除在外，使得后续LLM能够聚焦于最核心的污点处理逻辑。
  
  #### **链外函数补全机制 **
  
  在构建调用树的过程中，系统还具备一个强大且创新的“链外函数补全”能力。这是一个非常先进且关键的特性，它扩展了传统的污点分析范围。当 `taint_actions` 中包含了一个不属于原始 `VulnChain` 的函数调用时，系统会主动检查这个调用的实参是否携带污点。如果是，系统会将这个“干净”的、但影响污点流向的外部函数动态地加入到当前的分析流程中。
  
  ```python
  # llmService.py
  def find_and_append_clean_functions(self, node, function, vuln_chain):
      for action in node["taint_actions"]:
          # ... 获取调用的函数名和实参
          called_function_name = ...
          call_args_list = ...
          # ...
          # 检查函数是否存在且不在漏洞链中
          if called_function_name in self.all_funtion_list and (...):
              clean_function = self.all_funtion_list[called_function_name]
              # ... 判断 clean 函数哪些参数是污点
              # ...
              # 标记对应位置的参数为污点参数
              clean_function.add_tainted_param(param_name)
              
              # 构建调用树
              clean_node = self.build_call_tree(clean_function, vuln_chain)
              if clean_node is not None:
                  node['calls'].insert(0, clean_node)
  ```
  
  这个机制的引入，解决了实际漏洞利用链可能不只包含一条简单的线性调用路径的问题。污点数据可能会流经一些看似“干净”的、不直接位于核心漏洞链上的辅助函数（例如字符串处理、类型转换、数据封装或中间件函数）。如果这些辅助函数的实现存在缺陷，污点可能仍然能够传递下去，导致漏洞。通过动态地将这些“链外”函数纳入分析，系统能够追踪污点数据的完整生命周期，即使它流经了原始调用链之外的函数，也能够捕捉到。这显著提升了污点分析的完整性、深度和准确性，有效避免了因路径过于简化而导致的漏报，使得检测结果更为可靠。
  
  ### **3.2.4 大语言模型驱动的智能分析模块**
  
  大型语言模型（LLM）是贯穿本系统分析流程的核心驱动力，它不仅弥补了传统静态分析工具在多语言和复杂逻辑理解上的不足，更在最终的漏洞评估环节扮演了决策者的角色。整个智能分析模块由底层的LLM服务、精细的提示工程（Prompt Engineering）以及上层的多个分析器共同构成。
  
  #### **LLM服务基础 (`llmbase.py`) 和 提示工程(`prompt.py`)**
  
  所有与LLM的交互都通过 `llmbase.py` 中定义的服务层进行。该文件封装了与LLM API通信的底层细节，提供了一个统一、可靠的调用接口。
  
  (1) **统一通信接口**
  
  `LLM` 类作为统一接口，内部集成了有记忆和无记忆两种会话模式，并根据输入token数量自动选择合适的模式。对于本系统的单次分析任务，主要使用无记忆的 `LLM_WITHOUT_MEMORY` 类。
  
  ```python
  # llmbase.py
  class LLM:
      def __init__(self):
          self.llm_with_memory = LLM_MEMORY()
          self.llm_without_memory = LLM_WITHOUT_MEMORY()
  
      def communicate(self,system_message,humen_message) -> str:
          # ... token量判断与分发逻辑
          output = self.llm_without_memory.chat(system_message,str(humen_message))
          # ...
          return output
  ```
  
  `chat` 方法负责将系统提示（`system_message`）和用户输入（`humen_message`，即代码片段或调用链数据）整合成符合API要求的格式，并处理重试、超时等异常情况。
  
  ```python
  # llmbase.py
  class LLM_WITHOUT_MEMORY:
      def chat(self,syscontent,humancontent):
          """
          系统消息，定义对话的上下文或模型的角色.用户消息，表示用户的输入内容
          """
          try:
              Message1 = SystemMessage(syscontent)
              Message2 = HumanMessage(humancontent)
              Message = [Message1, Message2]
              output = self.llm(Message)
              return output.content
          except Exception as e:
              return None
  ```
  
  (2) **提示工程**
  
  `prompt.py` 文件是系统的“智慧核心”，它包含了所有指导LLM进行分析的提示词。这些提示词经过精心设计，为每个分析任务（如函数解析、语义理解、漏洞评估）设定了明确的角色、任务、输入输出格式和限制，是确保LLM输出内容准确、可控的关键。
  
  表3-3 主要的prompt介绍
  
  | Prompt 名称                | 使用模块              | 主要功能                                               |
  | -------------------------- | --------------------- | ------------------------------------------------------ |
  | `function_parse_prompt`    | 多语言代码解析模块    | 从代码中提取函数名、调用点和参数。                     |
  | `[vuln_type]_prompt`       | 污点分析模块          | 为函数打上`source`或`sink`语义标签。                   |
  | `code_chain_travel_prompt` | LLM驱动的智能分析模块 | 对完整的污点调用树进行最终评估，并生成结构化分析报告。 |
  
  - **function_parse_prompt**
  
    `function_parse_prompt` 专为多语言代码解析模块设计，旨在从 C、C++、Java、Python、Go 和 JavaScript 等语言的代码片段中提取函数名、调用点和参数列表。
  
    它要求模型扮演经验丰富的代码安全分析人员，精准识别用户定义的函数调用，排除系统函数（如 `printf`）和类名（如从 `a.b` 中仅提取 `b`）的干扰。
  
    输出采用严格的 JSON 格式，例如 :
  
    ```json
    {
        "function_name": "example", 
        "call_sites": ["func1", "func2"],
        "param_list": ["param1", "param2"]
    }
    ```
  
    并禁止多余内容如注释或空行。
  
  - **[vuln_type]_prompt**
  
    `[vuln_type]_prompt` 系列提示词，包括` Arbitrary_file_access_prompt `和 `Buffer_overflow_prompt `等，服务于污点分析模块，针对特定漏洞类型（如任意文件访问、缓冲区溢出、命令注入等）标记函数是否为输入点（`source`）或敏感操作点（`sink`）。
  
    这些提示词通过检查函数是否处理外部输入（如 `input() `或` request.get()`）或调用危险函数（如 `C/C++ `中的` strcpy`、`memcpy`）来识别潜在风险。
  
    例如，Buffer_overflow_prompt 的输出为 {"input": true, "memoryOP": true}，确保结果一致性。它们要求模型逐步推理，分析代码和数据流，提供语义标签，用于识别可能引入外部数据或执行危险操作的函数。
  
  - **code_chain_travel_prompt**
  
    `code_chain_travel_prompt` 驱动智能分析模块，分析完整的污点调用链，评估是否存在漏洞利用链，并生成详细的漏洞报告。
  
    它综合函数调用关系和污点传播，判断漏洞的可能性、类型、利用方式、威胁评分（0-10 分）及修复建议，输出结构化 JSON 报告，例如 :
  
    ```json
    {
        "存在漏洞": true,
        "漏洞函数": "example",
        "漏洞类型": "buffer_overflow", 
        "利用方式": "crafted input to overflow buffer", 
        "威胁评分": 8,
        "修复建议": "use strncpy with bounds checking", 
        "分析理由": "detailed reasoning"
    }
    ```
  
    提示词要求模型逐步分析调用链，检查污点参数是否传播到危险操作，并严格限制输出为纯 JSON 格式，避免多余内容。
  
  #### **函数信息提取 **
  
  如 "3.2.2 多语言代码解析与调用图生成模块" 中所述，该模块利用LLM从原始代码片段中提取函数名、参数和调用点，为构建调用图提供基础元数据。
  
  #### **函数语义理解 **
  
  如 "3.2.3 污点分析与传播模块" 中所述，该模块借助LLM理解函数的核心功能，为函数打上`source`或`sink`等语义标签，从而识别出污点分析的起点和终点。
  
  #### **最终漏洞链评估与报告生成 **
  
  这是LLM在分析流程中扮演的最终，也是最关键的角色。在污点分析模块成功生成了带有完整污点传播路径和相关代码片段的调用树后，`CodeChainTravel` 类会接管该数据，并请求LLM对其进行全面的安全评估。LLM在此处扮演了“AI安全专家”的角色，基于其对安全知识和代码语义的理解进行高级推理和决策。
  
  (1) **最终评估提示（Prompt）**
  
  `prompt.py` 中的 `code_chain_travel_prompt` 是为最终评估量身定制的。它要求LLM扮演网络安全专家的角色，基于输入的调用链数据（包含了函数调用关系、污点参数和相关代码切片）和漏洞类型，进行一次完整的漏洞分析。
  
  ~~~python
  # prompt.py
  class FunctionParsePrompt:
      code_chain_travel_prompt = """
      你是一个网络安全专家。以下是代码调用链的数据和漏洞类型的信息。请分析是否存在漏洞利用链，并直接将分析结果到 JSON 数据中。
  
      ### 输入数据：
      - **调用链数据**: {node_data}
      - **漏洞类型**: {vuln_type}
  
      ### 分析要求：
      1. **漏洞检测**：判断是否存在漏洞利用链。
      2. **漏洞类型识别**：说明漏洞的具体类型。
      ...
      6. **分析理由**：提供详细的分析过程...
  
      返回以下json数据
      ```json
      {{
          "存在漏洞": true 或 false,
          "漏洞函数": "函数名",
          "漏洞类型": "漏洞类型",
          ...
      }}
      ```
      """
  ~~~
  
  这个提示词引导LLM输出一个结构化的JSON报告，内容涵盖漏洞是否存在、漏洞函数、利用方式、威胁评分、修复建议和分析理由。
  
  (2) **执行评估与生成报告**
  
  `CodeChainTravel` 的 `analysis_chain` 方法负责格式化输入、调用LLM并处理返回结果。它将污点分析生成的调用树（`node_data`）序列化为JSON字符串，并将其精确地嵌入到提示词中，然后通过 `self.llm.communicate` 调用LLM服务。LLM返回的分析报告会被解析，并作为一个新的键值（`"漏洞分析"`）附加到原始调用树数据中，形成一个包含原始证据和LLM高级分析结果的完整JSON对象。
  
  ```python
  # llmService.py
  class CodeChainTravel:
      def generate_prompt(self, node_data, vuln_type):
          """
          根据漏洞链数据生成提示词
          """
          return self.CodeChainTravelPrompt.format(
              node_data=json.dumps(node_data, indent=2),
              vuln_type=vuln_type
          )
  
      def analysis_chain(self, node_data, vuln_type):
          """
          使用 LLM 分析漏洞链并返回结果，将分析结果附加到原始 JSON 数据
          """
          try:
              prompt = self.generate_prompt(node_data, vuln_type)
              # ... 调用LLM
              llm_output = self.llm.communicate(prompt, None)
              llm_output = self.resolve_output(llm_output)
              # ...
              node_data["漏洞分析"] = llm_output
              return node_data
          # ...
  ```
  
  它将污点分析生成的调用树（`node_data`）序列化为JSON字符串，嵌入到提示词中，然后调用LLM。LLM返回的分析报告会被解析并附加到原始调用树数据中，形成最终的分析结果。
  
  (3) **保存结果**
  
  最后，在 `Challenge.py` 的 `code_chain_generate` 方法中，这些带有LLM最终评估意见的、完整的JSON调用树会被逐一保存为独立的JSON文件。这些JSON文件构成了本次漏洞检测任务的完整交付产物，它们不仅包含了详细的污点传播路径和代码切片，更重要的是，它们包含了由LLM这位“AI安全专家”出具的权威性分析报告，包括漏洞判断、类型、利用方式、威胁评分、修复建议和详细理由。
  
  ```python
  # Challenge.py
  def code_chain_generate(self):
      # ...s
      for index, node_data in enumerate(self.node):
          try:
              # ...
              result_data = self.CodeChainTravel.analysis_chain(node_data, vuln_type)
              # ...
              # 将结果保存到 JSON 文件
              output_path = os.path.join(output_dir, f"{index + 1}.json")
              with open(output_path, "w", encoding="utf-8") as file:
                  json.dump(result_data, file, indent=4, ensure_ascii=False)
          # ...
  ```
  
  保存的结果示意图如图一所示：
  
  ![图一](https://image.h3cof6.com/md/image-20250527010747028.png)
  
  这个结构清晰地包含了漏洞检测结果、关键的漏洞信息，以及LLM提供的详细分析和推理过程。提供了结构化、机器可读且包含LLM智能分析结果的详细漏洞证据，支持自动化处理、系统集成、高效人工审计及全面的漏洞管理。
