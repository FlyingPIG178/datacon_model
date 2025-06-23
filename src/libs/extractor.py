class TaintExtractor:

    def __init__(self, function):
        self.function = function
        self.language = getattr(function, "language", "python")

    def extract(self):

        if not self.function.tainted_params:
            return

        if isinstance(self.function.body, bytes):
            self.function.body = self.function.body.decode('utf-8')

        if self.language in ["c", "cpp", "java", "go", "js"]:
            self.extract_with_brace_blocks()
        else:
            self.extract_with_indent_blocks()

    def extract_with_indent_blocks(self):
        """
        缩进代码的提取 例如：python
        """
        lines = self.function.body.strip().splitlines()
        result_lines = []
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            # 检测控制语句（如 if, for, while, def, class 等，通常以 : 结尾）
            if stripped.endswith(":"):
                block_indent = len(line) - len(line.lstrip())
                block_lines = [line]
                i += 1

                while i < len(lines):
                    next_line = lines[i]
                    next_indent = len(next_line) - len(next_line.lstrip())

                    if next_line.strip() == "":
                        block_lines.append(next_line)
                        i += 1
                        continue

                    if next_indent > block_indent:
                        block_lines.append(next_line)
                        i += 1
                    else:
                        break

                if any(any(param in l for param in self.function.tainted_params) for l in block_lines):
                    result_lines.extend(block_lines)
            else:
                if any(param in stripped for param in self.function.tainted_params):
                    result_lines.append(line)
                i += 1
        if result_lines:
            self.function.node = "\n".join(result_lines)

    def extract_with_brace_blocks(self):
        """
        使用{}分割代码块的语言 C，java等
        """
        lines = self.function.body.strip().splitlines()
        result_lines = []
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            if self._contains_open_brace(line):
                block_lines = [line]
                brace_count = self._count_braces(line)
                i += 1

                while i < len(lines) and brace_count > 0:
                    current_line = lines[i]
                    block_lines.append(current_line)
                    brace_count += self._count_braces(current_line)
                    i += 1

                if any(any(param in l for param in self.function.tainted_params) for l in block_lines):
                    result_lines.extend(block_lines)
            else:
                if any(param in stripped for param in self.function.tainted_params):
                    result_lines.append(line)
                i += 1

        if result_lines:
            self.function.node = "\n".join(result_lines)

    @staticmethod
    def _contains_open_brace(line):
        """
        检查行是否包含有效的 {（忽略字符串和注释）。
        用于辅助判断一个大括号块的开始。
        """
        in_string = False
        string_char = None
        in_comment = False
        i = 0
        while i < len(line):
            if in_comment:
                if line[i:i + 2] == "*/":
                    in_comment = False
                    i += 2
                else:
                    i += 1
                continue

            if in_string:
                if line[i] == string_char and line[i - 1] != "\\":
                    in_string = False
                i += 1
                continue

            if line[i] == '"' or line[i] == "'":
                in_string = True
                string_char = line[i]
                i += 1
            elif line[i:i + 2] == "//":
                break
            elif line[i:i + 2] == "/*":
                in_comment = True
                i += 2
            elif line[i] == "{":
                return True
            else:
                i += 1

        return False

    @staticmethod
    def _count_braces(line):
        """
        计算行中有效的大括号数（正为 {，负为 }，忽略字符串和注释）。
        用于辅助判断一个大括号块的结束。
        """
        count = 0
        in_string = False
        string_char = None
        in_comment = False
        i = 0
        while i < len(line):
            if in_comment:
                if line[i:i + 2] == "*/":
                    in_comment = False
                    i += 2
                else:
                    i += 1
                continue

            if in_string:
                if line[i] == string_char and line[i - 1] != "\\":
                    in_string = False
                i += 1
                continue

            if line[i] == '"' or line[i] == "'":
                in_string = True
                string_char = line[i]
                i += 1

            elif line[i:i + 2] == "//":
                break

            elif line[i:i + 2] == "/*":
                in_comment = True
                i += 2

            elif line[i] == "{":
                count += 1
                i += 1

            elif line[i] == "}":
                count -= 1
                i += 1
            else:
                i += 1

        return count