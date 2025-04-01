
import re

class TaintExtractor:
    def __init__(self, function):
        self.function = function
        self.language = getattr(function, "language", "python")

    def extract(self):
        if self.language in ["c", "cpp", "java", "go", "js"]:
            self.extract_with_brace_blocks()
        else:
            self.extract_with_indent_blocks()

    def extract_with_indent_blocks(self):
        if not self.function.tainted_params:
            return
        lines = self.function.body.strip().splitlines()
        result_lines = []
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            if any(param in stripped for param in self.function.tainted_params):
                block_indent = len(line) - len(line.lstrip())
                filtered_block = [line] if any(p in line for p in self.function.tainted_params) else []

                i += 1
                while i < len(lines):
                    next_line = lines[i]
                    next_indent = len(next_line) - len(next_line.lstrip())
                    if next_line.strip() == "":
                        i += 1
                        continue
                    if next_indent > block_indent:
                        if any(param in next_line for param in self.function.tainted_params):
                            filtered_block.append(next_line)
                        i += 1
                    else:
                        break
                result_lines.extend(filtered_block)
            else:
                i += 1
        if result_lines:
            self.function.node = "\n".join(result_lines)

    def extract_with_brace_blocks(self):
        if not self.function.tainted_params:
            return
        lines = self.function.body.strip().splitlines()
        result_lines = []
        i = 0
        total_lines = len(lines)
        while i < total_lines:
            line = lines[i]
            stripped = line.strip()
            if any(param in stripped for param in self.function.tainted_params):
                if "{" in line:
                    block_lines = [line]
                    filtered_block = []
                    brace_count = line.count("{") - line.count("}")
                    i += 1
                    while i < total_lines and brace_count > 0:
                        current_line = lines[i]
                        brace_count += current_line.count("{")
                        brace_count -= current_line.count("}")
                        if any(param in current_line for param in self.function.tainted_params):
                            filtered_block.append(current_line)
                        i += 1
                    if filtered_block:
                        block_lines.extend(filtered_block)
                        if brace_count == 0:
                            block_lines.append("}")
                        result_lines.extend(block_lines)
                    continue
                else:
                    result_lines.append(line)
            i += 1
        if result_lines:
            self.function.node = "\n".join(result_lines)
