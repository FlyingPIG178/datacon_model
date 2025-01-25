## 1.关于apikey

在`LLM_MEMORY()`中的kimi免费key

## 2.修改的地方

### 2.1 Fuction

### 2.2 Vulchain

### 2.3 gen_source_sink_type_vulchain

在Fuction加入vulchain之前，拷贝了一个Fuction副本，防止不同链条之间赋值相互影响

## 3.结束

```
challenge.code_chain_generate()
```

中直接获取的输出写到{vuln_chain.vuln_function_name}.json，暂时没有对输出有任何的分类和记录

## 4.关于文件

测试文件在vlun_demo的命令注入下面，其他地方的路径被换成了我电脑上的