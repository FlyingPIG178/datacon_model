from libs.llmService import FunctionAnalyser ,VulnChecker
from libs.objects import Function
from libs.llmbase import LLM
from libs.prompt import FunctionAnalysisPrompt
Arbitrary_file_access_prompt = """
    #设定
    你是一个分析经验丰富的代码安全分析人员，能够精准分析函数功能。
    #输入
    ##函数代码片段：<包含了反编译伪代码，C，C++，java，python，go，js等语言>
    #任务
    1.查看当前上传的函数代码片段的函数名
    2.分析该函数代码片段调用了哪些函数，准确找出其调用所有的函数
    3.分析该函数代码是否调用了读取文件的函数，如open()、ReadFile()等函数。
    4. 让我们一步步地进行推理。
    #输出结果
    请务必严格按照以下JSON格式返回分析结果，请确保生成格式正确的结果：
    ```json
    {
        function_name:上传的函数名称，
        file_read:bool(是否进行文件读取),
        call_sites:[函数名1,函数名2,函数名3,......,函数名n](被调用的函数名列表)
    }```
    #限制
    1. 输出结果以JSON的纯文本形式返回,除json外不要返回任何内容,确保JSON格式标准化，输出前后无多余空行或注释，严格按照要求格式输出。
    """

get_cal_site_prompt = """
    #设定
    你是一个分析经验丰富的代码安全分析人员，能够精准分析函数。
    #输入
    ##函数代码片段：<包含了反编译伪代码，C，C++，java，python，go，js等语言>
    #任务
    1.查看当前上传的函数代码片段的函数名
    2.分析该函数代码片段调用了哪些非库函数(即非系统函数或者公共库函数)，准确找出其调用所有的函数
    3. 让我们一步步地进行推理。
    #输出结果
    请务必严格按照以下JSON格式返回分析结果，请确保生成格式正确的结果：
    ```json
    {
        function_name:上传的函数名称，
        call_sites:[函数名1,函数名2,函数名3,......,函数名n](被调用的函数名列表)
    }```
    #限制
    1. 输出结果以JSON的纯文本形式返回,除json外不要返回任何内容,确保JSON格式标准化，输出前后无多余空行或注释，严格按照要求格式输出。
    """

get_cal_site_prompt = """
    #设定
    你是一个分析经验丰富的代码安全分析人员，能够精准分析函数。
    #输入
    ##函数代码片段：<包含了反编译伪代码，C，C++，java，python，go，js等语言>
    #任务
    1.查看当前上传的函数代码片段的函数名
    2.分析该函数代码片段调用了哪些非库函数(即非系统函数或者公共库函数)，准确找出其调用所有的函数
    3. 让我们一步步地进行推理。
    #输出结果
    请务必严格按照以下JSON格式返回分析结果，请确保生成格式正确的结果：
    ```json
    {
        function_name:上传的函数名称，
        call_sites:[函数名1,函数名2,函数名3,......,函数名n](被调用的函数名列表)
    }```
    #限制
    1. 输出结果以JSON的纯文本形式返回,除json外不要返回任何内容,确保JSON格式标准化，输出前后无多余空行或注释，严格按照要求格式输出。
    """


function_name = "sub_12A3C"

function_body = """
// Function at 0x12A3C
void __fastcall sub_12A3C(int a1)
{
  unsigned int v2; // r1
  int v3; // r10
  int v4; // r7
  unsigned int v5; // r5
  bool v6; // zf
  int v7; // r3
  char v8; // r3
  int v9; // r2
  unsigned int v10; // r5
  int v11; // r3
  unsigned int v12; // r5
  bool v13; // cc
  int v14; // r3
  _BYTE *v15; // r3
  int v16; // r3
  const char *v17; // r9
  size_t v18; // r7
  size_t v19; // r0
  char *v20; // r0
  char *v21; // r7
  int i; // r9
  const char *v23; // r7
  size_t v24; // r0
  char *v25; // r0
  char *v26; // r5
  int v27; // r3
  char *v28; // r0
  const char *v29; // r10
  int v30; // r6
  size_t v31; // r10
  size_t v32; // r0
  char *v33; // r0
  char *v34; // r10
  int v35; // r9
  const char *v36; // r11
  const char *v37; // r9
  size_t v38; // r7
  size_t v39; // r0
  char *v40; // r0
  int v41; // r11
  struct tm *v42; // r0
  int v43; // r0
  const char **v44; // r3
  int v45; // r5
  int v46; // r5
  char *v47; // r0
  struct tm *v48; // r0
  int v49; // r0
  const char *v50; // r2
  char *v51; // r0
  size_t v52; // r5
  ssize_t v53; // r0
  ssize_t v54; // r0
  signed int v55; // r4
  char *v56; // r5
  const char *v57; // [sp+0h] [bp-3580h]
  const char *v58; // [sp+4h] [bp-357Ch]
  time_t timer; // [sp+Ch] [bp-3574h] BYREF
  char v60[16]; // [sp+10h] [bp-3570h] BYREF
  char v61[80]; // [sp+60h] [bp-3520h] BYREF
  struct stat stat_buf; // [sp+B0h] [bp-34D0h] BYREF
  struct stat v63; // [sp+108h] [bp-3478h] BYREF
  char v64[1024]; // [sp+160h] [bp-3420h] BYREF
  char v65[9248]; // [sp+1160h] [bp-2420h] BYREF

  v2 = *(_DWORD *)(a1 + 20);
  if ( *(_DWORD *)(a1 + 8) && !v2 )
    goto LABEL_3;
  if ( !v2 )
  {
    v3 = *(_DWORD *)(a1 + 16);
    v4 = 0;
    while ( 1 )
    {
      v5 = *(unsigned __int8 *)(v3 + v4);
      v6 = v5 == 0;
      if ( *(_BYTE *)(v3 + v4) )
        v6 = v5 == 63;
      if ( v6 )
        break;
      if ( v5 == 43 )
      {
        LOBYTE(v5) = 32;
      }
      else
      {
        if ( v5 == 37 )
        {
          v7 = v3 + v4;
          v4 += 2;
          v8 = *(_BYTE *)(v7 + 1);
          v9 = *(unsigned __int8 *)(v3 + v4);
          v10 = (unsigned __int8)(v8 - 48);
          if ( v10 > 9 )
            LOBYTE(v10) = (v8 & 0xDF) - 55;
          v11 = (unsigned __int8)(16 * v10);
          v12 = (unsigned __int8)(v9 - 48);
          v13 = v12 > 9;
          if ( v12 <= 9 )
            v5 = v12 | v11;
          else
            v5 = v9 & 0xFFFFFFDF;
          if ( v13 )
            v5 = (unsigned __int8)((v5 - 55) | v11);
        }
        if ( v5 == 47 && v2 )
        {
          if ( *((_BYTE *)&v63.__unused5 + v2 + 3) == 47 )
            --v2;
          else
            v2 = sub_129C4(v64);
        }
      }
      v64[v2++] = v5;
      ++v4;
      if ( v2 >= 0x1000 )
      {
        *_errno_location() = 36;
        *(_DWORD *)(a1 + 20) = dword_2D2C4;
        v14 = 7;
        goto LABEL_79;
      }
    }
    if ( v2 && *((_BYTE *)&v63.__unused5 + v2 + 3) != 47 )
      v2 = sub_129C4(v64);
    *(_DWORD *)(a1 + 20) = v64;
    v64[v2] = 0;
  }
  v15 = *(_BYTE **)(a1 + 20);
  if ( !v15[1] || !*v15 )
    *(_DWORD *)(a1 + 20) = "/./";
  if ( sub_189C4((char *)(*(_DWORD *)(a1 + 20) + 1), &stat_buf) < 0 )
  {
    if ( *(_DWORD *)(a1 + 8) )
      goto LABEL_3;
    v16 = *_errno_location();
    if ( v16 == 13 )
      goto LABEL_77;
    if ( v16 != 2 )
    {
LABEL_78:
      *(_DWORD *)(a1 + 20) = dword_2D2C8;
      v14 = 8;
      goto LABEL_79;
    }
    v17 = *(const char **)(config + 24);
    if ( !v17 )
      goto LABEL_73;
    v18 = strlen(*(const char **)(a1 + 20));
    v19 = strlen(v17);
    v20 = (char *)malloc(v18 + v19 + 1);
    v21 = v20;
    if ( !v20 )
    {
LABEL_68:
      *(_DWORD *)(a1 + 8) = 8;
      v27 = dword_2D2C8;
LABEL_69:
      *(_DWORD *)(a1 + 20) = v27;
LABEL_80:
      sub_12A3C(a1);
      return;
    }
    strcpy(v20, v17);
    if ( !sub_189C4(v21 + 1, &stat_buf) )
    {
      *(_DWORD *)(a1 + 8) = 4;
LABEL_71:
      *(_DWORD *)(a1 + 20) = v21;
      goto LABEL_80;
    }
    free(v21);
  }
  if ( (stat_buf.st_mode & 0xF000) == 0x4000 )
  {
    if ( *(_BYTE *)(*(_DWORD *)(a1 + 20) + strlen(*(const char **)(a1 + 20)) - 1) != 47 )
    {
      v23 = *(const char **)(a1 + 16);
      v24 = strlen(v23);
      v25 = (char *)malloc(v24 + 2);
      *(_DWORD *)(a1 + 24) = v25;
      v26 = v25;
      if ( v25 )
      {
        v28 = strchr(v23, 63);
        v29 = v28;
        if ( v28 )
        {
          v30 = v28 - v23;
          strncpy(v26, v23, v28 - v23);
          v26[v30] = 47;
          strcpy(&v26[v30 + 1], v29);
        }
        else
        {
          sprintf(v26, "%s/", v23);
        }
        *(_DWORD *)(a1 + 8) = 1;
        v27 = dword_2D2AC;
      }
      else
      {
        *(_DWORD *)(a1 + 8) = 8;
        v27 = dword_2D2C8;
      }
      goto LABEL_69;
    }
    for ( i = 0; i < *(_DWORD *)(config + 12); ++i )
    {
      v58 = *(const char **)(a1 + 20);
      v57 = *(const char **)(*(_DWORD *)(config + 16) + 4 * i);
      v31 = strlen(v58);
      v32 = strlen(v57);
      v33 = (char *)malloc(v31 + v32 + 1);
      v34 = v33;
      if ( !v33 )
        goto LABEL_68;
      sprintf(v33, "%s%s", v58, v57);
      if ( !sub_189C4(v34 + 1, &stat_buf) )
      {
        *(_DWORD *)(a1 + 20) = v34;
        goto LABEL_80;
      }
      free(v34);
    }
  }
  if ( (stat_buf.st_mode & 0xF000) != 0x8000 )
    goto LABEL_77;
  *(_DWORD *)(a1 + 28) = sub_14FCC(*(_DWORD *)(a1 + 20));
  v35 = config;
  if ( *(_DWORD *)(config + 28) != 1 )
  {
    v36 = *(const char **)(a1 + 20);
    if ( strncmp(v36, "/cgi-bin/", 9u) && strncmp(v36, "/./cgi-bin/", 0xBu) )
      goto LABEL_74;
    if ( (stat_buf.st_mode & 0x49) != 0 )
      goto LABEL_62;
    v37 = *(const char **)(v35 + 24);
    if ( v37 )
    {
      v38 = strlen(v36);
      v39 = strlen(v37);
      v40 = (char *)malloc(v38 + v39 + 1);
      v21 = v40;
      if ( v40 )
      {
        strcpy(v40, v37);
        if ( sub_189C4(v21 + 1, &stat_buf) )
        {
          free(v21);
          return;
        }
        goto LABEL_71;
      }
      goto LABEL_68;
    }
LABEL_73:
    *(_DWORD *)(a1 + 20) = dword_2D2B8;
    v14 = 4;
LABEL_79:
    *(_DWORD *)(a1 + 8) = v14;
    goto LABEL_80;
  }
  if ( (stat_buf.st_mode & 0x49) != 0 )
  {
LABEL_62:
    sub_14EC0(a1);
    return;
  }
LABEL_74:
  v41 = open((const char *)(*(_DWORD *)(a1 + 20) + 1), 0);
  if ( v41 < 0 )
  {
    if ( !*(_DWORD *)(a1 + 8) )
    {
      if ( *_errno_location() == 13 )
      {
LABEL_77:
        *(_DWORD *)(a1 + 20) = dword_2D2B4;
        v14 = 3;
        goto LABEL_79;
      }
      goto LABEL_78;
    }
LABEL_3:
    sub_13520(a1);
    return;
  }
  timer = time(0);
  v42 = gmtime(&timer);
  strftime(v60, 0x50u, "%a, %d %b %Y %H:%M:%S GMT", v42);
  v43 = sprintf(v65, "HTTP/1.1 %s\r\n", message[*(_DWORD *)(a1 + 8)]);
  v44 = *(const char ***)(a1 + 28);
  v45 = v43;
  if ( v44 )
  {
    v46 = v43 + sprintf(&v65[v43], "Content-type: %s\r\n", *v44);
    v47 = &v65[v46];
    v45 = v46 + 28;
    strcpy(v47, "Cache-Control: max-age=600\r\n");
  }
  if ( !strstr(v60, "1970") )
    v45 += sprintf(&v65[v45], "Date: %s\r\n", v60);
  if ( sub_189C4((char *)(*(_DWORD *)(a1 + 20) + 1), &v63) >= 0 )
  {
    v48 = gmtime((const time_t *)&v63.st_mtim);
    strftime(v61, 0x50u, "%a, %d %b %Y %H:%M:%S GMT", v48);
    v49 = sprintf(&v65[v45], "Last-Modified: %s\r\nContent-length: %d\r\n", v61, v63.st_size);
    v50 = *(const char **)(config + 32);
    v45 += v49;
    if ( v50 )
      v45 += sprintf(&v65[v45], "X-HNDP-DeviceId: %s\r\n", v50);
  }
  v51 = &v65[v45];
  v52 = v45 + 21;
  strcpy(v51, "Connection: close\r\n\r\n");
  while ( v52 )
  {
    v53 = write(1, v65, v52);
    if ( v53 < 0 )
    {
      if ( *_errno_location() != 11 )
        break;
    }
    else
    {
      v52 -= v53;
    }
  }
LABEL_96:
  v55 = read(v41, v65, 0x2400u);
  if ( v55 > 0 )
  {
    v56 = v65;
    while ( 1 )
    {
      v54 = write(1, v56, v55);
      if ( v54 <= 0 )
        break;
      v55 -= v54;
      v56 += v54;
      if ( !v55 )
        goto LABEL_96;
    }
  }
  close(v41);
}"""


sysprompt = get_cal_site_prompt




def function_analysis_test():
    llm = LLM()
    out_put = llm.communicate(sysprompt,function_body)
    print(out_put)


if __name__ == "__main__":
    function_analysis_test()