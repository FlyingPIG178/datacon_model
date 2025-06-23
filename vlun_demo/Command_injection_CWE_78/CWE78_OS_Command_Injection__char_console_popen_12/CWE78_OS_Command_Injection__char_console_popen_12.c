#include "std_testcase.h"
#include <wchar.h>

#ifdef _WIN32
#define FULL_COMMAND "dir "
#else
#include <unistd.h>
#define FULL_COMMAND "ls "
#endif

#ifdef _WIN32
#define POPEN _popen
#define PCLOSE _pclose
#else
#define POPEN popen
#define PCLOSE pclose
#endif

/* ===== 新增函数：获取控制台输入（不过滤） ===== */
void get_unfiltered_input(char *data, size_t maxLen)
{
    size_t dataLen = strlen(data);
    if (maxLen - dataLen > 1)
    {
        if (fgets(data + dataLen, (int)(maxLen - dataLen), stdin) != NULL)
        {
            dataLen = strlen(data);
            if (dataLen > 0 && data[dataLen - 1] == '\n')
            {
                data[dataLen - 1] = '\0';
            }
        }
        else
        {
            printLine("fgets() failed");
            data[dataLen] = '\0';
        }
    }
}


void CWE78_OS_Command_Injection__char_console_popen_12_bad()
{
    char * data;
    char data_buf[100] = FULL_COMMAND;
    data = data_buf;

    if (globalReturnsTrueOrFalse())
    {
        /* 使用外部函数获取用户输入（无过滤） */
        get_unfiltered_input(data, sizeof(data_buf));
    }
    else
    {
        /* FIX: Append a fixed string to data (not user / external input) */
        strcat(data, "*.*");
    }

    {
        FILE *pipe;
        /* POTENTIAL FLAW: Execute command in data possibly leading to command injection */
        pipe = POPEN(data, "w");
        if (pipe != NULL)
        {
            PCLOSE(pipe);
        }
    }
}
