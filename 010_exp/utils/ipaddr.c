#include "ipaddr.h"
#include "ex_string.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int verify_ip_format(char *ipStr)
{
    char *pSaveSplit = NULL;
    char *pSplit = NULL;
    char ipBuf[100];
    char *pBuff = NULL;
    int splitCount = 0;
    int tmp = 0;

    if(strlen(ipStr) > 20)
        return -3;

    memset(ipBuf, 0x00, sizeof(ipBuf));

    strcat(ipBuf, ipStr);
    pBuff = ipBuf;
    while((pSplit = strtok_r(pBuff, ".", &pSaveSplit)) != NULL)
    {
        pBuff = NULL;
        splitCount++;
        tmp = atoi(pSplit);
        if(tmp < 0 || tmp > 255)
        {
            return -1;
        }
    }

    if(splitCount != 4)
        return -2;

    return 0;
}
