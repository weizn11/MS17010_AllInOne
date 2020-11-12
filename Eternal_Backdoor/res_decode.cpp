#include "res_decode.h"
#include "encode.h"

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>

enum _get_decode_ret_
{
    GET_DECODE_NORMAL = 0,
    GET_DECODE_ERR_MALLOC,
    GET_DECODE_ERR_DECODE
};
ENC_RES_DESC get_decode_hex(char *pB64Buf)
{
    ENC_RES_DESC encResDesc;
    char *pDecodeBuf = NULL;
    int b64StrLen = 0;
    int hexLen = 0;

    memset(&encResDesc, 0x00, sizeof(encResDesc));

    b64StrLen = strlen(pB64Buf);
    pDecodeBuf = (char *)malloc(b64StrLen);
    if(pDecodeBuf == NULL)
    {
        encResDesc.status = GET_DECODE_ERR_MALLOC;
        return encResDesc;
    }
    memset(pDecodeBuf, 0x00, b64StrLen);

    hexLen = base64_decode(pB64Buf, (unsigned char *)pDecodeBuf);
    if(hexLen <= 0)
    {
        encResDesc.status = GET_DECODE_ERR_DECODE;
        return encResDesc;
    }
    encResDesc.pBufAddr = pDecodeBuf;
    encResDesc.bufSize = hexLen;

    return encResDesc;
}
