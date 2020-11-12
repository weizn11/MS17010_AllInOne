#ifndef RES_DECODE_H_INCLUDED
#define RES_DECODE_H_INCLUDED

typedef struct _Enc_Res_Desc_
{
    char *pBufAddr;        //malloc
    int bufSize;
    int status;
}ENC_RES_DESC;

ENC_RES_DESC get_decode_hex(char *pB64Buf);

#endif // RES_DECODE_H_INCLUDED
