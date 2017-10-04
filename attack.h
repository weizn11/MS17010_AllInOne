#ifndef ATTACK_H_INCLUDED
#define ATTACK_H_INCLUDED

#include "global.h"

#define RETRY_COUNT 5

int attack_target(TARGET_DESC *pTargetDesc, int retryCount);

#endif // ATTACK_H_INCLUDED
