

#ifndef __X18_WINERROR_H
#define __X18_WINERROR_H


#include "nsisapi.h"


void PushLastError(void);
void PushWinError(DWORD);


#endif