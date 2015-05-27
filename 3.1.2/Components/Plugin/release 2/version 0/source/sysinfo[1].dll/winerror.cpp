

#include "winerror.h"
#include "nsisapi.h"


void PushWinError(DWORD error)
{
	LPVOID lpMsgBuf;
	
	FormatMessage( 
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM | 
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &lpMsgBuf,
		0,
		NULL 
	);

	pushstring((char*)lpMsgBuf);

	LocalFree( lpMsgBuf );
}

void PushLastError(void)
{
	PushWinError(GetLastError());
}