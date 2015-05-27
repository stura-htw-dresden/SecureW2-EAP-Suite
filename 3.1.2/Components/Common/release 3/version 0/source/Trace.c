/*
    SecureW2, Copyright (C) Alfa & Ariss

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  

    See the GNU General Public License for more details, included in the file 
    LICENSE which you should have received along with this program.

    If you did not receive a copy of the GNU General Public License, 
    write to the Free Software Foundation, Inc., 675 Mass Ave, 
    Cambridge, MA 02139, USA.

    Alfa & Ariss can be contacted at http://www.alfa-ariss.com
*/
//
// Name: Trace.c
// Description: Contains the functionality used for tracing
// Author: Tom Rixom
// Created: 17 December 2002
// Version: 1.0
// Last revision: <Date of last revision>
//
// ----------------------------- Revisions -------------------------------
//
// Revision - <Date of revision> <Version of file which has been revised> <Name of author>
// <Description of what has been revised>
//

#include "Common.h"

#include <stdio.h>
#include <time.h>

//
// Name: AA_Trace
// Description: Main trace function
// Author: Tom Rixom
// Created: 17 December 2002
//
void
AA_Trace( TCHAR* fmt, ... ) 
{
	SYSTEMTIME	SystemTime;
	FILE	*f;
	va_list vlist;

#ifdef _WIN32_WCE
	char *AA_TRACE_FILE = { "\\aa_sw2_trace.log" };
#else
	char *AA_TRACE_FILE = { "c:\\aa_sw2_trace.log" };
#endif

	if( ( f = fopen( AA_TRACE_FILE, "a+" ) ) )
	{
		GetLocalTime( &SystemTime );

		_ftprintf( f, TEXT( "%d:%d:%d:%d::%s::%x::" ), SystemTime.wHour, SystemTime.wMinute, SystemTime.wSecond, SystemTime.wMilliseconds, "AA_SW2", GetCurrentProcessId() );

		va_start( vlist, fmt );
		_vftprintf( f, fmt, vlist );
		va_end( vlist );

		_ftprintf( f, TEXT( "\n" ) );

		fflush( f );

		fclose( f );
	}
}