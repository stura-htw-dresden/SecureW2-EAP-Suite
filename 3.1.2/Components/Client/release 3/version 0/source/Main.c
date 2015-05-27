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
// Name: Main.c
// Description: Contains the DLL entry points for the main David DLL
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
#define AA_MAIN_C

#include "Main.h"

//
// Name: DLLMain
// Description: Main DLL entry point
// Author: Tom Rixom
// Created: 17 December 2002
//
BOOL WINAPI
DllMain(	IN HINSTANCE   hInstance,
			IN DWORD       dwReason,
			IN LPVOID		lpVoid )
{
    if( dwReason == DLL_PROCESS_ATTACH )
    {
		AA_TRACE( ( TEXT( "DllMain::DLL_PROCESS_ATTACH" ) ) );

        ghInstance = hInstance;

		if( ( hDLL = LoadLibrary( L"aa_sw2_res.dll" ) ) )
		{
			ghInstance = hDLL;
		}
    }
    else if ( dwReason == DLL_PROCESS_DETACH )
    {
		if( hDLL )
			FreeLibrary( hDLL );

		AA_TRACE( ( TEXT( "DllMain::DLL_PROCESS_DETACH" ) ) );
    }

    return TRUE;
}

//
// Name: DllRegisterServer
// Description: Is called by regsvr32.exe
// Author: Tom Rixom
// Created: 17 December 2002
//
STDAPI
DllRegisterServer( IN VOID )
{
	AA_TRACE( ( TEXT( "DllRegisterServer" ) ) );

	return S_OK;
}

//
// Name: DllUnregisterServer
// Description: Is called by regsvr32.exe /U
// Author: Tom Rixom
// Created: 17 December 2002
//
STDAPI
DllUnregisterServer( IN VOID )
{
	AA_TRACE( ( TEXT( "DllUnregisterServer" ) ) );

	return S_OK;
}