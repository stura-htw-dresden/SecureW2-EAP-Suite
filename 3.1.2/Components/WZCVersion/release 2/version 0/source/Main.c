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
#ifdef UNICODE
#undef UNICODE
#endif

#ifdef _UNICODE
#undef _UNICODE
#endif

#include <windows.h>
#include <stdio.h>

#include "exdll.h"

HINSTANCE	g_hInstance;

typedef enum _AA_WZCS_DLL_VERSION
{
	WZCS_DLL_VERSION_5_0_6034,
	WZCS_DLL_VERSION_5_0_6604,
	WZCS_DLL_VERSION_5_1_2600,
	WZCS_DLL_VERSION_5_1_2600_1106,
	WZCS_DLL_VERSION_5_1_2600_1181,
	WZCS_DLL_VERSION_5_1_2600_1276,
	WZCS_DLL_VERSION_5_1_2600_2149

} AA_WZCS_DLL_VERSION;

void 
__declspec ( dllexport )
Get( HWND hwndParent, 
	int string_size, 
	char *variables, 
	stack_t **stacktop )
{
	VS_FIXEDFILEINFO*	pvsFileInfo;
	DWORD				dwvsFileInfoSize;
	PBYTE				pbVersion;
	DWORD				dwHandle = 0;
	DWORD				cbVersion;
	DWORD				dwWZCSDllVersion;
	CHAR				pcTemp[256];
	DWORD				dwRet;

	EXDLL_INIT();

	dwRet = NO_ERROR;

	cbVersion = GetFileVersionInfoSize( "wzcsapi.dll", &dwHandle );

	if( ( pbVersion = ( PBYTE ) malloc( cbVersion ) ) )
	{
		if( GetFileVersionInfo( "wzcsapi.dll",
								0,
								cbVersion,
								pbVersion ) )
		{
			dwvsFileInfoSize = 0;

			if( VerQueryValue( pbVersion, "\\", ( LPVOID*) &pvsFileInfo, &dwvsFileInfoSize ) )
			{
				if( pvsFileInfo->dwProductVersionLS == 143857554 )
				{
					dwWZCSDllVersion = WZCS_DLL_VERSION_5_0_6034; // Windows 2000 SP3 + hotfix
				}
				else if( pvsFileInfo->dwProductVersionLS == 143858124 )
				{
					dwWZCSDllVersion = WZCS_DLL_VERSION_5_0_6604; // Windows 2000 SP4
				}
				else if( pvsFileInfo->dwProductVersionLS == 170393600 )
				{
					dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600; // Windows XP SP0
				}
				else if( pvsFileInfo->dwProductVersionLS == 170394706 )
				{
					dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600_1106; // Windows XP SP1
				}
				else if( pvsFileInfo->dwProductVersionLS == 170394781 )
				{
					dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600_1181; // Windows XP SP1 + WPA
				}
				else if( pvsFileInfo->dwProductVersionLS == 170394876 )
				{
					dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600_1276; // Windows XP SP1 + WPA Rollup
				}				
				else if( pvsFileInfo->dwProductVersionLS >= 170395749 )
				{
					dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600_2149; // Windows XP SP2 Release candidate 2
				}
				else
				{
					dwRet = ERROR_NOT_SUPPORTED;
				}
			}
			else
				dwRet = ERROR_NOT_SUPPORTED;
		}
		else
		{
			dwRet = ERROR_NOT_SUPPORTED;
		}

		free( pbVersion );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	if( dwRet == NO_ERROR )
	{
		sprintf( pcTemp, "%ld", dwWZCSDllVersion );
	}
	else
	{
		sprintf( pcTemp, "%ld", dwRet );
	}

	pushstring( pcTemp );
}

BOOL WINAPI
DllMain(	IN HINSTANCE   hInstance,
			IN DWORD       dwReason,
			IN LPVOID		lpVoid )
{
	g_hInstance = hInstance;

	return TRUE;
}