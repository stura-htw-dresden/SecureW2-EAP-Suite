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
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <stdio.h>

#include "WZCLib.h"
#include "..\..\..\..\Common\release 3\version 0\source\Common.h"

#ifdef AA_WZC_LIB_2K_XP_SP0
#include "nuiouser.h"
#endif

DWORD
WZCInit( IN PAA_WZC_LIB_CONTEXT *ppWZCContext )
{
	PAA_WZC_LIB_CONTEXT pWZCContext;
	VS_FIXEDFILEINFO*	pvsFileInfo;
	DWORD				dwvsFileInfoSize;
	PBYTE				pbVersion;
	DWORD				dwHandle = 0;
	DWORD				cbVersion;
	DWORD				dwRet;

	dwRet = NO_ERROR;

	if( ( *ppWZCContext = ( PAA_WZC_LIB_CONTEXT ) malloc( sizeof( AA_WZC_LIB_CONTEXT ) ) ) )
	{
		memset( *ppWZCContext, 0, sizeof( AA_WZC_LIB_CONTEXT ) );

		pWZCContext = *ppWZCContext;

		//
		// See if zero config API present in system
		//
		if( ( pWZCContext->hWZCDll = LoadLibrary( L"wzcsapi.dll" ) ) )
		{
			//
			// Check file version
			//
			cbVersion = GetFileVersionInfoSize( L"wzcsapi.dll", &dwHandle );

			if( ( pbVersion = ( PBYTE ) malloc( cbVersion ) ) )
			{
				if( GetFileVersionInfo( L"wzcsapi.dll",
										0,
										cbVersion,
										pbVersion ) )
				{
					dwvsFileInfoSize = 0;

					if( VerQueryValue( pbVersion, L"\\", ( LPVOID*) &pvsFileInfo, &dwvsFileInfoSize ) )
					{
						AA_TRACE( ( TEXT( "WZCInit::%ld" ), pvsFileInfo->dwProductVersionLS ) );

						if( pvsFileInfo->dwProductVersionLS == 143857554 )
						{
							pWZCContext->dwWZCSDllVersion = WZCS_DLL_VERSION_5_0_6034;
						}
						else if( pvsFileInfo->dwProductVersionLS == 143858124 )
						{
							pWZCContext->dwWZCSDllVersion = WZCS_DLL_VERSION_5_0_6604;
						}
						else if( pvsFileInfo->dwProductVersionLS == 170393600 )
						{
							pWZCContext->dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600;
						}
						else if( pvsFileInfo->dwProductVersionLS == 170394706 )
						{
							pWZCContext->dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600_1106;
						}
						else if( pvsFileInfo->dwProductVersionLS == 170394781 )
						{
							pWZCContext->dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600_1181;
						}
						else if( pvsFileInfo->dwProductVersionLS == 170394876 )
						{
							pWZCContext->dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600_1276; // Windows XP SP1 + WPA Rollup
						}				
						else if( pvsFileInfo->dwProductVersionLS >= 170395780 )
						{
							pWZCContext->dwWZCSDllVersion = WZCS_DLL_VERSION_5_1_2600_2149;
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
				pWZCContext->pfnWZCEnumInterfaces = ( PFN_WZCEnumInterfaces ) GetProcAddress( pWZCContext->hWZCDll, "WZCEnumInterfaces" );

#ifdef AA_WZC_LIB_XP_SP2
				pWZCContext->pfnWZCQueryInterface	= ( PFN_WZCQueryInterface ) GetProcAddress( pWZCContext->hWZCDll, "WZCQueryInterface" );
				pWZCContext->pfnWZCSetInterface		= ( PFN_WZCQueryInterface ) GetProcAddress( pWZCContext->hWZCDll, "WZCSetInterface" );
				pWZCContext->pfnWZCRefreshInterface	= ( PFN_WZCQueryInterface ) GetProcAddress( pWZCContext->hWZCDll, "WZCRefreshInterface" );
#endif

#ifdef AA_WZC_LIB_XP_SP1
				if( pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
				{
					pWZCContext->pfnWZCQueryInterface_1106		= ( PFN_WZCQueryInterface_1106 ) GetProcAddress( pWZCContext->hWZCDll, "WZCQueryInterface" );
					pWZCContext->pfnWZCSetInterface_1106		= ( PFN_WZCSetInterface_1106 ) GetProcAddress( pWZCContext->hWZCDll, "WZCSetInterface" );
					pWZCContext->pfnWZCRefreshInterface_1106	= ( PFN_WZCRefreshInterface_1106 ) GetProcAddress( pWZCContext->hWZCDll, "WZCRefreshInterface" );
				}
				else
				{
					pWZCContext->pfnWZCQueryInterface_1181		= ( PFN_WZCQueryInterface_1181 ) GetProcAddress( pWZCContext->hWZCDll, "WZCQueryInterface" );
					pWZCContext->pfnWZCSetInterface_1181		= ( PFN_WZCSetInterface_1181 ) GetProcAddress( pWZCContext->hWZCDll, "WZCSetInterface" );
					pWZCContext->pfnWZCRefreshInterface_1181	= ( PFN_WZCRefreshInterface_1181 ) GetProcAddress( pWZCContext->hWZCDll, "WZCRefreshInterface" );
				}
#endif

#ifdef AA_WZC_LIB_2K_XP_SP0
				pWZCContext->pfnWZCQueryInterface	= ( PFN_WZCQueryInterface ) GetProcAddress( pWZCContext->hWZCDll, "WZCQueryInterface" );
				pWZCContext->pfnWZCSetInterface		= ( PFN_WZCSetInterface ) GetProcAddress( pWZCContext->hWZCDll, "WZCSetInterface" );
				pWZCContext->pfnWZCRefreshInterface	= ( PFN_WZCRefreshInterface ) GetProcAddress( pWZCContext->hWZCDll, "WZCRefreshInterface" );
#endif


				pWZCContext->pfnWZCEapolReAuthenticate	= ( PFN_WZCEapolReAuthenticate ) GetProcAddress( pWZCContext->hWZCDll, "WZCEapolReAuthenticate" );

				pWZCContext->pfnWZCEapolGetInterfaceParams = ( PFN_WZCEapolGetInterfaceParams ) GetProcAddress( pWZCContext->hWZCDll, "WZCEapolGetInterfaceParams" );
				pWZCContext->pfnWZCEapolSetInterfaceParams = ( PFN_WZCEapolSetInterfaceParams ) GetProcAddress( pWZCContext->hWZCDll, "WZCEapolSetInterfaceParams" );
				pWZCContext->pfnWZCEapolSetCustomAuthData = ( PFN_WZCEapolSetCustomAuthData ) GetProcAddress( pWZCContext->hWZCDll, "WZCEapolSetCustomAuthData" );
				pWZCContext->pfnWZCEapolGetCustomAuthData = ( PFN_WZCEapolGetCustomAuthData ) GetProcAddress( pWZCContext->hWZCDll, "WZCEapolGetCustomAuthData" );

				pWZCContext->pfnWZCGetEapUserInfo = ( PFN_WZCGetEapUserInfo ) GetProcAddress( pWZCContext->hWZCDll, "WZCGetEapUserInfo" );

#ifndef AA_WZC_LIB_2K_XP_SP0
				pWZCContext->pfnWZCQueryContext = ( PFN_WZCQueryContext ) GetProcAddress( pWZCContext->hWZCDll, "WZCQueryContext" );

				pWZCContext->pfnWZCEapolQueryState = ( PFN_WZCEapolQueryState ) GetProcAddress( pWZCContext->hWZCDll, "WZCEapolQueryState" );
#endif

				//
				// Connected to procs?
				//

#ifdef AA_WZC_LIB_XP_SP2
				if( ( pWZCContext->pfnWZCEnumInterfaces == NULL )			||
					( pWZCContext->pfnWZCQueryInterface == NULL )		||
					( pWZCContext->pfnWZCSetInterface == NULL )		||
					( pWZCContext->pfnWZCRefreshInterface == NULL )	||
					( pWZCContext->pfnWZCEapolReAuthenticate == NULL )		||
					( pWZCContext->pfnWZCEapolGetInterfaceParams == NULL )	||
					( pWZCContext->pfnWZCEapolSetInterfaceParams == NULL )	||
					( pWZCContext->pfnWZCEapolSetCustomAuthData == NULL )	||
					( pWZCContext->pfnWZCEapolGetCustomAuthData == NULL )	||
					( pWZCContext->pfnWZCGetEapUserInfo == NULL )			||
					( pWZCContext->pfnWZCQueryContext == NULL )				||
					( pWZCContext->pfnWZCEapolQueryState == NULL ) )
				{
					dwRet = ERROR_NOT_SUPPORTED;
				}
#endif

#ifdef AA_WZC_LIB_XP_SP1
				//
				// Connected to procs?
				//
				if( pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
				{
					if( ( pWZCContext->pfnWZCEnumInterfaces == NULL )			||
						( pWZCContext->pfnWZCQueryInterface_1106 == NULL )		||
						( pWZCContext->pfnWZCSetInterface_1106 == NULL )		||
						( pWZCContext->pfnWZCRefreshInterface_1106 == NULL )	||
						( pWZCContext->pfnWZCEapolReAuthenticate == NULL )		||
						( pWZCContext->pfnWZCEapolGetInterfaceParams == NULL )	||
						( pWZCContext->pfnWZCEapolSetInterfaceParams == NULL )	||
						( pWZCContext->pfnWZCEapolSetCustomAuthData == NULL )	||
						( pWZCContext->pfnWZCEapolGetCustomAuthData == NULL )	||
						( pWZCContext->pfnWZCGetEapUserInfo == NULL )			||
						( pWZCContext->pfnWZCQueryContext == NULL )				||
						( pWZCContext->pfnWZCEapolQueryState == NULL ) )
					{
						dwRet = ERROR_NOT_SUPPORTED;
					}
				}
				else
				{
					if( ( pWZCContext->pfnWZCEnumInterfaces == NULL )			||
						( pWZCContext->pfnWZCQueryInterface_1181 == NULL )		||
						( pWZCContext->pfnWZCSetInterface_1181 == NULL )		||
						( pWZCContext->pfnWZCRefreshInterface_1181 == NULL )	||
						( pWZCContext->pfnWZCEapolReAuthenticate == NULL )		||
						( pWZCContext->pfnWZCEapolGetInterfaceParams == NULL )	||
						( pWZCContext->pfnWZCEapolSetInterfaceParams == NULL )	||
						( pWZCContext->pfnWZCEapolSetCustomAuthData == NULL )	||
						( pWZCContext->pfnWZCEapolGetCustomAuthData == NULL )	||
						( pWZCContext->pfnWZCGetEapUserInfo == NULL )			||
						( pWZCContext->pfnWZCQueryContext == NULL )				||
						( pWZCContext->pfnWZCEapolQueryState == NULL ) )
					{
						dwRet = ERROR_NOT_SUPPORTED;
					}
				}
#endif

#ifdef AA_WZC_LIB_2K_XP_SP0
				if( ( pWZCContext->pfnWZCEnumInterfaces == NULL )			||
					( pWZCContext->pfnWZCQueryInterface == NULL )			||
					( pWZCContext->pfnWZCSetInterface == NULL )				||
					( pWZCContext->pfnWZCRefreshInterface == NULL )			||
					( pWZCContext->pfnWZCEapolGetInterfaceParams == NULL )	||
					( pWZCContext->pfnWZCEapolSetInterfaceParams == NULL )	||
					( pWZCContext->pfnWZCEapolSetCustomAuthData == NULL )	||
					( pWZCContext->pfnWZCEapolGetCustomAuthData == NULL )	||
					( pWZCContext->pfnWZCGetEapUserInfo == NULL ) )
				{
					dwRet = ERROR_NOT_SUPPORTED;
				}
#endif
			}

			if( dwRet != NO_ERROR )
				FreeLibrary( pWZCContext->hWZCDll );
		}
		else
		{
			dwRet = ERROR_NOT_SUPPORTED;
		}


		if( dwRet != NO_ERROR )
			free( pWZCContext );
    }
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

//
// Builds an initial WZC_WLAN_CONFIG item
// The SSID and InfrastructureMode are used to distinct between WZC_WLAN_CONFIG items
//
DWORD
WZCInitConfig(	IN PAA_WZC_LIB_CONTEXT	pWZCContext, 
				IN WZC_WLAN_CONFIG		*pWZCCfgNew, 
				IN WCHAR				*pwcSSID,
				IN DWORD				dwInfrastructureMode )
{
	PCHAR	pcSSID;
	DWORD	ccSSID;
	DWORD	dwRet;

	dwRet = NO_ERROR;

	ccSSID = ( DWORD ) wcslen( pwcSSID ) + 1;

	if( ( pcSSID = ( PCHAR ) malloc( ccSSID ) ) )
	{
		if( WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID, NULL, NULL ) > 0 )
		{
			memset( pWZCCfgNew, 0, sizeof( WZC_WLAN_CONFIG ) );

			pWZCCfgNew->AuthenticationMode = Ndis802_11AuthModeOpen;

			pWZCCfgNew->Length = sizeof( WZC_WLAN_CONFIG );
/*
			pWZCCfgNew->Configuration.ATIMWindow = 0;
			pWZCCfgNew->Configuration.BeaconPeriod = 0;
			pWZCCfgNew->Configuration.DSConfig = 0;
			pWZCCfgNew->Configuration.FHConfig = 0;
			pWZCCfgNew->Configuration.Length = 0;
*/
			pWZCCfgNew->dwCtlFlags = 0;


			pWZCCfgNew->InfrastructureMode = dwInfrastructureMode;
/*
			pWZCCfgNew->KeyIndex
			pWZCCfgNew->KeyLength
			pWZCCfgNew->KeyMaterial
			pWZCCfgNew->MacAddress
			pWZCCfgNew->NetworkTypeInUse = Ndis802_11DS;
*/
			if( pWZCContext->dwWZCSDllVersion >= WZCS_DLL_VERSION_5_1_2600_1181 )
				pWZCCfgNew->Privacy = 0; // Encryption is not OFF ;)
			else
				pWZCCfgNew->Privacy = 1; // Encryption ON
/*
			pWZCCfgNew->rdUserData
			pWZCCfgNew->Reserved
			pWZCCfgNew->Rssi
*/
			strcpy( pWZCCfgNew->Ssid.Ssid, pcSSID );
			pWZCCfgNew->Ssid.SsidLength = ( ULONG ) strlen( pcSSID );
/*
			pWZCCfgNew->SupportedRates
*/
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcSSID );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

#ifdef AA_WZC_LIB_XP_SP1
DWORD
WZCSetZeroConfState_1106( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN BOOL bOn )
{
	INTF_ENTRY_1106			Intf;
	DWORD					dwOIDFlags;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if( ( dwRet = pWZCContext->pfnWZCQueryInterface_1106( NULL,
														INTF_ALL_FLAGS,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		if( bOn )
			Intf.dwCtlFlags |= INTFCTL_ENABLED;
		else
			Intf.dwCtlFlags &= ~INTFCTL_ENABLED;

		dwRet = pWZCContext->pfnWZCSetInterface_1106( NULL,
														INTF_ALL_FLAGS,
														&Intf,
														&dwOIDFlags );
	}

	return dwRet;
}

DWORD
WZCSetZeroConfState_1181( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN BOOL bOn )
{
	INTF_ENTRY_1181			Intf;
	DWORD					dwOIDFlags;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if( ( dwRet = pWZCContext->pfnWZCQueryInterface_1181( NULL,
														INTF_ALL_FLAGS,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		if( bOn )
			Intf.dwCtlFlags |= INTFCTL_ENABLED;
		else
			Intf.dwCtlFlags &= ~INTFCTL_ENABLED;

		dwRet = pWZCContext->pfnWZCSetInterface_1181( NULL,
														INTF_ALL_FLAGS,
														&Intf,
														&dwOIDFlags );
	}

	return dwRet;
}
#endif

DWORD
WZCSetZeroConfState( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN BOOL bOn )
{
	DWORD dwRet = NO_ERROR;

#ifdef AA_WZC_LIB_XP_SP2
	INTF_ENTRY				Intf;
	DWORD					dwOIDFlags;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if( ( dwRet = pWZCContext->pfnWZCQueryInterface( NULL,
													INTF_ALL_FLAGS,
													&Intf,
													&dwOIDFlags ) ) == NO_ERROR )
	{
		if( bOn )
			Intf.dwCtlFlags |= INTFCTL_ENABLED;
		else
			Intf.dwCtlFlags &= ~INTFCTL_ENABLED;

		dwRet = pWZCContext->pfnWZCSetInterface( NULL,
												INTF_ALL_FLAGS,
												&Intf,
												&dwOIDFlags );
	}

#endif

#ifdef AA_WZC_LIB_XP_SP1

	if( pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCSetZeroConfState_1106( pWZCContext, pwcGUID, bOn );
	}
	else
	{
		dwRet = WZCSetZeroConfState_1181( pWZCContext, pwcGUID, bOn );
	}
#endif

	return dwRet;
}

#ifdef AA_WZC_LIB_XP_SP1
DWORD
WZCSetMediaState_1106( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN BOOL bOn )
{
	INTF_ENTRY_1106			Intf;
	DWORD					dwOIDFlags;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if( bOn )
		Intf.ulMediaState = 1;
	else
		Intf.ulMediaState = 0;

	//
	// First query interface for existing configs
	//
	dwRet = pWZCContext->pfnWZCSetInterface_1106( NULL,
													INTF_NDISMEDIA,
													&Intf,
													&dwOIDFlags );

	return dwRet;
}

DWORD
WZCSetMediaState_1181( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN BOOL bOn )
{
	INTF_ENTRY_1181			Intf;
	DWORD					dwOIDFlags;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if( bOn )
		Intf.ulMediaState = 1;
	else
		Intf.ulMediaState = 0;

	//
	// First query interface for existing configs
	//
	dwRet = pWZCContext->pfnWZCSetInterface_1181( NULL,
													INTF_NDISMEDIA,
													&Intf,
													&dwOIDFlags );

	return dwRet;
}
#endif // AA_WZC_LIB_XP_SP1

DWORD
WZCSetMediaState( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN BOOL bOn )
{
	DWORD dwRet = NO_ERROR;

#ifdef AA_WZC_LIB_XP_SP2
	INTF_ENTRY			Intf;
	DWORD				dwOIDFlags;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if( bOn )
		Intf.ulMediaState = 1;
	else
		Intf.ulMediaState = 0;

	//
	// First query interface for existing configs
	//
	dwRet = pWZCContext->pfnWZCSetInterface( NULL,
											INTF_NDISMEDIA,
											&Intf,
											&dwOIDFlags );

#endif

#ifdef AA_WZC_LIB_XP_SP1

	if( pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCSetMediaState_1106( pWZCContext, pwcGUID, bOn );
	}
	else
	{
		dwRet = WZCSetMediaState_1181( pWZCContext, pwcGUID, bOn );
	}
#endif

	return dwRet;
}

#ifdef AA_WZC_LIB_XP_SP1
DWORD
WZCGetMediaState_1106( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID )
{
	INTF_ENTRY_1106			Intf;
	DWORD					dwOIDFlags;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if( ( dwRet = pWZCContext->pfnWZCQueryInterface_1106( NULL,
															INTF_NDISMEDIA,
															&Intf,
															&dwOIDFlags ) ) == NO_ERROR )
	{
		if( Intf.ulMediaState == 0 )
			dwRet = ERROR_MEDIA_OFFLINE;
	}

	return dwRet;
}

DWORD
WZCGetMediaState_1181( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID )
{
	INTF_ENTRY_1181			Intf;
	DWORD					dwOIDFlags;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if( ( dwRet = pWZCContext->pfnWZCQueryInterface_1181( NULL,
															INTF_NDISMEDIA,
															&Intf,
															&dwOIDFlags ) ) == NO_ERROR )
	{
		if( Intf.ulMediaState == 0 )
			dwRet = ERROR_MEDIA_OFFLINE;
	}

	return dwRet;
}
#endif // AA_WZC_LIB_XP_SP1

DWORD
WZCGetMediaState( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID )
{
	DWORD dwRet = NO_ERROR;

#ifdef AA_WZC_LIB_XP_SP2
	INTF_ENTRY	Intf;
	DWORD		dwOIDFlags;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if( ( dwRet = pWZCContext->pfnWZCQueryInterface( NULL,
													INTF_NDISMEDIA,
													&Intf,
													&dwOIDFlags ) ) == NO_ERROR )
	{
		if( Intf.ulMediaState == 0 )
			dwRet = ERROR_MEDIA_OFFLINE;
	}

#endif

#ifdef AA_WZC_LIB_XP_SP1
	
	if( pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCGetMediaState_1106( pWZCContext, pwcGUID );
	}
	else
	{
		dwRet = WZCGetMediaState_1181( pWZCContext, pwcGUID );
	}
#endif // AA_WZC_LIB_XP_SP1

	return dwRet;
}

#ifdef AA_WZC_LIB_XP_SP1
//
// Retrieves WZC_WLAN_CONFIG item of current SSID belonging to the adapter pwcGUID
//
DWORD
WZCGetCurrentConfig_1106( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT WZC_WLAN_CONFIG *pWZCCfg )
{
	BOOL					bFoundCfg;
	INTF_ENTRY_1106			Intf;
	DWORD					dwOIDFlags;
	PWZC_802_11_CONFIG_LIST	pWZCCfgList;
	WZC_WLAN_CONFIG			WZCCfg;
	PCHAR					pcSSID;
	DWORD					i;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	//
	// First query interface for existing configs
	//
	if( ( dwRet = pWZCContext->pfnWZCQueryInterface_1106( NULL,
														INTF_ALL,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		//
		// Connected to SSID?
		//
		if( Intf.rdSSID.dwDataLen > 0 )
		{
			if( ( pcSSID = ( PCHAR ) malloc( Intf.rdSSID.dwDataLen + 1 ) ) )
			{
				memset( pcSSID, 0, Intf.rdSSID.dwDataLen + 1 );

				memcpy( pcSSID, Intf.rdSSID.pData, Intf.rdSSID.dwDataLen );

//				printf( "Connected to SSID: %s", pcSSID );

				if( Intf.rdBSSIDList.dwDataLen > 0 )
				{
//					printf( "Intf.rdBSSIDList.dwDataLen: %ld", Intf.rdBSSIDList.dwDataLen );
				
					if( ( pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen ) ) )
					{
						memcpy( pWZCCfgList, Intf.rdBSSIDList.pData, Intf.rdBSSIDList.dwDataLen );

//						printf( "pWZCCfgList->NumberOfItems: %ld", pWZCCfgList->NumberOfItems );

						bFoundCfg = FALSE;

						//
						// Add existing items
						//
						for( i=0; i < pWZCCfgList->NumberOfItems; i++ )
						{
							WZCCfg = pWZCCfgList->Config[i];

							if( ( strcmp( WZCCfg.Ssid.Ssid, pcSSID ) == 0 ) &&
								( WZCCfg.InfrastructureMode == Intf.nInfraMode ) )
							{
								memcpy( pWZCCfg, &WZCCfg, sizeof( WZCCfg ) );
								
								bFoundCfg = TRUE;

								i = pWZCCfgList->NumberOfItems;
							}
						}

						if( !bFoundCfg )
							dwRet = ERROR_NO_DATA;

						free( pWZCCfgList );
					}
					else
					{
						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
				}

				free( pcSSID );
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}

	return dwRet;
}

DWORD
WZCGetCurrentConfig_1181( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT WZC_WLAN_CONFIG *pWZCCfg )
{
	BOOL					bFoundCfg;
	INTF_ENTRY_1181			Intf;
	DWORD					dwOIDFlags;
	PWZC_802_11_CONFIG_LIST	pWZCCfgList;
	WZC_WLAN_CONFIG			WZCCfg;
	PCHAR					pcSSID;
//	CHAR					pcTemp[1024];
	DWORD					i;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	//
	// First query interface for existing configs
	//
	if( ( dwRet = pWZCContext->pfnWZCQueryInterface_1181( NULL,
														INTF_ALL,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
/*
		printf( "Intf.dwCapabilities: %ld", Intf.dwCapabilities );
		printf( "Intf.dwCtlFlags: %ld", Intf.dwCtlFlags );
		printf( "Intf.nAuthMode: %ld", Intf.nAuthMode );
		printf( "Intf.nInfraMode: %ld", Intf.nInfraMode );
		printf( "Intf.nWepStatus: %ld", Intf.nWepStatus );
		printf( "Intf.rdBSSID.dwDataLen: %ld", Intf.rdBSSID.dwDataLen );

		memset( pcTemp, 0, sizeof( pcTemp ) );
		memcpy( pcTemp, Intf.rdBSSID.pData, Intf.rdBSSID.dwDataLen );

		printf( "rdBSSID: %s", pcTemp );

		printf( "Intf.rdBSSIDList.dwDataLen: %ld", Intf.rdBSSIDList.dwDataLen );
		printf( "Intf.rdCtrlData.dwDataLen: %ld", Intf.rdCtrlData.dwDataLen );
		printf( "Intf.rdSSID.dwDataLen: %ld", Intf.rdSSID.dwDataLen );

		memset( pcTemp, 0, sizeof( pcTemp ) );
		memcpy( pcTemp, Intf.rdSSID.pData, Intf.rdSSID.dwDataLen );

		printf( "rdSSID: %s", pcTemp );

		printf( "Intf.rdStSSIDList: %ld", Intf.rdStSSIDList.dwDataLen );
		printf( "Intf.ulMediaState: %ld", Intf.ulMediaState );
		printf( "Intf.ulMediaType: %ld", Intf.ulMediaType );
		printf( "Intf.ulPhysicalMediaType: %ld", Intf.ulPhysicalMediaType );
		printf( "Intf.wszDescr: %ws", Intf.wszDescr );
		printf( "Intf.wszGuid: %ws", Intf.wszGuid);
*/
		//
		// Connected to SSID?
		//
		if( Intf.rdSSID.dwDataLen > 0 )
		{
			if( ( pcSSID = ( PCHAR ) malloc( Intf.rdSSID.dwDataLen + 1 ) ) )
			{
				memset( pcSSID, 0, Intf.rdSSID.dwDataLen + 1 );

				memcpy( pcSSID, Intf.rdSSID.pData, Intf.rdSSID.dwDataLen );

//				printf( "Connected to SSID: %s", pcSSID );

				if( Intf.rdBSSIDList.dwDataLen > 0 )
				{
//					printf( "Intf.rdBSSIDList.dwDataLen: %ld", Intf.rdBSSIDList.dwDataLen );
				

					if( ( pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen ) ) )
					{
						memcpy( pWZCCfgList, Intf.rdBSSIDList.pData, Intf.rdBSSIDList.dwDataLen );

//						printf( "pWZCCfgList->NumberOfItems: %ld", pWZCCfgList->NumberOfItems );

						bFoundCfg = FALSE;

						//
						// Add existing items
						//
						for( i=0; i < pWZCCfgList->NumberOfItems; i++ )
						{
							WZCCfg = pWZCCfgList->Config[i];
/*
							printf( "WZCCfgList[%ld]", i );

							printf( "WZCCfg.AuthenticationMode: %ld", WZCCfg.AuthenticationMode );
							printf( "WZCCfg.Configuration.ATIMWindow: %ld", WZCCfg.Configuration.ATIMWindow );
							printf( "WZCCfg.Configuration.BeaconPeriod: %ld", WZCCfg.Configuration.BeaconPeriod );
							printf( "WZCCfg.Configuration.DSConfig: %ld", WZCCfg.Configuration.DSConfig );
							printf( "WZCCfg.Configuration.FHConfig: %ld", WZCCfg.Configuration.FHConfig );
							printf( "WZCCfg.Configuration.Length: %ld", WZCCfg.Configuration.Length );
							printf( "WZCCfg.dwCtlFlags: %ld", WZCCfg.dwCtlFlags );
							printf( "WZCCfg.InfrastructureMode: %ld", WZCCfg.InfrastructureMode );
							printf( "WZCCfg.KeyIndex: %ld", WZCCfg.KeyIndex );
							printf( "WZCCfg.KeyLength: %ld", WZCCfg.KeyLength );
							printf( "WZCCfg.KeyMaterial: %s", A_ByteToHex( WZCCfg.KeyMaterial, 32 ) );
							printf( "WZCCfg.Length: %ld", WZCCfg.Length );
							printf( "WZCCfg.MacAddress: %s", A_ByteToHex( WZCCfg.MacAddress, 6 ) );
							printf( "WZCCfg.NetworkTypeInUse: %ld", WZCCfg.NetworkTypeInUse );
							printf( "WZCCfg.Privacy: %ld", WZCCfg.Privacy );
							printf( "WZCCfg.rdUserData: %s", A_ByteToHex( WZCCfg.rdUserData.pData, WZCCfg.rdUserData.dwDataLen ) );
							printf( "WZCCfg.Reserved: %s", A_ByteToHex( WZCCfg.Reserved, 2 ) );
							printf( "WZCCfg.Rssi: %ld", WZCCfg.Rssi );
							printf( "WZCCfg.Ssid.Ssid: %s", WZCCfg.Ssid.Ssid );
							printf( "WZCCfg.Ssid.length: %ld", WZCCfg.Ssid.SsidLength );
							printf( "WZCCfg.SupportedRates: %s", A_ByteToHex( WZCCfg.SupportedRates, 8 ) );
*/
							if( ( strcmp( WZCCfg.Ssid.Ssid, pcSSID ) == 0 ) &&
								( WZCCfg.InfrastructureMode == Intf.nInfraMode ) )
							{
								memcpy( pWZCCfg, &WZCCfg, sizeof( WZCCfg ) );
								
								bFoundCfg = TRUE;

								i = pWZCCfgList->NumberOfItems;
							}
						}

						if( !bFoundCfg )
							dwRet = ERROR_NO_DATA;

						free( pWZCCfgList );
					}
					else
					{
						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
				}

				free( pcSSID );
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}

	return dwRet;
}
#endif // AA_WZC_LIB_XP_SP1

//
// Retrieves WZC_WLAN_CONFIG item of current SSID belonging to the adapter pwcGUID
//
DWORD
WZCGetCurrentConfig( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT WZC_WLAN_CONFIG *pWZCCfg )
{
	DWORD dwRet;

#ifdef AA_WZC_LIB_XP_SP1
	dwRet = NO_ERROR;

	if( pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCGetCurrentConfig_1106( pWZCContext, pwcGUID, pWZCCfg );
	}
	else
	{
		dwRet = WZCGetCurrentConfig_1181( pWZCContext, pwcGUID, pWZCCfg );
	}
#else
	BOOL					bFoundCfg;
	INTF_ENTRY				Intf;
	DWORD					dwOIDFlags;
	PWZC_802_11_CONFIG_LIST	pWZCCfgList;
	WZC_WLAN_CONFIG			WZCCfg;
	PCHAR					pcSSID;
	DWORD					i;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	AA_TRACE( ( TEXT( "WZCGetCurrentConfig" ) ) );

	//
	// First query interface for existing configs
	//
	if( ( dwRet = pWZCContext->pfnWZCQueryInterface( NULL,
													INTF_ALL,
													&Intf,
													&dwOIDFlags ) ) == NO_ERROR )
	{
		//
		// Connected to SSID?
		//
		if( Intf.rdSSID.dwDataLen > 0 )
		{
			if( ( pcSSID = ( PCHAR ) malloc( Intf.rdSSID.dwDataLen + 1 ) ) )
			{
				memset( pcSSID, 0, Intf.rdSSID.dwDataLen + 1 );

				memcpy( pcSSID, Intf.rdSSID.pData, Intf.rdSSID.dwDataLen );

				AA_TRACE( ( TEXT( "Connected to SSID: %s" ), pcSSID ) );

				if( Intf.rdBSSIDList.dwDataLen > 0 )
				{
					AA_TRACE( ( TEXT( "Intf.rdBSSIDList.dwDataLen: %ld" ), Intf.rdBSSIDList.dwDataLen ) );

					if( ( pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen ) ) )
					{
						memcpy( pWZCCfgList, Intf.rdBSSIDList.pData, Intf.rdBSSIDList.dwDataLen );

						AA_TRACE( ( TEXT( "pWZCCfgList->NumberOfItems: %ld" ), pWZCCfgList->NumberOfItems ) );

						bFoundCfg = FALSE;

						//
						// Add existing items
						//
						for( i=0; i < pWZCCfgList->NumberOfItems; i++ )
						{
							WZCCfg = pWZCCfgList->Config[i];

							if( ( strcmp( WZCCfg.Ssid.Ssid, pcSSID ) == 0 ) &&
								( WZCCfg.InfrastructureMode == Intf.nInfraMode ) )
							{
								memcpy( pWZCCfg, &WZCCfg, sizeof( WZCCfg ) );
								
								bFoundCfg = TRUE;

								i = pWZCCfgList->NumberOfItems;
							}
						}

						if( !bFoundCfg )
							dwRet = ERROR_NO_DATA;

						free( pWZCCfgList );
					}
					else
					{
						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
				}

				free( pcSSID );
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}
#endif

	return dwRet;
}

#ifdef AA_WZC_LIB_XP_SP1
DWORD
WZCGetPrefSSIDList_1106( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT PAA_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	INTF_ENTRY_1106				Intf;
	PAA_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						i;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if( ( dwRet = pWZCContext->pfnWZCQueryInterface_1106( NULL,
														INTF_PREFLIST,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		//
		// Retrieve Preferred List
		//
		if( Intf.rdStSSIDList.dwDataLen > 0 )
		{	
			if( ( pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdStSSIDList.dwDataLen ) ) )
			{
				memcpy( pWZCCfgList, Intf.rdStSSIDList.pData, Intf.rdStSSIDList.dwDataLen );

				if( ( *ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[0], AA_WZC_LIB_CONFIG_PREF ) ) )
				{
					pWZCConfigListItem = *ppWZCConfigListItem;

					for( i=1; i < pWZCCfgList->NumberOfItems; i++ )
					{
						if( ( dwRet = WZCConfigItemAppend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[i], AA_WZC_LIB_CONFIG_PREF ) ) ) == NO_ERROR )
						{
							pWZCConfigListItem = pWZCConfigListItem->pNext;
						}
						else
							break;
					}
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				free( pWZCCfgList );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}

	return dwRet;
}

DWORD
WZCGetPrefSSIDList_1181( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT PAA_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	INTF_ENTRY_1181				Intf;
	PAA_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						i;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	AA_TRACE( ( TEXT( "WZCGetPrefSSIDList_1181" ) ) );

	if( ( dwRet = pWZCContext->pfnWZCQueryInterface_1181( NULL,
														INTF_PREFLIST,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		AA_TRACE( ( TEXT( "pfnWZCQueryInterface_1181" ) ) );

		//
		// Retrieve Preferred List
		//
		if( Intf.rdStSSIDList.dwDataLen > 0 )
		{
			if( ( pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdStSSIDList.dwDataLen ) ) )
			{
				memcpy( pWZCCfgList, Intf.rdStSSIDList.pData, Intf.rdStSSIDList.dwDataLen );

				if( ( *ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[0], AA_WZC_LIB_CONFIG_PREF ) ) )
				{
					pWZCConfigListItem = *ppWZCConfigListItem;

					for( i=1; i < pWZCCfgList->NumberOfItems; i++ )
					{
						if( ( dwRet = WZCConfigItemAppend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[i], AA_WZC_LIB_CONFIG_PREF ) ) ) == NO_ERROR )
						{
							pWZCConfigListItem = pWZCConfigListItem->pNext;
						}
						else
							break;
					}
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				free( pWZCCfgList );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}

	AA_TRACE( ( TEXT( "WZCGetPrefSSIDList_1181::returning: %ld" ), dwRet ) );

	return dwRet;
}
#endif // AA_WZC_LIB_XP_SP1

DWORD
WZCGetPrefSSIDList( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT PAA_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	DWORD	dwRet;

#ifdef AA_WZC_LIB_XP_SP1
	dwRet = NO_ERROR;

	if( pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCGetPrefSSIDList_1106( pWZCContext, pwcGUID, ppWZCConfigListItem );
	}
	else
	{
		dwRet = WZCGetPrefSSIDList_1181( pWZCContext, pwcGUID, ppWZCConfigListItem );
	}
#else
	INTF_ENTRY					Intf;
	PAA_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	DWORD						dwOIDFlags;
	CHAR						pcSSID[MAX_SSID_LEN];
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						i;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if( ( dwRet = pWZCContext->pfnWZCQueryInterface( NULL,
													INTF_ALL,
													&Intf,
													&dwOIDFlags ) ) == NO_ERROR )
	{
		AA_TRACE( ( TEXT( "WZCGetPrefSSIDList::Intf.rdStSSIDList(%ld): %s" ), Intf.rdStSSIDList.dwDataLen, AA_ByteToHex( Intf.rdStSSIDList.pData, Intf.rdStSSIDList.dwDataLen ) ) );

		//
		// Retrieve Preferred List
		//
		if( Intf.rdStSSIDList.dwDataLen > 0 )
		{
			if( ( pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdStSSIDList.dwDataLen ) ) )
			{
				AA_TRACE( ( TEXT( "WZCGetPrefSSIDList::malloced pWZCCfgList" ) ) );

				memcpy( pWZCCfgList, Intf.rdStSSIDList.pData, Intf.rdStSSIDList.dwDataLen );

				AA_TRACE( ( TEXT( "WZCGetPrefSSIDList::pWZCCfgList->NumberOfItems: %ld" ), pWZCCfgList->NumberOfItems ) );

				if( ( *ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[0], AA_WZC_LIB_CONFIG_PREF ) )  )
				{
					AA_TRACE( ( TEXT( "WZCGetPrefSSIDList::WZCConfigItemCreate::successfull" ) ) );

					pWZCConfigListItem = *ppWZCConfigListItem;

					for( i=1; i < pWZCCfgList->NumberOfItems; i++ )
					{
						memset( pcSSID, 0, sizeof( pcSSID ) );

						memcpy( pcSSID, pWZCCfgList->Config->Ssid.Ssid, pWZCCfgList->Config->Ssid.SsidLength );

						if( ( dwRet = WZCConfigItemAppend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[i], AA_WZC_LIB_CONFIG_PREF ) ) ) == NO_ERROR )
						{
							pWZCConfigListItem = pWZCConfigListItem->pNext;
						}
						else
							break;
					}
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				free( pWZCCfgList );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}
#endif

	return dwRet;
}

#ifdef AA_WZC_LIB_XP_SP1
DWORD
WZCSetPrefSSIDList_1106( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN PAA_WZC_CONFIG_LIST_ITEM pWZCConfigListItem )
{
	INTF_ENTRY_1106				Intf;
	PAA_WZC_CONFIG_LIST_ITEM	p;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	p = pWZCConfigListItem;

	Intf.rdStSSIDList.pData = NULL;
	Intf.rdStSSIDList.dwDataLen = 0;

	if( p )
	{
		Intf.rdStSSIDList.dwDataLen = sizeof( WZC_802_11_CONFIG_LIST );

		while( p->pNext )
		{
			Intf.rdStSSIDList.dwDataLen = Intf.rdStSSIDList.dwDataLen + sizeof( WZC_WLAN_CONFIG );

			p = p->pNext;
		}

		p = pWZCConfigListItem;

		if( ( pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdStSSIDList.dwDataLen ) ) )
		{
			pWZCCfgList->Config[0] = p->WZCConfig;

			pWZCCfgList->NumberOfItems = 1;

			while( p->pNext )
			{
				pWZCCfgList->Config[pWZCCfgList->NumberOfItems] = p->pNext->WZCConfig;

				pWZCCfgList->NumberOfItems++;

				p = p->pNext;
			}


			pWZCCfgList->Index = pWZCCfgList->NumberOfItems;

			if( ( Intf.rdStSSIDList.pData = ( PBYTE ) malloc( Intf.rdStSSIDList.dwDataLen ) ) )
			{
				memcpy( Intf.rdStSSIDList.pData, pWZCCfgList, Intf.rdStSSIDList.dwDataLen );
			}
			else
				dwRet = ERROR_NOT_ENOUGH_MEMORY;

			free( pWZCCfgList );
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
	}

	if( dwRet == NO_ERROR )
	{
		dwRet = pWZCContext->pfnWZCSetInterface_1106( NULL,
													INTF_PREFLIST,
													&Intf,
													&dwOIDFlags );

		if( Intf.rdStSSIDList.pData )
			free( Intf.rdStSSIDList.pData );
	}

	return dwRet;
}

DWORD
WZCSetPrefSSIDList_1181( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN PAA_WZC_CONFIG_LIST_ITEM pWZCConfigListItem )
{
	INTF_ENTRY_1181				Intf;
	PAA_WZC_CONFIG_LIST_ITEM	p;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	p = pWZCConfigListItem;

	Intf.rdStSSIDList.pData = NULL;
	Intf.rdStSSIDList.dwDataLen = 0;

	if( p )
	{
		Intf.rdStSSIDList.dwDataLen = sizeof( WZC_802_11_CONFIG_LIST );

		while( p->pNext )
		{
			Intf.rdStSSIDList.dwDataLen = Intf.rdStSSIDList.dwDataLen + sizeof( WZC_WLAN_CONFIG );

			p = p->pNext;
		}

		p = pWZCConfigListItem;

		if( ( pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdStSSIDList.dwDataLen ) ) )
		{
			pWZCCfgList->Config[0] = p->WZCConfig;

			pWZCCfgList->NumberOfItems = 1;

			while( p->pNext )
			{
				pWZCCfgList->Config[pWZCCfgList->NumberOfItems] = p->pNext->WZCConfig;

				pWZCCfgList->NumberOfItems++;

				p = p->pNext;
			}


			pWZCCfgList->Index = pWZCCfgList->NumberOfItems;

			if( ( Intf.rdStSSIDList.pData = ( PBYTE ) malloc( Intf.rdStSSIDList.dwDataLen ) ) )
			{
				memcpy( Intf.rdStSSIDList.pData, pWZCCfgList, Intf.rdStSSIDList.dwDataLen );
			}
			else
				dwRet = ERROR_NOT_ENOUGH_MEMORY;

			free( pWZCCfgList );
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
	}

	if( dwRet == NO_ERROR )
	{
		dwRet = pWZCContext->pfnWZCSetInterface_1181( NULL,
													INTF_PREFLIST,
													&Intf,
													&dwOIDFlags );

		if( Intf.rdStSSIDList.pData )
			free( Intf.rdStSSIDList.pData );
	}

	return dwRet;
}
#endif // AA_WZC_LIB_XP_SP1

DWORD
WZCSetPrefSSIDList( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN PAA_WZC_CONFIG_LIST_ITEM pWZCConfigListItem )
{
	DWORD	dwRet;

#ifdef AA_WZC_LIB_XP_SP1
	dwRet = NO_ERROR;

	if( pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCSetPrefSSIDList_1106( pWZCContext, pwcGUID, pWZCConfigListItem );
	}
	else
	{
		dwRet = WZCSetPrefSSIDList_1181( pWZCContext, pwcGUID, pWZCConfigListItem );
	}
#else
	INTF_ENTRY					Intf;
	PAA_WZC_CONFIG_LIST_ITEM	p;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	p = pWZCConfigListItem;

	Intf.rdStSSIDList.pData = NULL;
	Intf.rdStSSIDList.dwDataLen = 0;

	AA_TRACE( ( TEXT( "WZCSetPrefSSIDList: %s" ), pwcGUID ) );

	if( p )
	{
		Intf.rdStSSIDList.dwDataLen = sizeof( WZC_802_11_CONFIG_LIST );

		while( p->pNext )
		{
			Intf.rdStSSIDList.dwDataLen = Intf.rdStSSIDList.dwDataLen + sizeof( WZC_WLAN_CONFIG );

			p = p->pNext;
		}

		p = pWZCConfigListItem;

		if( ( pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdStSSIDList.dwDataLen ) ) )
		{
			pWZCCfgList->Config[0] = p->WZCConfig;

			AA_TRACE( ( TEXT( "WZCSetPrefSSIDList::WZCCfg[0]: %s" ), AA_ByteToHex( ( PBYTE ) &( pWZCCfgList->Config[0] ), sizeof( WZC_WLAN_CONFIG ) ) ) );

			pWZCCfgList->NumberOfItems = 1;

			while( p->pNext )
			{
				pWZCCfgList->Config[pWZCCfgList->NumberOfItems] = p->pNext->WZCConfig;

				AA_TRACE( ( TEXT( "WZCSetPrefSSIDList::WZCCfg[%ld]: %s" ), pWZCCfgList->NumberOfItems, AA_ByteToHex( ( PBYTE ) &( pWZCCfgList->Config[pWZCCfgList->NumberOfItems] ), sizeof( WZC_WLAN_CONFIG ) ) ) );

				pWZCCfgList->NumberOfItems++;

				p = p->pNext;
			}


			pWZCCfgList->Index = pWZCCfgList->NumberOfItems;

			if( ( Intf.rdStSSIDList.pData = ( PBYTE ) malloc( Intf.rdStSSIDList.dwDataLen ) ) )
			{
				memcpy( Intf.rdStSSIDList.pData, pWZCCfgList, Intf.rdStSSIDList.dwDataLen );
			}
			else
				dwRet = ERROR_NOT_ENOUGH_MEMORY;

			free( pWZCCfgList );
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
	}

	if( dwRet == NO_ERROR )
	{
		dwRet = pWZCContext->pfnWZCSetInterface( NULL,
												INTF_PREFLIST,
												&Intf,
												&dwOIDFlags );

		if( Intf.rdStSSIDList.pData )
			free( Intf.rdStSSIDList.pData );
	}
#endif

	return dwRet;
}

#ifdef AA_WZC_LIB_XP_SP1
DWORD
WZCGetBSSIDList_1106( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT PAA_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	INTF_ENTRY_1106				Intf;
	PAA_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						i;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if( ( dwRet = pWZCContext->pfnWZCQueryInterface_1106( NULL,
														INTF_BSSIDLIST,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		if( Intf.rdBSSIDList.dwDataLen > 0 )
		{	
			if( ( pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen ) ) )
			{
				memcpy( pWZCCfgList, Intf.rdBSSIDList.pData, Intf.rdBSSIDList.dwDataLen );

				if( ( *ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[0], AA_WZC_LIB_CONFIG_BSSID ) ) )
				{
					pWZCConfigListItem = *ppWZCConfigListItem;

					for( i=1; i < pWZCCfgList->NumberOfItems; i++ )
					{
						WZCConfigItemAppend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[i], AA_WZC_LIB_CONFIG_BSSID ) );
						pWZCConfigListItem = pWZCConfigListItem->pNext;
					}
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				free( pWZCCfgList );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}

	return dwRet;
}

DWORD
WZCGetBSSIDList_1181( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT PAA_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	INTF_ENTRY_1181				Intf;
	PAA_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						i;
	DWORD						dwRet;

	AA_TRACE( ( TEXT( "WZCGetBSSIDList_1181: %ws" ), pwcGUID ) );

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if( ( dwRet = pWZCContext->pfnWZCQueryInterface_1181( NULL,
														INTF_BSSIDLIST,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		AA_TRACE( ( TEXT( "WZCGetBSSIDList_1181::pfnWZCQueryInterface_1181" ) ) );

		//
		// Retrieve Preferred List
		//
		if( Intf.rdBSSIDList.dwDataLen > 0 )
		{
			AA_TRACE( ( TEXT( "WZCGetBSSIDList_1181::Intf.rdBSSIDList.dwDataLen %ld" ), Intf.rdBSSIDList.dwDataLen ) );

			if( ( pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen ) ) )
			{
				AA_TRACE( ( TEXT( "WZCGetBSSIDList_1181::malloced" ) ) );

				memcpy( pWZCCfgList, Intf.rdBSSIDList.pData, Intf.rdBSSIDList.dwDataLen );

				if( ( *ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[0], AA_WZC_LIB_CONFIG_BSSID ) ) )
				{
					AA_TRACE( ( TEXT( "WZCGetBSSIDList_1181::WZCConfigItemCreate" ) ) );

					pWZCConfigListItem = *ppWZCConfigListItem;

					for( i=1; i < pWZCCfgList->NumberOfItems; i++ )
					{
						AA_TRACE( ( TEXT( "WZCGetBSSIDList_1181::appending item %ld" ), i ) );

						if( ( WZCConfigItemAppend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[i], AA_WZC_LIB_CONFIG_BSSID ) ) ) == NO_ERROR )
						{
							AA_TRACE( ( TEXT( "WZCGetBSSIDList_1181::appended" ) ) );

							pWZCConfigListItem = pWZCConfigListItem->pNext;
						}
						else
							break;
					}
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				free( pWZCCfgList );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}

	AA_TRACE( ( TEXT( "WZCGetBSSIDList_1181::returning" ) ) );

	return dwRet;
}
#endif // AA_WZC_LIB_XP_SP1

DWORD
WZCGetBSSIDList( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT PAA_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	DWORD	dwRet = NO_ERROR;

#ifdef AA_WZC_LIB_XP_SP2
	INTF_ENTRY					Intf;
	PAA_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						i;

	AA_TRACE( ( TEXT( "WZCGetBSSIDList_1181: %ws" ), pwcGUID ) );

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	if( ( dwRet = pWZCContext->pfnWZCQueryInterface( NULL,
													INTF_BSSIDLIST,
													&Intf,
													&dwOIDFlags ) ) == NO_ERROR )
	{
		AA_TRACE( ( TEXT( "WZCGetBSSIDList::pfnWZCQueryInterface" ) ) );

		//
		// Retrieve Preferred List
		//
		if( Intf.rdBSSIDList.dwDataLen > 0 )
		{
			AA_TRACE( ( TEXT( "WZCGetBSSIDList::Intf.rdBSSIDList.dwDataLen %ld" ), Intf.rdBSSIDList.dwDataLen ) );

			if( ( pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen ) ) )
			{
				AA_TRACE( ( TEXT( "WZCGetBSSIDList::malloced" ) ) );

				memcpy( pWZCCfgList, Intf.rdBSSIDList.pData, Intf.rdBSSIDList.dwDataLen );

				if( ( *ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[0], AA_WZC_LIB_CONFIG_BSSID ) ) )
				{
					AA_TRACE( ( TEXT( "WZCGetBSSIDList::WZCConfigItemCreate" ) ) );

					pWZCConfigListItem = *ppWZCConfigListItem;

					for( i=1; i < pWZCCfgList->NumberOfItems; i++ )
					{
						AA_TRACE( ( TEXT( "WZCGetBSSIDList::appending item %ld" ), i ) );

						if( ( WZCConfigItemAppend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, pWZCCfgList->Config[i], AA_WZC_LIB_CONFIG_BSSID ) ) ) == NO_ERROR )
						{
							AA_TRACE( ( TEXT( "WZCGetBSSIDList::appended" ) ) );

							pWZCConfigListItem = pWZCConfigListItem->pNext;
						}
						else
							break;
					}
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				free( pWZCCfgList );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}
#endif

#ifdef AA_WZC_LIB_XP_SP1

	if( pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCGetBSSIDList_1106( pWZCContext, pwcGUID, ppWZCConfigListItem );
	}
	else
	{
		dwRet = WZCGetBSSIDList_1181( pWZCContext, pwcGUID, ppWZCConfigListItem );
	}
#endif // AA_WZC_LIB_XP_SP1

	return dwRet;
}

#ifdef AA_WZC_LIB_XP_SP1
DWORD
WZCSetBSSIDList_1106( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN PAA_WZC_CONFIG_LIST_ITEM pWZCConfigListItem )
{
	INTF_ENTRY_1106				Intf;
	PAA_WZC_CONFIG_LIST_ITEM	p;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	if( !pWZCConfigListItem  )
		return ERROR_NO_DATA;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	p = pWZCConfigListItem;

	Intf.rdBSSIDList.dwDataLen = sizeof( WZC_802_11_CONFIG_LIST );

	while( p->pNext )
	{
		Intf.rdBSSIDList.dwDataLen = Intf.rdBSSIDList.dwDataLen + sizeof( WZC_WLAN_CONFIG );

		p = p->pNext;
	}

//	printf( "Intf.rdBSSIDList.dwDataLen: %ld", Intf.rdBSSIDList.dwDataLen );

	p = pWZCConfigListItem;

	if( ( pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen ) ) )
	{
		pWZCCfgList->Config[0] = p->WZCConfig;

		pWZCCfgList->NumberOfItems = 1;

		while( p->pNext )
		{
			pWZCCfgList->Config[pWZCCfgList->NumberOfItems] = p->pNext->WZCConfig;

			pWZCCfgList->NumberOfItems++;

			p = p->pNext;
		}

		pWZCCfgList->Index = pWZCCfgList->NumberOfItems;

//		printf( "pWZCCfgList->Index: %ld", pWZCCfgList->Index );
//		printf( "pWZCCfgList->NumberOfItems: %ld", pWZCCfgList->NumberOfItems );

		if( ( Intf.rdBSSIDList.pData = ( PBYTE ) malloc( Intf.rdBSSIDList.dwDataLen ) ) )
		{
			memcpy( Intf.rdBSSIDList.pData, pWZCCfgList, Intf.rdBSSIDList.dwDataLen );

			dwRet = pWZCContext->pfnWZCSetInterface_1106( NULL,
														INTF_BSSIDLIST,
														&Intf,
														&dwOIDFlags );

			free( Intf.rdBSSIDList.pData );
		}

		free( pWZCCfgList );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

DWORD
WZCSetBSSIDList_1181( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN PAA_WZC_CONFIG_LIST_ITEM pWZCConfigListItem )
{
	INTF_ENTRY_1181				Intf;
	PAA_WZC_CONFIG_LIST_ITEM	p;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	if( !pWZCConfigListItem  )
		return ERROR_NO_DATA;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	p = pWZCConfigListItem;

	Intf.rdBSSIDList.dwDataLen = sizeof( WZC_802_11_CONFIG_LIST );

	while( p->pNext )
	{
		Intf.rdBSSIDList.dwDataLen = Intf.rdBSSIDList.dwDataLen + sizeof( WZC_WLAN_CONFIG );

		p = p->pNext;
	}

	p = pWZCConfigListItem;

	if( ( pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen ) ) )
	{
		pWZCCfgList->Config[0] = p->WZCConfig;

		pWZCCfgList->NumberOfItems = 1;

		while( p->pNext )
		{
			pWZCCfgList->Config[pWZCCfgList->NumberOfItems] = p->pNext->WZCConfig;

			pWZCCfgList->NumberOfItems++;

			p = p->pNext;
		}

		pWZCCfgList->Index = pWZCCfgList->NumberOfItems;

		printf( "pWZCCfgList->Index: %ld", pWZCCfgList->Index );
		printf( "pWZCCfgList->NumberOfItems: %ld", pWZCCfgList->NumberOfItems );

		if( ( Intf.rdBSSIDList.pData = ( PBYTE ) malloc( Intf.rdBSSIDList.dwDataLen ) ) )
		{
			memcpy( Intf.rdBSSIDList.pData, pWZCCfgList, Intf.rdBSSIDList.dwDataLen );

			dwRet = pWZCContext->pfnWZCSetInterface_1181( NULL,
														INTF_BSSIDLIST,
														&Intf,
														&dwOIDFlags );

			free( Intf.rdBSSIDList.pData );
		}

		free( pWZCCfgList );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}
#endif // AA_WZC_LIB_XP_SP1

DWORD
WZCSetBSSIDList( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN PAA_WZC_CONFIG_LIST_ITEM pWZCConfigListItem )
{
	DWORD	dwRet = NO_ERROR;

#ifdef AA_WZC_LIB_XP_SP2
	INTF_ENTRY					Intf;
	PAA_WZC_CONFIG_LIST_ITEM	p;
	DWORD						dwOIDFlags;
	PWZC_802_11_CONFIG_LIST		pWZCCfgList;

	dwRet = NO_ERROR;

	if( !pWZCConfigListItem  )
		return ERROR_NO_DATA;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	p = pWZCConfigListItem;

	Intf.rdBSSIDList.dwDataLen = sizeof( WZC_802_11_CONFIG_LIST );

	while( p->pNext )
	{
		Intf.rdBSSIDList.dwDataLen = Intf.rdBSSIDList.dwDataLen + sizeof( WZC_WLAN_CONFIG );

		p = p->pNext;
	}

	p = pWZCConfigListItem;

	if( ( pWZCCfgList = ( WZC_802_11_CONFIG_LIST * ) malloc( Intf.rdBSSIDList.dwDataLen ) ) )
	{
		pWZCCfgList->Config[0] = p->WZCConfig;

		pWZCCfgList->NumberOfItems = 1;

		while( p->pNext )
		{
			pWZCCfgList->Config[pWZCCfgList->NumberOfItems] = p->pNext->WZCConfig;

			pWZCCfgList->NumberOfItems++;

			p = p->pNext;
		}

		pWZCCfgList->Index = pWZCCfgList->NumberOfItems;

		printf( "pWZCCfgList->Index: %ld", pWZCCfgList->Index );
		printf( "pWZCCfgList->NumberOfItems: %ld", pWZCCfgList->NumberOfItems );

		if( ( Intf.rdBSSIDList.pData = ( PBYTE ) malloc( Intf.rdBSSIDList.dwDataLen ) ) )
		{
			memcpy( Intf.rdBSSIDList.pData, pWZCCfgList, Intf.rdBSSIDList.dwDataLen );

			dwRet = pWZCContext->pfnWZCSetInterface( NULL,
													INTF_BSSIDLIST,
													&Intf,
													&dwOIDFlags );

			free( Intf.rdBSSIDList.pData );
		}

		free( pWZCCfgList );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}
#endif

#ifdef AA_WZC_LIB_XP_SP1

	if( pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCSetBSSIDList_1106( pWZCContext, pwcGUID, pWZCConfigListItem );
	}
	else
	{
		dwRet = WZCSetBSSIDList_1181( pWZCContext, pwcGUID, pWZCConfigListItem );
	}
#endif // AA_WZC_LIB_XP_SP1

	return dwRet;
}

DWORD
WZCGetCompleteSSIDList( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, PAA_WZC_CONFIG_LIST_ITEM	*ppWZCConfigListItem )
{
	PAA_WZC_CONFIG_LIST_ITEM	pWZCPrefConfigListItem;
	PAA_WZC_CONFIG_LIST_ITEM	pWZCBConfigListItem;
	PAA_WZC_CONFIG_LIST_ITEM	p1, p2, p3;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList" ) ) );

	//
	// First retrieve BSSID List
	//
	if( ( dwRet = WZCGetBSSIDList( pWZCContext, pwcGUID, &pWZCBConfigListItem ) ) == NO_ERROR )
	{
		AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::WZCGetBSSIDList" ) ) );

		p1 = pWZCBConfigListItem;

		if( ( *ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, p1->WZCConfig, p1->dwFlags ) ) )
		{
			AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::BSSID:WZCConfigItemCreate" ) ) );

			p2 = *ppWZCConfigListItem;

			while( p1->pNext )
			{
				if( ( dwRet = WZCConfigItemAppend( p2, WZCConfigItemCreate( pWZCContext, p1->pNext->WZCConfig, p1->pNext->dwFlags ) ) ) != NO_ERROR )
				{
					AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::BSSID:appendWZCConfigItemCreate: failed: %ld" ), dwRet ) );

					break;
				}

				p2 = p2->pNext;
				p1 = p1->pNext;
			}
		}
		else
		{
			AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::BSSID:WZCConfigItemCreate failed" ) ) );

			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		if( dwRet != NO_ERROR )
		{
			while( pWZCBConfigListItem->pNext )
				WZCConfigItemDelete( &pWZCBConfigListItem->pNext );

			WZCConfigItemDelete( &pWZCBConfigListItem );
		}
	}

	if( dwRet == NO_ERROR )
	{
		//
		// Reset list back to last item
		//
		p2 = *ppWZCConfigListItem;

		while( p2->pNext )
			p2 = p2->pNext;

		//
		// Retrieve Preferred SSID List
		//
		if( ( dwRet = WZCGetPrefSSIDList( pWZCContext, pwcGUID, &pWZCPrefConfigListItem ) ) == NO_ERROR )
		{
			AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::BSSID:WZCGetPrefSSIDList" ) ) );

			p1 = pWZCPrefConfigListItem;

			while( p1 )
			{
				AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::BSSID:PREF:checking list for item(%ld): %s" ), p1->WZCConfig.Ssid.SsidLength, p1->WZCConfig.Ssid.Ssid ) );

				//
				// Check if we have already found this SSID in the list
				//
				if( ( dwRet = WZCConfigItemGet( *ppWZCConfigListItem, p1->WZCConfig.Ssid.Ssid, &p3 ) ) == NO_ERROR )
				{
					AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::BSSID:PREF:found item in list" ) ) );

					//
					// Found item in the list so just OR the flags
					//
					p3->dwFlags |= p1->dwFlags;
				}
				else
				{
					AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::BSSID:PREF:going to append" ) ) );

					if( ( dwRet = WZCConfigItemAppend( p2, WZCConfigItemCreate( pWZCContext, p1->WZCConfig, p1->dwFlags ) ) ) != NO_ERROR )
					{
						AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::BSSID:PREF:WZCConfigItemAppend failed: %ld" ), dwRet ) );

						break;
					}

					//
					// Added an item so reset the list to the last item
					//
					p2 = p2->pNext;
				}

				p1 = p1->pNext;
			}

			AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::BSSID:PREF:deleting PREF" ) ) );

			while( pWZCPrefConfigListItem->pNext )
				WZCConfigItemDelete( &pWZCPrefConfigListItem->pNext );

			WZCConfigItemDelete( &pWZCPrefConfigListItem );
		}
		else
		{
			//
			// Did not retrieve pref SSID list, but did succeed in getting a BSSID list
			// so set dwRet to NO_ERROR to continue with just a BSSID
			//
			AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::BSSID:PREF:WZCGetPrefSSIDList failed: %ld" ), dwRet ) );

			dwRet = NO_ERROR;
		}

		AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::BSSID:deleting BSSID" ) ) );

		while( pWZCBConfigListItem->pNext )
			WZCConfigItemDelete( &pWZCBConfigListItem->pNext );

		WZCConfigItemDelete( &pWZCBConfigListItem );
	}
	else
	{
		AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::WZCGetBSSIDList failed: %ld" ), dwRet ) );

		//
		// Could not find a BSSID list, so just add PREF (If Any)
		//
		if( ( dwRet = WZCGetPrefSSIDList( pWZCContext, pwcGUID, &pWZCPrefConfigListItem ) ) == NO_ERROR )
		{
			AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::WZCGetPrefSSIDList" ) ) );

			p1 = pWZCPrefConfigListItem;

			if( ( *ppWZCConfigListItem = WZCConfigItemCreate( pWZCContext, p1->WZCConfig, p1->dwFlags ) ) )
			{
				AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::PREF:WZCConfigItemCreate" ) ) );

				p2 = *ppWZCConfigListItem;

				while( p1->pNext )
				{
					if( ( dwRet = WZCConfigItemAppend( p2, WZCConfigItemCreate( pWZCContext, p1->pNext->WZCConfig, p1->pNext->dwFlags ) ) ) != NO_ERROR )
					{
						AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::PREF:WZCConfigItemAppend failed: %ld" ), dwRet ) );

						break;
					}

					p2 = p2->pNext;
					p1 = p1->pNext;
				}
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}

			AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::PREF:deleting PREF" ) ) );
		
			while( pWZCPrefConfigListItem->pNext )
				WZCConfigItemDelete( &pWZCPrefConfigListItem->pNext );

			WZCConfigItemDelete( &pWZCPrefConfigListItem );
		}
	}

	AA_TRACE( ( TEXT( "WZCGetCompleteSSIDList::returning" ) ) );

	return dwRet;
}

DWORD
WZCGetEapUserData( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN DWORD dwEapTypeId, IN OUT PBYTE pbUserInfo, IN OUT DWORD cbUserInfo )
{
	WCHAR	*pwcSSID;
	PCHAR	pcSSID;
	DWORD	ccSSID;
	DWORD	dwRet;

	dwRet = NO_ERROR;

	if( ( dwRet = WZCGetCurrentSSID( pWZCContext, pwcGUID, &pwcSSID ) ) == NO_ERROR )
	{
		ccSSID = ( DWORD ) wcslen( pwcSSID );

		if( ( pcSSID = ( PCHAR ) malloc( ccSSID + 1 ) ) )
		{
			if( WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
			{
				dwRet = pWZCContext->pfnWZCGetEapUserInfo( pwcGUID,
															dwEapTypeId,
															ccSSID,
															pcSSID,
															pbUserInfo,
															&cbUserInfo );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}

			free( pcSSID );
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pwcSSID );
	}	
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

#ifdef AA_WZC_LIB_XP_SP1
DWORD
WZCGetCurrentSSID_1106( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT WCHAR ** ppwcSSID )
{
	INTF_ENTRY_1106			Intf;
	DWORD					dwOIDFlags;
	PCHAR					pcSSID;
	DWORD					ccSSID;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	//
	// Refresh INTF_SSID
	//
	if( ( dwRet = pWZCContext->pfnWZCRefreshInterface_1106( NULL,
															INTF_SSID | INTF_WEPSTATUS,
															&Intf,
															&dwOIDFlags ) ) == NO_ERROR )
	{
		if( ( dwRet = pWZCContext->pfnWZCQueryInterface_1106( NULL,
															INTF_SSID,
															&Intf,
															&dwOIDFlags ) ) == NO_ERROR )
		{
			//
			// Connected to SSID?
			//
			if( Intf.rdSSID.dwDataLen > 0 )
			{
				if( ( pcSSID = ( PCHAR ) malloc( Intf.rdSSID.dwDataLen + 1 ) ) )
				{
					memset( pcSSID, 0, Intf.rdSSID.dwDataLen + 1 );

					memcpy( pcSSID, Intf.rdSSID.pData, Intf.rdSSID.dwDataLen );

					ccSSID = ( DWORD ) strlen( pcSSID ) + 1;

					if( ( *ppwcSSID = ( WCHAR* ) malloc( ccSSID * sizeof( WCHAR ) ) ) )
					{
						memset( *ppwcSSID, 0, ccSSID );

						if( MultiByteToWideChar( CP_ACP, 0, pcSSID, -1, *ppwcSSID, ccSSID ) == 0 )
							dwRet = ERROR_NOT_ENOUGH_MEMORY;

						if( dwRet != NO_ERROR )
							free( *ppwcSSID );
					}

					free( pcSSID );
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
			else
			{
				dwRet = ERROR_NO_DATA;
			}
		}
	}

	return dwRet;
}

DWORD
WZCGetCurrentSSID_1181( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT WCHAR ** ppwcSSID )
{
	INTF_ENTRY_1181			Intf;
	DWORD					dwOIDFlags;
	PCHAR					pcSSID;
	DWORD					ccSSID;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	//
	// Refresh INTF_SSID
	//
	if( ( dwRet = pWZCContext->pfnWZCRefreshInterface_1181( NULL,
															INTF_SSID | INTF_WEPSTATUS,
															&Intf,
															&dwOIDFlags ) ) == NO_ERROR )
	{
		if( ( dwRet = pWZCContext->pfnWZCQueryInterface_1181( NULL,
																INTF_SSID,
																&Intf,
																&dwOIDFlags ) ) == NO_ERROR )
		{
			//
			// Connected to SSID?
			//
			if( Intf.rdSSID.dwDataLen > 0 )
			{
				if( ( pcSSID = ( PCHAR ) malloc( Intf.rdSSID.dwDataLen + 1 ) ) )
				{
					memset( pcSSID, 0, Intf.rdSSID.dwDataLen + 1 );

					memcpy( pcSSID, Intf.rdSSID.pData, Intf.rdSSID.dwDataLen );

					ccSSID = ( DWORD ) strlen( pcSSID ) + 1;

					if( ( *ppwcSSID = ( WCHAR* ) malloc( ccSSID * sizeof( WCHAR ) ) ) )
					{
						memset( *ppwcSSID, 0, ccSSID );

						if( MultiByteToWideChar( CP_ACP, 0, pcSSID, -1, *ppwcSSID, ccSSID ) == 0 )
							dwRet = ERROR_NOT_ENOUGH_MEMORY;

						if( dwRet != NO_ERROR )
							free( *ppwcSSID );
					}

					free( pcSSID );
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
		}
	}

	return dwRet;
}
#endif // AA_WZC_LIB_XP_SP1

//
// Searches for the INTF_ENTRY beloning to the GUID and retrieves the current SSID
// The calling function is responsible for freeing ppwcSSID using free();
//
DWORD
WZCGetCurrentSSID( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT WCHAR ** ppwcSSID )
{
	DWORD	dwRet = NO_ERROR;

#ifdef AA_WZC_LIB_XP_SP1
	if( pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCGetCurrentSSID_1106( pWZCContext, pwcGUID, ppwcSSID );
	}
	else
	{
		dwRet = WZCGetCurrentSSID_1181( pWZCContext, pwcGUID, ppwcSSID );
	}
#else

	INTF_ENTRY			Intf;
	DWORD				dwOIDFlags;
	PCHAR				pcSSID;
	DWORD				ccSSID;

	AA_TRACE( ( TEXT( "WZCGetCurrentSSID" ) ) );

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	AA_TRACE( ( TEXT( "WZCGetCurrentSSID::refreshing interface" ) ) );

	//
	// Refresh INTF_SSID
	//
	if( ( dwRet = pWZCContext->pfnWZCRefreshInterface( NULL,
														INTF_SSID | INTF_WEPSTATUS,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		AA_TRACE( ( TEXT( "pfnWZCRefreshInterface:successfull" ) ) );

		if( ( dwRet = pWZCContext->pfnWZCQueryInterface( NULL,
														INTF_SSID,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
		{
			AA_TRACE( ( TEXT( "pfnWZCQueryInterface:successfull" ) ) );

			//
			// Connected to SSID?
			//
			if( Intf.rdSSID.dwDataLen > 0 )
			{
				AA_TRACE( ( TEXT( "Intf.rdSSID.dwDataLen: %ld" ), Intf.rdSSID.dwDataLen ) );

				if( ( pcSSID = ( PCHAR ) malloc( Intf.rdSSID.dwDataLen + 1 ) ) )
				{
					memset( pcSSID, 0, Intf.rdSSID.dwDataLen + 1 );

					memcpy( pcSSID, Intf.rdSSID.pData, Intf.rdSSID.dwDataLen );

					ccSSID = ( DWORD ) strlen( pcSSID ) + 1;

					AA_TRACE( ( TEXT( "pcSSID(%ld): %s" ), ccSSID, pcSSID ) );

					if( ( *ppwcSSID = ( WCHAR* ) malloc( ccSSID * sizeof( WCHAR ) ) ) )
					{
						memset( *ppwcSSID, 0, ccSSID );

						if( MultiByteToWideChar( CP_ACP, 0, pcSSID, -1, *ppwcSSID, ccSSID ) == 0 )
							dwRet = ERROR_NOT_ENOUGH_MEMORY;

						if( dwRet != NO_ERROR )
							free( *ppwcSSID );
					}

					free( pcSSID );
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
			else
			{
				dwRet = ERROR_NO_DATA;
			}
		}
	}
#endif //  AA_WZC_LIB_2K_XP_SP0

	return dwRet;
}

#ifdef AA_WZC_LIB_XP_SP1
DWORD
WZCSetCurrentSSID_1106( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WCHAR * pwcSSID )
{
	INTF_ENTRY_1106			Intf;
	DWORD					dwOIDFlags;
	PCHAR					pcSSID;
	DWORD					ccSSID;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	ccSSID = ( DWORD ) wcslen( pwcSSID );

	if( ( pcSSID = ( PCHAR ) malloc( ccSSID + 1 ) ) )
	{
		if( WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
		{
			if( ( Intf.rdSSID.pData = ( PBYTE ) malloc( ccSSID + 1 ) ) )
			{
				printf( "SSID: %s", pcSSID );

				memset( Intf.rdSSID.pData, 0, ccSSID + 1 );

				memcpy( Intf.rdSSID.pData, pcSSID, ccSSID );
				Intf.rdSSID.dwDataLen = ccSSID;

				dwRet = pWZCContext->pfnWZCSetInterface_1106( NULL,
															INTF_SSID,
															&Intf,
															&dwOIDFlags );

				free( Intf.rdSSID.pData );
			}
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcSSID );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

DWORD
WZCSetCurrentSSID_1181( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WCHAR * pwcSSID )
{
	INTF_ENTRY_1181			Intf;
	DWORD					dwOIDFlags;
	PCHAR					pcSSID;
	DWORD					ccSSID;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	ccSSID = ( DWORD ) wcslen( pwcSSID );

	if( ( pcSSID = ( PCHAR ) malloc( ccSSID + 1 ) ) )
	{
		if( WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
		{
			if( ( Intf.rdSSID.pData = ( PBYTE ) malloc( ccSSID + 1 ) ) )
			{
				memset( Intf.rdSSID.pData, 0, ccSSID + 1 );

				memcpy( Intf.rdSSID.pData, pcSSID, ccSSID );
				Intf.rdSSID.dwDataLen = ccSSID;

				dwRet = pWZCContext->pfnWZCSetInterface_1181( NULL,
															INTF_SSID,
															&Intf,
															&dwOIDFlags );

				free( Intf.rdSSID.pData );
			}
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcSSID );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}
#endif // AA_WZC_LIB_XP_SP1

//
// Searches for the INTF_ENTRY beloning to the GUID and sets the current SSID
// The calling function is responsible for freeing ppwcSSID using free();
//
DWORD
WZCSetCurrentSSID( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WCHAR * pwcSSID )
{
	DWORD	dwRet;

#ifdef AA_WZC_LIB_XP_SP1
	dwRet = NO_ERROR;

	if( pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCSetCurrentSSID_1106( pWZCContext, pwcGUID, pwcSSID );
	}
	else
	{
		dwRet = WZCSetCurrentSSID_1181( pWZCContext, pwcGUID, pwcSSID );
	}
#else
	INTF_ENTRY				Intf;
	DWORD					dwOIDFlags;
	PCHAR					pcSSID;
	DWORD					ccSSID;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	ccSSID = ( DWORD ) wcslen( pwcSSID );

	if( ( pcSSID = ( PCHAR ) malloc( ccSSID + 1 ) ) )
	{
		if( WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
		{
			if( ( Intf.rdSSID.pData = ( PBYTE ) malloc( ccSSID + 1 ) ) )
			{
				printf( "SSID: %s", pcSSID );

				memset( Intf.rdSSID.pData, 0, ccSSID + 1 );

				memcpy( Intf.rdSSID.pData, pcSSID, ccSSID );
				Intf.rdSSID.dwDataLen = ccSSID;

				Intf.nInfraMode = Ndis802_11Infrastructure;

				dwRet = pWZCContext->pfnWZCSetInterface( NULL,
														INTF_SSID | INTF_INFRAMODE,
														&Intf,
														&dwOIDFlags );

				free( Intf.rdSSID.pData );
			}
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcSSID );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

#endif // AA_WZC_LIB_XP_SP1

	return dwRet;
}

#ifdef AA_WZC_LIB_XP_SP1
DWORD
WZCRefreshList_1106( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID )
{
	INTF_ENTRY_1106			Intf;
	DWORD					dwOIDFlags;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	//
	// Refresh INTF_SSID
	//
	dwRet = pWZCContext->pfnWZCRefreshInterface_1106( NULL,
													INTF_LIST_SCAN,
													&Intf,
													&dwOIDFlags );

	return dwRet;
}

DWORD
WZCRefreshList_1181( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID )
{
	INTF_ENTRY_1181			Intf;
	DWORD					dwOIDFlags;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid = pwcGUID;

	dwOIDFlags = 0;

	//
	// Refresh INTF_SSID
	//
	dwRet = pWZCContext->pfnWZCRefreshInterface_1181( NULL,
													INTF_LIST_SCAN,
													&Intf,
													&dwOIDFlags );

	return dwRet;
}
#endif // AA_WZC_LIB_XP_SP1

DWORD
WZCRefreshList( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID )
{
	DWORD	dwRet;

	dwRet = NO_ERROR;

#ifdef AA_WZC_LIB_XP_SP1

	if( pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCRefreshList_1106( pWZCContext, pwcGUID );
	}
	else
	{
		dwRet = WZCRefreshList_1181( pWZCContext, pwcGUID );
	}
#endif // AA_WZC_LIB_XP_SP1

	return dwRet;
}

DWORD
WZCGetConfigEapData(	IN PAA_WZC_LIB_CONTEXT pWZCContext,
						IN WCHAR *pwcGUID, 
						IN WCHAR *pwcSSID, 
						IN DWORD dwEapType, 
						OUT PBYTE *ppbConfigData, 
						OUT DWORD *pcbConfigData )
{
//	EAPOL_INTF_PARAMS		IntfParams;
	PCHAR					pcSSID;
	DWORD					ccSSID;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	ccSSID = ( DWORD ) wcslen( pwcSSID );

	if( ( pcSSID = ( PCHAR ) malloc( ccSSID + 1 ) ) )
	{
		memset( pcSSID, 0, ccSSID );

		if( WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
		{
			*pcbConfigData = 0;

			dwRet = pWZCContext->pfnWZCEapolGetCustomAuthData ( NULL,
																pwcGUID,
																dwEapType,															
																( DWORD ) ccSSID,
																( PBYTE ) pcSSID,
																( PBYTE ) NULL,
																pcbConfigData );

			if( dwRet == ERROR_BUFFER_TOO_SMALL )
			{
				if( *pcbConfigData == 0 )
				{
					//
					// no eap data available
					//
					*ppbConfigData = NULL;
				}
				else
				{
					if( ( *ppbConfigData = ( PBYTE ) malloc( *pcbConfigData ) ) )
					{
						if( dwRet = pWZCContext->pfnWZCEapolGetCustomAuthData ( NULL,
																			pwcGUID,
																			dwEapType,															
																			( DWORD ) ccSSID,
																			( PBYTE ) pcSSID,
																			( PBYTE ) *ppbConfigData,
																			pcbConfigData ) != NO_ERROR )
						{
							free( *ppbConfigData );
							*ppbConfigData = NULL;
							*pcbConfigData = 0;
						}
					}
					else
					{
						*pcbConfigData = 0;

						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
				}
			}
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcSSID );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

//
// This function will enable 802.1X, set the EAP Type and the EAP Data for the pwcGUID
//
DWORD
WZCSetConfigEapData(	IN PAA_WZC_LIB_CONTEXT pWZCContext,
						IN WCHAR *pwcGUID, 
						IN WCHAR *pwcSSID, 
						IN DWORD dwEapType, 
						IN PBYTE pbConfigData, 
						IN DWORD cbConfigData )
{
	EAPOL_INTF_PARAMS		IntfParams;
	PCHAR					pcSSID;
	DWORD					ccSSID;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	ccSSID = ( DWORD ) wcslen( pwcSSID );

	AA_TRACE( ( TEXT( "WZCSetConfigEapData" ) ) );

	if( ( pcSSID = ( PCHAR ) malloc( ccSSID + 1 ) ) )
	{
		memset( pcSSID, 0, ccSSID );

		if( WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
		{
			AA_TRACE( ( TEXT( "WZCSetConfigEapData::pwcSSID: %s" ), pwcSSID ) );

			memset( &IntfParams, 0, sizeof( EAPOL_INTF_PARAMS ) );

			memcpy( &IntfParams.bSSID, pcSSID, ccSSID );
			IntfParams.dwSizeOfSSID = ccSSID;

			AA_TRACE( ( TEXT( "WZCSetConfigEapData:: calling pfnWZCEapolGetInterfaceParams" ) ) );

			if( ( dwRet = pWZCContext->pfnWZCEapolGetInterfaceParams( NULL,
																	pwcGUID,
																	&IntfParams ) ) == NO_ERROR )
			{
				AA_TRACE( ( TEXT( "IntfParams.dwEapFlags: %lx" ), IntfParams.dwEapFlags ) );
				AA_TRACE( ( TEXT( "IntfParams.dwEapType: %ld" ), IntfParams.dwEapType ) );
				AA_TRACE( ( TEXT( "IntfParams.dwSizeOfSSID: %ld" ), IntfParams.dwSizeOfSSID ) );
				AA_TRACE( ( TEXT( "IntfParams.dwReserved2: %ld" ), IntfParams.dwReserved2 ) );
				AA_TRACE( ( TEXT( "IntfParams.dwVersion: %ld" ), IntfParams.dwVersion ) );

				//
				// Setup 802.1X
				//
				IntfParams.dwEapFlags = EAPOL_ENABLED | EAPOL_MACHINE_AUTH_ENABLED;
				IntfParams.dwEapType = dwEapType;
				IntfParams.dwReserved2 = 0;

				if( ( dwRet = pWZCContext->pfnWZCEapolSetInterfaceParams( NULL,
																		pwcGUID,
																		&IntfParams ) ) == NO_ERROR )
				{
					AA_TRACE( ( TEXT( "pfnWZCEapolSetInterfaceParams successfull" ) ) );

					//
					// Setup the EAP Data
					//
					dwRet = pWZCContext->pfnWZCEapolSetCustomAuthData ( NULL,
																		pwcGUID,
																		dwEapType,															
																		( DWORD ) ccSSID,
																		( PBYTE ) pcSSID,
																		( PBYTE ) pbConfigData,
																		cbConfigData );

					AA_TRACE( ( TEXT( "pfnWZCEapolSetCustomAuthData returned %ld" ), dwRet ) );
				}
			}
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcSSID );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

DWORD
WZCIsEapType( IN PAA_WZC_LIB_CONTEXT pWZCContext,
				IN WCHAR *pwcGUID, 
				IN WCHAR *pwcSSID, 
				IN DWORD dwEapType, 
				IN PBYTE pbConfigData, 
				IN DWORD cbConfigData )
{
	EAPOL_INTF_PARAMS		IntfParams;
	PCHAR					pcSSID;
	DWORD					ccSSID;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	ccSSID = ( DWORD ) wcslen( pwcSSID );

	if( ( pcSSID = ( PCHAR ) malloc( ccSSID + 1 ) ) )
	{
		memset( pcSSID, 0, ccSSID );

		if( WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
		{
			memset( &IntfParams, 0, sizeof( EAPOL_INTF_PARAMS ) );

			memcpy( &IntfParams.bSSID, pcSSID, ccSSID );
			IntfParams.dwSizeOfSSID = ccSSID;

			if( ( dwRet = pWZCContext->pfnWZCEapolGetInterfaceParams( NULL,
																	pwcGUID,
																	&IntfParams ) ) == NO_ERROR )
			{
/*
				printf( "IntfParams.dwEapFlags: %lx", IntfParams.dwEapFlags );
				printf( "IntfParams.dwEapType: %ld", IntfParams.dwEapType );
				printf( "IntfParams.dwSizeOfSSID: %ld", IntfParams.dwSizeOfSSID );
				printf( "IntfParams.dwReserved2: %ld", IntfParams.dwReserved2 );
				printf( "IntfParams.dwVersion: %ld", IntfParams.dwVersion );
*/
				//
				// Setup 802.1X
				//
				IntfParams.dwEapFlags = EAPOL_ENABLED | EAPOL_MACHINE_AUTH_ENABLED;
				IntfParams.dwEapType = dwEapType;
				IntfParams.dwReserved2 = 0;

				if( ( dwRet = pWZCContext->pfnWZCEapolSetInterfaceParams( NULL,
																		pwcGUID,
																		&IntfParams ) ) == NO_ERROR )
				{
					//
					// Setup the EAP Data
					//
					dwRet = pWZCContext->pfnWZCEapolSetCustomAuthData ( NULL,
																		pwcGUID,
																		dwEapType,															
																		( DWORD ) ccSSID,
																		( PBYTE ) pcSSID,
																		( PBYTE ) pbConfigData,
																		cbConfigData );
				}
			}
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcSSID );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

#ifdef AA_WZC_LIB_XP_SP1
DWORD
WZCGetSignalStrength_1106( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT LONG *plSignalStrength )
{
	INTF_ENTRY_1106			Intf;
	DWORD					dwOIDFlags;
	WZC_WLAN_CONFIG			WZCCfg;
	int						i;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid =  pwcGUID;

	dwOIDFlags = 0;

	//
	// Refresh INTF_LIST_SCAN
	//
	if( ( dwRet = pWZCContext->pfnWZCRefreshInterface_1106( NULL,
															INTF_LIST_SCAN | INTF_WEPSTATUS,
															&Intf,
															&dwOIDFlags ) ) == NO_ERROR )
	{
		for( i=0; i < 10; i++ )
		{	
			dwRet = WZCGetCurrentConfig( pWZCContext, pwcGUID, &WZCCfg );
		
			if( dwRet == ERROR_NO_DATA )
				Sleep( 1000 );
			else
				break;
		}

		if( i == 10 )
		{
			dwRet = ERROR_NO_DATA;
		}
		else if( dwRet == NO_ERROR )
		{
			*plSignalStrength = WZCCfg.Rssi;
		}
	}

	return dwRet;
}

DWORD
WZCGetSignalStrength_1181( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT LONG *plSignalStrength )
{
	INTF_ENTRY_1181			Intf;
	DWORD					dwOIDFlags;
	WZC_WLAN_CONFIG			WZCCfg;
	int						i;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid =  pwcGUID;

	dwOIDFlags = 0;

	//
	// Refresh INTF_LIST_SCAN
	//
	if( ( dwRet = pWZCContext->pfnWZCRefreshInterface_1181( NULL,
															INTF_LIST_SCAN | INTF_WEPSTATUS,
															&Intf,
															&dwOIDFlags ) ) == NO_ERROR )
	{
		for( i=0; i < 10; i++ )
		{	
			dwRet = WZCGetCurrentConfig( pWZCContext, pwcGUID, &WZCCfg );
		
			if( dwRet == ERROR_NO_DATA )
				Sleep( 1000 );
			else
				break;
		}

		if( i == 10 )
		{
			dwRet = ERROR_NO_DATA;
		}
		else if( dwRet == NO_ERROR )
		{
			*plSignalStrength = WZCCfg.Rssi;
		}
	}

	return dwRet;
}
#endif // AA_WZC_LIB_XP_SP1

//
// Will return Received signal strength (Rssi) in Dbm
// Refreshes interface belonging to pwcGUID
// Waits till BSSIDLIST is back up, retrieves the current SSID WLAN_CONFIG 
// and returns the Rssi of that Config
//
DWORD
WZCGetSignalStrength( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, OUT LONG *plSignalStrength )
{
	DWORD					dwRet = NO_ERROR;

#ifdef AA_WZC_LIB_XP_SP2
	INTF_ENTRY				Intf;
	DWORD					dwOIDFlags;
	WZC_WLAN_CONFIG			WZCCfg;
	int						i;

	memset( &Intf, 0, sizeof( Intf ) );

	Intf.wszGuid =  pwcGUID;

	dwOIDFlags = 0;

	//
	// Refresh INTF_LIST_SCAN
	//
	if( ( dwRet = pWZCContext->pfnWZCRefreshInterface( NULL,
														INTF_LIST_SCAN | INTF_WEPSTATUS,
														&Intf,
														&dwOIDFlags ) ) == NO_ERROR )
	{
		for( i=0; i < 10; i++ )
		{	
			dwRet = WZCGetCurrentConfig( pWZCContext, pwcGUID, &WZCCfg );
		
			if( dwRet == ERROR_NO_DATA )
				Sleep( 1000 );
			else
				break;
		}

		if( i == 10 )
		{
			dwRet = ERROR_NO_DATA;
		}
		else if( dwRet == NO_ERROR )
		{
			*plSignalStrength = WZCCfg.Rssi;
		}
	}
#endif

#ifdef AA_WZC_LIB_XP_SP1

	if( pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600_1106 )
	{
		dwRet = WZCGetSignalStrength_1106( pWZCContext, pwcGUID, plSignalStrength );
	}
	else
	{
		dwRet = WZCGetSignalStrength_1181( pWZCContext, pwcGUID, plSignalStrength );
	}
#endif // AA_WZC_LIB_XP_SP1

	return dwRet;
}

DWORD
WZCAddPreferedConfig( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WZC_WLAN_CONFIG WZCCfgNew, IN DWORD dwFlags, IN BOOL bOverWrite, IN BOOL bFirst )
{
	PAA_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	PAA_WZC_CONFIG_LIST_ITEM	p;
	WZC_WLAN_CONFIG				WZCCfg;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "WZCAddPreferedConfig" ) ) );

	dwRet = WZCGetPrefSSIDList( pWZCContext, pwcGUID, &pWZCConfigListItem );

	if( dwRet == ERROR_NO_DATA )
	{
		//
		// List is empty, create one
		//
		dwRet = NO_ERROR;

		if( !( pWZCConfigListItem = WZCConfigItemCreate( pWZCContext, WZCCfgNew, AA_WZC_LIB_CONFIG_PREF ) ) )
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
		else
		{
			dwRet = WZCSetPrefSSIDList( pWZCContext, pwcGUID, pWZCConfigListItem );
	
			while( pWZCConfigListItem->pNext )
				WZCConfigItemDelete( &( pWZCConfigListItem->pNext ) );

			WZCConfigItemDelete( &pWZCConfigListItem );	
		}
	}
	else
	{
		if( dwRet == NO_ERROR )
		{
			//
			// Found list
			//
			if( ( dwRet = WZCConfigItemGet( pWZCConfigListItem, WZCCfgNew.Ssid.Ssid, &p ) ) == NO_ERROR )
			{
				AA_TRACE( ( TEXT( "WZCAddPreferedConfig::found in list" ) ) );

				//
				// Config already in list
				//
				if( bOverWrite && bFirst )
				{
					AA_TRACE( ( TEXT( "WZCAddPreferedConfig::overwriting and setting to first" ) ) );

					//
					// Overwrite it and set it to first item in list
					//
					memcpy( &WZCCfg, &WZCCfgNew, sizeof( WZC_WLAN_CONFIG ) );

					if( ( dwRet = WZCConfigItemPrePend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, WZCCfg, dwFlags ) ) ) == NO_ERROR )
					{
						pWZCConfigListItem = pWZCConfigListItem->pPrev;

						WZCConfigItemDelete( &p );
					}
				}
				else if( bFirst )
				{
					AA_TRACE( ( TEXT( "WZCAddPreferedConfig::setting to first" ) ) );

					//
					// Don't overwrite but set to first in list
					//
					if( ( dwRet = WZCConfigItemPrePend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, p->WZCConfig, p->dwFlags ) ) ) == NO_ERROR )
					{
						pWZCConfigListItem = pWZCConfigListItem->pPrev;

						WZCConfigItemDelete( &p );
					}
				}
				else if( bOverWrite )
				{
					AA_TRACE( ( TEXT( "WZCAddPreferedConfig::overwriting" ) ) );

					//
					// Just overwrite
					//
					memcpy( &p->WZCConfig, &WZCCfgNew, sizeof( WZC_WLAN_CONFIG ) );

					p->dwFlags = dwFlags;
				}
				else
					dwRet = ERROR_ALREADY_EXISTS;
			}
			else
			{
				AA_TRACE( ( TEXT( "WZCAddPreferedConfig::NOT found in list" ) ) );

				//
				// Not in list
				//
				if( bFirst )
				{
					AA_TRACE( ( TEXT( "WZCAddPreferedConfig::setting to first in list" ) ) );

					if( ( dwRet = WZCConfigItemPrePend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, WZCCfgNew, dwFlags ) ) ) == NO_ERROR )
					{
						pWZCConfigListItem = pWZCConfigListItem->pPrev;
					}
				}
				else
				{
					AA_TRACE( ( TEXT( "WZCAddPreferedConfig::inserting in to list" ) ) );

					if( ( dwRet = WZCConfigItemAppend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, WZCCfgNew, dwFlags ) ) ) == NO_ERROR )
					{
						AA_TRACE( ( TEXT( "WZCAddPreferedConfig::appended" ) ) );
					}
				}
			}

			if( pWZCConfigListItem )
			{
				AA_TRACE( ( TEXT( "WZCAddPreferedConfig::OK" ) ) );
			}

			dwRet = WZCSetPrefSSIDList( pWZCContext, pwcGUID, pWZCConfigListItem );

			AA_TRACE( ( TEXT( "WZCAddPreferedConfig::deleting list" ) ) );

			while( pWZCConfigListItem->pNext )
				WZCConfigItemDelete( &( pWZCConfigListItem->pNext ) );

			WZCConfigItemDelete( &pWZCConfigListItem );
		}
	}

	AA_TRACE( ( TEXT( "WZCAddPreferedConfig::returning: %ld" ), dwRet ) );

	return dwRet;
}

DWORD
WZCRemovePreferedConfig( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WZC_WLAN_CONFIG WZCCfgNew )
{
	PAA_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	PAA_WZC_CONFIG_LIST_ITEM	p;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "WZCRemovePreferedConfig" ) ) );

	if( ( dwRet = WZCGetPrefSSIDList( pWZCContext, pwcGUID, &pWZCConfigListItem ) ) == NO_ERROR )
	{
		AA_TRACE( ( TEXT( "WZCRemovePreferedConfig::got list" ) ) );

		if( ( dwRet = WZCConfigItemGet( pWZCConfigListItem, WZCCfgNew.Ssid.Ssid, &p ) ) == NO_ERROR )
		{
			AA_TRACE( ( TEXT( "WZCRemovePreferedConfig::found item" ) ) );

			if( p->pPrev )
			{
				AA_TRACE( ( TEXT( "WZCRemovePreferedConfig::not first in list so deleting" ) ) );

				WZCConfigItemDelete( &p );
			}
			else
			{
				//
				// item is at first of list so reset list after deleting
				//
				if( p->pNext )
				{
					AA_TRACE( ( TEXT( "WZCRemovePreferedConfig::not last in list" ) ) );

					pWZCConfigListItem = p->pNext;

					WZCConfigItemDelete( &p );
				}
				else
				{
					AA_TRACE( ( TEXT( "WZCRemovePreferedConfig::last in list" ) ) );

					WZCConfigItemDelete( &pWZCConfigListItem );
				}
			}

			dwRet = WZCSetPrefSSIDList( pWZCContext, pwcGUID, pWZCConfigListItem );
		}

		AA_TRACE( ( TEXT( "WZCRemovePreferedConfig::deleting" ) ) );

		if( pWZCConfigListItem )
		{
			while( pWZCConfigListItem->pNext )
				WZCConfigItemDelete( &( pWZCConfigListItem->pNext ) );

			WZCConfigItemDelete( &pWZCConfigListItem );
		}
	}	

	AA_TRACE( ( TEXT( "WZCRemovePreferedConfig::returning %ld" ), dwRet ) );

	return dwRet;
}

#ifdef AA_WZC_LIB_2K_XP_SP0
DWORD
WZCEnumAdapters_2K( IN PAA_WZC_LIB_CONTEXT pWZCContext, OUT PAA_WZC_LIB_ADAPTERS pAdapters )
{
	HANDLE					hFile;
	WCHAR					*pNdisuioDevice = L"\\\\.\\\\Ndisuio";
	DWORD					dwBytesReturned = 0;
	int						i = 0;
	CHAR					pcBuf[1024];
	PNDISUIO_QUERY_BINDING	pQueryBinding;
	DWORD					dwRet;

	dwRet = NO_ERROR;

	if( ( hFile = CreateFile( pNdisuioDevice,
								GENERIC_READ|GENERIC_WRITE,
								0,
								NULL,
								OPEN_EXISTING,
								FILE_ATTRIBUTE_NORMAL,
								(HANDLE) INVALID_HANDLE_VALUE ) ) )
	{
		AA_TRACE( ( TEXT( "CreateFile successfull" ) ) );

		//
		// Bind the file handle to the driver
		//

		if( DeviceIoControl(hFile,
							IOCTL_NDISUIO_BIND_WAIT,
							NULL,
							0,
							NULL,
							0,
							&dwBytesReturned,
							NULL ) )
		{
			AA_TRACE( ( TEXT( "IOCTL_NDISUIO_BIND_WAIT successfull" ) ) );

			dwBytesReturned = 0;

			//
			// Enumerate adapters
			//
			pQueryBinding = ( PNDISUIO_QUERY_BINDING ) pcBuf;

			for( i=0; i < AA_WZC_LIB_MAX_ADAPTER; i++ )
			{
				pQueryBinding->BindingIndex = i;

				if( DeviceIoControl( hFile,
									IOCTL_NDISUIO_QUERY_BINDING,
									pQueryBinding,
									sizeof( NDISUIO_QUERY_BINDING ),
									pcBuf,
									sizeof( pcBuf ),
									&dwBytesReturned,
									NULL ) )
				{
					AA_TRACE( ( TEXT( "IOCTL_NDISUIO_BIND_WAIT successfull" ) ) );

					AA_TRACE( ( TEXT( "pQueryBinding->BindingIndex: %ld" ), pQueryBinding->BindingIndex ) );
					AA_TRACE( ( TEXT( "pQueryBinding->DeviceNameLength: %ld" ), pQueryBinding->DeviceNameLength ) );
					AA_TRACE( ( TEXT( "pQueryBinding->DeviceDescrLength: %ld" ), pQueryBinding->DeviceDescrLength ) );
					AA_TRACE( ( TEXT( "pQueryBinding->DeviceNameOffset: %ld" ), pQueryBinding->DeviceNameOffset ) );
					AA_TRACE( ( TEXT( "pQueryBinding->DeviceDescrOffset: %ld" ), pQueryBinding->DeviceDescrOffset ) );

					memset( pAdapters->pwcGUID[i], 0, UNLEN );

					memcpy( pAdapters->pwcGUID[i], (PUCHAR) pQueryBinding+pQueryBinding->DeviceNameOffset + 16, pQueryBinding->DeviceNameLength - 16 );

					memset( pcBuf, 0, sizeof( pcBuf ) );
				}
				else
				{
					dwRet = GetLastError();

					if( dwRet == ERROR_NO_MORE_ITEMS )
					{
						dwRet = NO_ERROR;
					}

					break;
				}
			}

			AA_TRACE( ( TEXT( "quiting loop" ) ) );

			pAdapters->dwNumGUID = i;
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}
	else
	{
		dwRet = ERROR_NO_DATA;
	}

	return dwRet;
}

DWORD
WZCEnumAdapters_XP_SP0( IN PAA_WZC_LIB_CONTEXT pWZCContext, OUT PAA_WZC_LIB_ADAPTERS pAdapters )
{
	DWORD				dwRet;
	INTFS_KEY_TABLE		Intfs;
	DWORD				i;

	dwRet = NO_ERROR;

	memset( &Intfs, 0, sizeof( Intfs ) );

	if( ( dwRet = pWZCContext->pfnWZCEnumInterfaces( NULL,
													&Intfs ) ) == NO_ERROR )
	{
		if( Intfs.dwNumIntfs > 0 )
		{
			if( Intfs.dwNumIntfs > AA_WZC_LIB_MAX_ADAPTER )
				pAdapters->dwNumGUID = AA_WZC_LIB_MAX_ADAPTER;
			else
				pAdapters->dwNumGUID = Intfs.dwNumIntfs;

			for( i=0; i < pAdapters->dwNumGUID; i++ )
			{
				if( ( wcslen( Intfs.pIntfs->wszGuid ) + 1 ) <= UNLEN )
					wcscpy( pAdapters->pwcGUID[i], Intfs.pIntfs->wszGuid );

				Intfs.pIntfs->wszGuid++;
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}

	return dwRet;
}
#endif // AA_WZC_LIB_2K_XP_SP0

DWORD
WZCEnumAdapters( IN PAA_WZC_LIB_CONTEXT pWZCContext, OUT PAA_WZC_LIB_ADAPTERS pAdapters )
{
	DWORD				dwRet = NO_ERROR;

#ifdef AA_WZC_LIB_2K_XP_SP0

	dwRet = NO_ERROR;

	if( pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_0_6034 ||
		pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_0_6604 )
	{
		//
		// Windows 2K
		//
		dwRet = WZCEnumAdapters_2K( pWZCContext, pAdapters );
	}
	else if( pWZCContext->dwWZCSDllVersion == WZCS_DLL_VERSION_5_1_2600 )
	{
		dwRet = WZCEnumAdapters_XP_SP0( pWZCContext, pAdapters );
	}

#else
	INTFS_KEY_TABLE		Intfs;
	DWORD				i;

	memset( &Intfs, 0, sizeof( Intfs ) );

	AA_TRACE( ( TEXT( "WZCEnumAdapters" ) ) );

	if( ( dwRet = pWZCContext->pfnWZCEnumInterfaces( NULL,
													&Intfs ) ) == NO_ERROR )
	{
		AA_TRACE( ( TEXT( "WZCEnumAdapters::Intfs.dwNumIntfs: %ld" ), Intfs.dwNumIntfs ) );

		if( Intfs.dwNumIntfs > 0 )
		{
			if( Intfs.dwNumIntfs > AA_WZC_LIB_MAX_ADAPTER )
				pAdapters->dwNumGUID = AA_WZC_LIB_MAX_ADAPTER;
			else
				pAdapters->dwNumGUID = Intfs.dwNumIntfs;

			for( i=0; i < pAdapters->dwNumGUID; i++ )
			{
				if( ( wcslen( Intfs.pIntfs->wszGuid ) + 1 ) <= UNLEN )
					wcscpy( pAdapters->pwcGUID[i], Intfs.pIntfs->wszGuid );

				Intfs.pIntfs->wszGuid++;
			}
		}
		else
		{
			dwRet = ERROR_NO_DATA;
		}
	}

#endif

	return dwRet;
}

DWORD
WZCLogon( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WCHAR *pwcSSID )
{
	PAA_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;
	PAA_WZC_CONFIG_LIST_ITEM	p;
	WZC_WLAN_CONFIG				WZCCfg;
	EAPOL_INTF_PARAMS			IntfParams;
	PCHAR						pcSSID = NULL;
	DWORD						ccSSID;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	memset( &IntfParams, 0, sizeof( EAPOL_INTF_PARAMS ) );

	if( pwcSSID )
	{
		ccSSID = ( DWORD ) wcslen( pwcSSID );

		if( ( pcSSID = ( PCHAR ) malloc( ccSSID + 1 ) ) )
		{
			if( WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
			{
				memcpy( &IntfParams.bSSID, pcSSID, ccSSID );
				IntfParams.dwSizeOfSSID = ccSSID;
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}

			if( dwRet != NO_ERROR )
				free( pcSSID );
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
	}

	if( dwRet == NO_ERROR )
	{
		//
		// Set the top the SSID to the top of the list
		//
		if( ( dwRet = WZCGetPrefSSIDList( pWZCContext, pwcGUID, &pWZCConfigListItem ) ) == NO_ERROR )
		{
			if( ( dwRet = WZCConfigItemGet( pWZCConfigListItem, pcSSID, &p ) ) == NO_ERROR )
			{
				//
				// Found config in list
				//
				memcpy( &WZCCfg, &p->WZCConfig, sizeof( WZC_WLAN_CONFIG ) );

				if( ( dwRet = WZCConfigItemPrePend( pWZCConfigListItem, WZCConfigItemCreate( pWZCContext, WZCCfg, AA_WZC_LIB_CONFIG_PREF ) ) ) == NO_ERROR )
				{
					pWZCConfigListItem = pWZCConfigListItem->pPrev;

					WZCConfigItemDelete( &p );

					dwRet = WZCSetPrefSSIDList( pWZCContext, pwcGUID, pWZCConfigListItem );
				}
			}

			//
			// Cleanup
			//

			while( pWZCConfigListItem->pNext )
				WZCConfigItemDelete( &( pWZCConfigListItem->pNext ) );

			WZCConfigItemDelete( &pWZCConfigListItem );
		}

		//
		// Turn on 802.1X to make sure
		//
		if( ( dwRet = pWZCContext->pfnWZCEapolGetInterfaceParams( NULL,
																	pwcGUID,
																	&IntfParams ) ) == NO_ERROR )
		{

			IntfParams.dwEapFlags = IntfParams.dwEapFlags | EAPOL_ENABLED;

			if( ( dwRet = pWZCContext->pfnWZCEapolSetInterfaceParams( NULL,
																	pwcGUID,
																	&IntfParams ) ) == NO_ERROR )
			{
				//
				// Turn on ZerConf to make sure
				//
				if( ( dwRet = WZCSetZeroConfState( pWZCContext, pwcGUID, TRUE ) ) == NO_ERROR )
				{
					dwRet = WZCSetCurrentSSID( pWZCContext, pwcGUID, pwcSSID );
				}
			}
		}

		dwRet = WZCSetCurrentSSID( pWZCContext, pwcGUID, pwcSSID );

		if( pcSSID )
			free( pcSSID );
	}

	return dwRet;
}

DWORD
WZCLogoff( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, IN WCHAR *pwcSSID )
{
	EAPOL_INTF_PARAMS	IntfParams;
	PCHAR				pcSSID;
	DWORD				ccSSID;
	DWORD				dwRet;

	dwRet = NO_ERROR;

	memset( &IntfParams, 0, sizeof( EAPOL_INTF_PARAMS ) );

	ccSSID = ( DWORD ) wcslen( pwcSSID );

	if( ( pcSSID = ( PCHAR ) malloc( ccSSID + 1 ) ) )
	{
		if( WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, ccSSID + 1, NULL, NULL ) > 0 )
		{
			memcpy( IntfParams.bSSID, pcSSID, ccSSID );
			IntfParams.dwSizeOfSSID = ccSSID;

			if( ( dwRet = pWZCContext->pfnWZCEapolGetInterfaceParams( NULL,
																		pwcGUID,
																		&IntfParams ) ) == NO_ERROR )
			{
				//
				// Turn it off
				//
				IntfParams.dwEapFlags = IntfParams.dwEapFlags & 0x7fffffff;

				if( ( dwRet = pWZCContext->pfnWZCEapolSetInterfaceParams( NULL,
																		pwcGUID,
																		&IntfParams ) ) == NO_ERROR )
				{
/*
					dwRet = NO_ERROR;

					while( dwRet == NO_ERROR )
					{
						if( ( dwRet = WZCGetMediaState( pWZCContext, pwcGUID ) ) == NO_ERROR )
						{
							printf( "waiting..." ) ) );
						}

						Sleep( 1000 );
					}

					if( dwRet == ERROR_MEDIA_OFFLINE )
					{

						dwRet = WZCSetMediaState( pWZCContext, pwcGUID, TRUE );
*/
						dwRet = WZCSetCurrentSSID( pWZCContext, pwcGUID, L"                               " );

						if( ( dwRet = WZCSetZeroConfState( pWZCContext, pwcGUID, FALSE ) ) == NO_ERROR )
						{
							//
							// Turn 802.1X back on
							//
							IntfParams.dwEapFlags = IntfParams.dwEapFlags | EAPOL_ENABLED;

							dwRet = pWZCContext->pfnWZCEapolSetInterfaceParams( NULL,
																				pwcGUID,
																				&IntfParams );
						}
					//}
				}
			}
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcSSID );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

#ifdef AA_WZC_LIB_XP_SP1
DWORD
WZCGetCurrentEapState( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WCHAR *pwcGUID, EAPOL_INTF_STATE *pIntfState )
{
	DWORD	dwRet;

	dwRet = NO_ERROR;

	memset( pIntfState, 0, sizeof( EAPOL_INTF_STATE ) );

	dwRet = pWZCContext->pfnWZCEapolQueryState( NULL,
												pwcGUID,
												pIntfState );
	return dwRet;
}
#endif // AA_WZC_LIB_XP_SP1

DWORD
WZCEnd( IN PAA_WZC_LIB_CONTEXT pWZCContext )
{
	DWORD	dwRet;

	dwRet = NO_ERROR;

	FreeLibrary( pWZCContext->hWZCDll );

	free( pWZCContext );

	return dwRet;
}