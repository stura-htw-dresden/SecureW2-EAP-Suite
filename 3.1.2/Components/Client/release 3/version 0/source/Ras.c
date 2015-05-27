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
// Name: Ras.c
// Description: Contains the DLL entry points for thr RAS API
// Author: Tom Rixom
// Created: 17 December 2002
// Version: 1.0
// Last revision: 25 june 2003
//
// ----------------------------- Revisions -------------------------------
//
// Revision - <Date of revision> <Version of file which has been revised> <Name of author>
// <Description of what has been revised>
//
// Added invoke username and password handling - 27 Februari 2003 - Tom Rixom
// SecureW2 now checks if we have to use our dialogbox to aquire user creds
//
// Added EAP-Support - 26 Februari 2003 - Tom Rixom
// Can now select different EAP methods to tunnel through TLS
//
// * BUG FIX * connect to CSP using user store not machine store (failed with Windows XP) - 24 Februari 2003 - Tom Rixom
// When connecting to the machine store it is user specific, so if the store was created using Administrator only Administrator can connect to the store...
// See RasEapBegin when connecting to SChannel CSP
//
// Added DHCP-Fix - 24 june 2003 - Tom Rixom
// Ip address is renewed when authentication is successfull, currently it will renew all Ip addresses.
//
// Added config fix - 25 june 2003 - Tom Rixom
// If you select SecureW2 as the authentication for the first time but do not configure the module
// previous version would simply return error incorrect config size when called. Now if the config
// size is null or incorrect then we use a default config
//
// Added cert check - 21 Juli 2003 - Tom Rixom
// Added extra certificate check. The server certificate must be installed
// in the computer "My" Store.
//
// Removed License from SecureW2 2 XP - 23 Januari 2004 - Tom Rixom
// SecureW2 PPC still needs a license
//
// SecureW2 can now be configured to not accept new connections - 22 April 2004 - Tom Rixom
//
// SecureW2 can now save the user credentials filled in during authentication - 25 May 2004 - Tom Rixom
//
// Added SecureW2 Gina functionality - 23 October 2004 - Tom Rixom
// Each RasEap function will write the Error result to the registry, only RasEapEnd writes a success result
//

#include "Main.h"
#ifndef _WIN32_WCE
#include <Iphlpapi.h>
#endif // _WIN32_WCE

//
// Name: RasEapGetInfo
// Description: DLL entry point for RasEapGetInfo, called when Windows boots up to retrieve DLL Entry points
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD 
APIENTRY
RasEapGetInfo(	IN  DWORD			dwEapTypeId,
				OUT PPPP_EAP_INFO	pEapInfo )
{
	PPP_EAP_INFO	EapInfo;

	AA_TRACE( ( TEXT( "RasEapGetInfo" ) ) );

    if( dwEapTypeId != EAP_PROTOCOL_ID )
    {
		AA_TRACE( ( TEXT( "RasEapGetInfo::Incorrect EAP_TYPE: %ld" ), dwEapTypeId ) );

		//
		// Report error to event viewer
		//	
		AA_ReportEvent( L"RasEapGetInfo Failed", EVENTLOG_ERROR_TYPE, ERROR_NOT_SUPPORTED );

		return ERROR_NOT_SUPPORTED;
    }

    EapInfo.dwEapTypeId       = dwEapTypeId;
	EapInfo.RasEapInitialize  = NULL; 
    EapInfo.RasEapBegin       = RasEapBegin;
    EapInfo.RasEapEnd         = RasEapEnd;
    EapInfo.RasEapMakeMessage = RasEapMakeMessage;

	EapInfo.dwSizeInBytes = sizeof( PPP_EAP_INFO );

	*pEapInfo = EapInfo;

	AA_TRACE( ( TEXT( "RasEapGetInfo::returning" ) ) );

    return NO_ERROR;
}

//
// Name: RasEapGetEAPIdentity
// Description: retrieves the EAP user information
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
RasEapGetEAPIdentity(	PSW2_PROFILE_DATA	pProfileData,
						IN DWORD			dwEapTypeId,
						IN HWND				hwndParent,
						IN DWORD			dwFlags,
						IN const WCHAR *	pwcPhonebook,
						IN const WCHAR *	pwcEntry,
						IN BYTE *			pConnectionDataIn,
						IN DWORD			dwSizeOfConnectionDataIn,
						IN BYTE *			pUserDataIn,
						IN DWORD			dwSizeOfUserDataIn,
						OUT PBYTE *			ppUserDataOut,
						OUT DWORD *			pdwSizeOfUserDataOut,
						OUT WCHAR **		ppwcIdentity )
{
	SW2_INNER_EAP_CONFIG_DATA	InnerEapConfigData;
	HINSTANCE					hEapInstance;
	PINNEREAPGETIDENTITY		pInnerEapGetIdentity;
	PINNEREAPFREEMEMORY			pInnerEapFreeMemory;
	PSW2_USER_DATA				pUserData;
	PBYTE						pbInnerEapUserDataOut = NULL;
	DWORD						dwInnerEapUserDataOut = 0;
	WCHAR						*pwcInnerEapIdentityOut;
	WCHAR						*pwcDomain;
	WCHAR						*pwcIdentity;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "RasEapGetEAPIdentity" ) ) );

	//
	// First let's check in the registry if the inner eap requires
	// handles the username password itself.
	//
	if( ( dwRet = AA_ReadInnerEapMethod( dwEapTypeId, 
										pProfileData->pwcCurrentProfileId,
										&InnerEapConfigData ) ) == NO_ERROR )
	{
		if( ( InnerEapConfigData.dwInvokeUsernameDlg == 1 ) )
			//&& ( InnerEapConfigData.dwInvokePasswordDlg == 1  ) )
		{
			//
			// Must call our own dialogbox (much cooler) ;)
			//
			if ( ( dwRet = RasEapGetPAPIdentity(pProfileData, 
												dwEapTypeId,
												hwndParent,
												dwFlags,
												pwcPhonebook,
												pwcEntry,
												pConnectionDataIn,
												dwSizeOfConnectionDataIn,
												pUserDataIn,
												dwSizeOfUserDataIn,
												ppUserDataOut,
												pdwSizeOfUserDataOut,
												ppwcIdentity ) ) == NO_ERROR )
			{
				//
				// Use our own dialog box, later in RasEapBegin we need to set the Identity and Password field
				//
				pUserData = ( PSW2_USER_DATA ) *ppUserDataOut;

				//
				// Because we used our own dialog box we can stick the domain name onto the end
				//
				if( wcslen( pUserData->pwcDomain ) > 0 )
				{
					wcscpy( pUserData->InnerEapUserData.pwcIdentity, pUserData->pwcUsername );

					//
					// If we have enough space then copy the domain onto the end
					//
					if ( ( wcslen( pUserData->pwcUsername ) + 1 + 
													wcslen( pUserData->pwcUsername ) ) < UNLEN )
					{
						wcscat( pUserData->InnerEapUserData.pwcIdentity, L"@" );
						wcscat( pUserData->InnerEapUserData.pwcIdentity, pUserData->pwcDomain );
					}
				}
				else
				{
					wcscpy( pUserData->InnerEapUserData.pwcIdentity, pUserData->pwcUsername );
				}
			}
		}
		else
		{
			//
			// Pass everything on to EAP DLL
			//
			if( ( pUserData = ( PSW2_USER_DATA ) malloc( sizeof( SW2_USER_DATA ) ) ) )
			{
				memset( pUserData, 0, sizeof( SW2_USER_DATA ) );

				pUserData->PrevAuthResult = PREV_AUTH_RESULT_pending;

				AA_TRACE( ( TEXT( "RasEapGetEAPIdentity:: pwcEapPath: %s" ), InnerEapConfigData.pwcEapPath ) );

				//
				// Connect to EAP DLL
				//
				if( ( hEapInstance = LoadLibrary( InnerEapConfigData.pwcEapPath ) ) )
				{
#ifndef _WIN32_WCE
					if( ( pInnerEapGetIdentity = ( PINNEREAPGETIDENTITY ) 
										GetProcAddress( hEapInstance, "RasEapGetIdentity" ) ) )
#else
					if( ( pInnerEapGetIdentity = ( PINNEREAPGETIDENTITY ) 
										GetProcAddress( hEapInstance, L"RasEapGetIdentity" ) ) )
#endif // _WIN32_WCE
					{
						AA_TRACE( ( TEXT( "RasEapGetEAPIdentity:: cbConnectionData: %ld" ), InnerEapConfigData.cbConnectionData ) );

						if(	( dwRet = pInnerEapGetIdentity( InnerEapConfigData.dwEapType,
															hwndParent,
															dwFlags,
															pwcPhonebook,
															pwcEntry,
															InnerEapConfigData.pbConnectionData,
															InnerEapConfigData.cbConnectionData,
															NULL,
															0,
															&pbInnerEapUserDataOut,
															&dwInnerEapUserDataOut,
															&pwcInnerEapIdentityOut ) ) == NO_ERROR )
						{
							AA_TRACE( ( TEXT( "RasEapGetEAPIdentity:: dwInnerEapUserDataOut: %ld" ), dwInnerEapUserDataOut ) );

							if( pwcInnerEapIdentityOut )
								if( wcslen( pwcInnerEapIdentityOut ) > 0 )
									AA_TRACE( ( TEXT( "RasEapGetEAPIdentity:: pwcInnerIdentityOut: %s" ), pwcInnerEapIdentityOut ) );

#ifndef _WIN32_WCE
							if( ( pInnerEapFreeMemory = ( PINNEREAPFREEMEMORY ) 
										GetProcAddress( hEapInstance, "RasEapFreeMemory" ) ) )
#else
							if( ( pInnerEapFreeMemory = ( PINNEREAPFREEMEMORY )
										GetProcAddress( hEapInstance, L"RasEapFreeMemory" ) ) )
#endif // _WIN32_WCE
							{
								//
								// Copy the inner user data and then free it
								//
								if( dwInnerEapUserDataOut <= EAP_MAX_INNER_DATA )
								{
									pUserData->InnerEapUserData.cbUserData = dwInnerEapUserDataOut;

									memcpy( pUserData->InnerEapUserData.pbUserData, 
											pbInnerEapUserDataOut, 
											pUserData->InnerEapUserData.cbUserData );

									pInnerEapFreeMemory( pbInnerEapUserDataOut );

									if( pwcInnerEapIdentityOut )
									{
										if( wcslen( pwcInnerEapIdentityOut ) )
										{
											//
											// Copy the inner Identity
											//
											if( wcslen( pwcInnerEapIdentityOut ) <= 
																			( UNLEN * sizeof( WCHAR ) ) )
											{
												wcscpy( pUserData->InnerEapUserData.pwcIdentity, 
														pwcInnerEapIdentityOut );
											}
											else
											{
												AA_TRACE( ( TEXT( "RasEapGetEAPIdentity:: pwcInnerEapIdentityOut is too large" ) ) );

												dwRet = ERROR_NOT_ENOUGH_MEMORY;
											}
										}

										pInnerEapFreeMemory( ( PBYTE ) pwcInnerEapIdentityOut );
									}
									else
									{
										dwRet = ERROR_NOT_ENOUGH_MEMORY;
									}
								}
								else
								{
									AA_TRACE( ( TEXT( "RasEapGetEAPIdentity:: dwInnerUserDataOut is too large" ) ) );

									dwRet = ERROR_NOT_ENOUGH_MEMORY;
								}
							}
							else
							{
								dwRet = ERROR_DLL_INIT_FAILED;
							}

							if( dwRet == NO_ERROR && 
								pProfileData->bUseAlternateOuter && 
								pProfileData->bUseAlternateAnonymous )
							{
								//
								// Use alternate anonymous outer identity
								//
								//
								// Check if we have an @ in the username which will be followed by the domain
								//
								if( ( pwcDomain = wcsstr( pUserData->InnerEapUserData.pwcIdentity, L"@" ) ) )
								{
									//
									// Outer authentication will be anonymous@domain
									//
									AA_TRACE( ( TEXT( "RasEapGetEAPIdentity:: pwcDomain: %ws" ), pwcDomain ) );

									pwcDomain = pwcDomain + 1;

									//
									// Outer authentication will be anonymous
									//
									if( ( pwcIdentity = ( WCHAR* ) 
										malloc( ( 
										( wcslen( TLS_ANONYMOUS_USERNAME ) + 
										  1 + 
										  wcslen( pwcDomain ) 
										  + 1 )
										 * sizeof( WCHAR ) ) ) ) )
									{
										*ppUserDataOut = ( PBYTE ) pUserData;
										*pdwSizeOfUserDataOut = sizeof( SW2_USER_DATA );

										wcscpy( pwcIdentity, TLS_ANONYMOUS_USERNAME );
										wcscat( pwcIdentity, L"@" );
										wcscat( pwcIdentity, pwcDomain );

										*ppwcIdentity = pwcIdentity;

										AA_TRACE( ( TEXT( "RasEapGetEAPIdentity::Anonymous user: %ws" ), *ppwcIdentity ) );
									}
									else
									{
										AA_TRACE( ( TEXT( "RasEapGetEAPIdentity::could not allocate memory for pwcIdentity" ) ) );

										dwRet = ERROR_NOT_ENOUGH_MEMORY;
									}
								}
								else
								{
									//
									// Outer authentication will be anonymous
									//
									if( ( pwcIdentity = ( WCHAR* ) 
										malloc( 
										( ( wcslen( TLS_ANONYMOUS_USERNAME ) + 1 ) * sizeof( WCHAR ) )
										) ) )
									{
										*ppUserDataOut = ( PBYTE ) pUserData;
										*pdwSizeOfUserDataOut = sizeof( SW2_USER_DATA );

										wcscpy( pwcIdentity, TLS_ANONYMOUS_USERNAME );

										*ppwcIdentity = pwcIdentity;

										AA_TRACE( ( TEXT( "RasEapGetEAPIdentity::Anonymous user: %ws" ), *ppwcIdentity ) );
									}
									else
									{
										AA_TRACE( ( TEXT( "RasEapGetEAPIdentity::could not allocate memory for pwcIdentity" ) ) );

										dwRet = ERROR_NOT_ENOUGH_MEMORY;
									}
								}
							}
							else if( dwRet == NO_ERROR 
										&& pProfileData->bUseAlternateOuter
										&& !pProfileData->bUseAlternateAnonymous )
							{
								//
								// Outer authentication will use alternate username
								//
								if( ( pwcIdentity = ( WCHAR* ) 
									malloc( 
									( ( wcslen( pProfileData->pwcAlternateOuter ) + 1 )
									* sizeof( WCHAR ) )
									) ) )
								{
									*ppUserDataOut = ( PBYTE ) pUserData;
									*pdwSizeOfUserDataOut = sizeof( SW2_USER_DATA );

									wcscpy( pwcIdentity, pProfileData->pwcAlternateOuter );

									*ppwcIdentity = pwcIdentity;

									AA_TRACE( ( TEXT( "RasEapGetEAPIdentity::Alternate identity: %ws" ), *ppwcIdentity ) );
								}
								else
								{
									AA_TRACE( ( TEXT( "RasEapGetEAPIdentity::could not allocate memory for pwcIdentity" ) ) );

									dwRet = ERROR_NOT_ENOUGH_MEMORY;
								}
							}
							else if( dwRet == NO_ERROR )
							{
								//
								// Outer authentication will be user@domain
								//
								if( ( pwcIdentity = ( WCHAR* ) 
									malloc( 
									( ( wcslen( pUserData->InnerEapUserData.pwcIdentity ) + 1 )
									* sizeof( WCHAR ) )
									) ) )
								{
									*ppUserDataOut = ( PBYTE ) pUserData;
									*pdwSizeOfUserDataOut = sizeof( SW2_USER_DATA );

									wcscpy( pwcIdentity, pUserData->InnerEapUserData.pwcIdentity );

									*ppwcIdentity = pwcIdentity;

									AA_TRACE( ( TEXT( "RasEapGetEAPIdentity::identity: %ws" ), *ppwcIdentity ) );
								}
								else
								{
									AA_TRACE( ( TEXT( "RasEapGetEAPIdentity::could not allocate memory for pwcIdentity" ) ) );

									dwRet = ERROR_NOT_ENOUGH_MEMORY;
								}
							}
						}
						else
						{
							AA_TRACE( ( TEXT( "RasEapGetEAPIdentity::pInnerEapGetIdentity FAILED: %d" ), dwRet ) );
						}
					}
					else
					{
						AA_TRACE( ( TEXT( "RasEapGetEAPIdentity:: GetProcAddress FAILED" ) ) );

						dwRet = ERROR_DLL_INIT_FAILED;
					}

					FreeLibrary( hEapInstance );
				}
				else
				{
					AA_TRACE( ( TEXT( "RasEapGetEAPIdentity:: LoadLibrary FAILED: %ld" ), GetLastError() ) );

					dwRet = ERROR_DLL_INIT_FAILED;
				}

				//
				// Something went wrong so clean up allocated memory
				//
				if( dwRet != NO_ERROR )
					free( pUserData );
			}
			else
			{
				AA_TRACE( ( TEXT( "RasEapGetEAPIdentity::could not allocate memory for pUserData" ) ) );

				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
	}

	AA_TRACE( ( TEXT( "RasEapGetEAPIdentity::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: RasEapGetPAPIdentity
// Description: retrieves the PAP user information
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
RasEapGetPAPIdentity(	PSW2_PROFILE_DATA	pProfileData,
						IN DWORD			dwEapTypeId,
						IN HWND				hwndParent,
						IN DWORD			dwFlags,
						IN const WCHAR *	pwcPhonebook,
						IN const WCHAR *	pwcEntry,
						IN BYTE *			pConnectionDataIn,
						IN DWORD			dwSizeOfConnectionDataIn,
						IN BYTE *			pUserDataIn,
						IN DWORD			dwSizeOfUserDataIn,
						OUT PBYTE *			ppUserDataOut,
						OUT DWORD *			pdwSizeOfUserDataOut,
						OUT WCHAR **		ppwcIdentity )
{
	PSW2_USER_DATA		pUserData;
#ifdef _WIN32_WCE
//	WNDCLASS			wc;
	//HWND				hWnd;
	//MSG					msg;
#endif // _WIN32_WCE
	WCHAR				pwcUsername[UNLEN];
	WCHAR				*pwcIdentity;
	WCHAR				*pwcTemp;
	DWORD				dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "RasEapGetPAPIdentity" ) ) );

	//
	// Return credentials from SW2 Gina
	//
#ifndef _WIN32_WCE
	if( pProfileData->GinaConfigData.bUseSW2Gina )
	{
		return RasEapGetGinaIdentity(	pProfileData, 
										dwEapTypeId,
										hwndParent,
										dwFlags,
										pwcPhonebook,
										pwcEntry,
										pConnectionDataIn,
										dwSizeOfConnectionDataIn,
										pUserDataIn,
										dwSizeOfUserDataIn,
										ppUserDataOut,
										pdwSizeOfUserDataOut,
										ppwcIdentity );
	}
#endif // _WIN32_WCE

	//
	// Microsoft BUG check Windows have a 30 second timeout, too short:
	// If we are already showing a dialog then
	// cancel this request
	//
	if( FindWindow( WC_DIALOG, L"SecureW2 Credentials" ) )
	{
		AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::Username Dialog already shown" ) ) );

		return PENDING;
	}

	if( ( pUserData = ( PSW2_USER_DATA ) malloc( sizeof( SW2_USER_DATA ) ) ) )
	{
		memset( pUserData, 0, sizeof( SW2_USER_DATA ) );

		AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::checking for pUserDataIn(%ld), looking for size %ld" ), 
				dwSizeOfUserDataIn, sizeof (SW2_USER_DATA) ) ) ;

		if( dwFlags & RAS_EAP_FLAG_MACHINE_AUTH )
		{
			AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::Authenticating as computer" ) ) );

#ifndef _WIN32_WCE

			AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::pProfileData->bUseAlternateComputerCred: %ld" ), pProfileData->bUseAlternateComputerCred ) );
			AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::pProfileData->bUseCredentialsForComputer: %ld" ), pProfileData->bUseCredentialsForComputer ) );
			AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::wcslen( pProfileData->pwcCompName ): %ld" ), wcslen( pProfileData->pwcCompName ) ) );
			AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::wcslen( pProfileData->pwcCompPassword ): %ld" ), wcslen( pProfileData->pwcCompPassword ) ) );
			//
			// Authenticating as machine
			//
			if( ( pProfileData->bUseAlternateComputerCred ||
				pProfileData->bUseCredentialsForComputer ) &&
				( wcslen( pProfileData->pwcCompName ) > 0 ) &&
				( wcslen( pProfileData->pwcCompPassword ) > 0 ) )
			{
				AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::using computer credentials" ) ) );

				//
				// Can copy the password as we should have been able to read it
				//
				memcpy( pUserData->pwcUsername, 
						pProfileData->pwcCompName, 
						sizeof( pUserData->pwcUsername ) );
				memcpy( pUserData->pwcPassword, 
						pProfileData->pwcCompPassword, 
						sizeof( pUserData->pwcPassword ) );
				memcpy( pUserData->pwcDomain, 
						pProfileData->pwcCompDomain, 
						sizeof( pUserData->pwcDomain ) );
			}
			else
#endif // _WIN32_WCE
				dwRet = ERROR_NO_SUCH_USER;
		}
		else
		{
			AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::Authenticating as user" ) ) );

			if( pProfileData->bPromptUser )
			{
				AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::prompting user" ) ) );

				if( dwFlags & RAS_EAP_FLAG_NON_INTERACTIVE )
				{
					dwRet = ERROR_INTERACTIVE_MODE;
				}
				else
				{
					//
					// Windows BUG, sometimes called when in secure desktop but handle is crap!!
					// so check dwFlags for RAS_EAP_FLAG_MACHINE_AUTH
					//
					if( !( dwFlags & RAS_EAP_FLAG_MACHINE_AUTH ) )
					{
						AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::showing dialog" ) ) );

						//
						// Copy any information we already have
						//
						memcpy( pUserData->pwcUsername, 
								pProfileData->pwcUserName, 
								sizeof( pUserData->pwcUsername ) );

						memcpy( pUserData->pwcDomain, 
								pProfileData->pwcUserDomain, 
								sizeof( pUserData->pwcDomain ) );

						//
						// Show username dialog
						//
						if( !DialogBoxParam( ghInstance,
											MAKEINTRESOURCE( IDD_CRED_DLG ),
											hwndParent,
											CredentialsDlgProc,
											( LPARAM ) pUserData ) )
						{
							dwRet = ERROR_CANCELLED;
						}
					}
					else
					{
						dwRet = ERROR_NOT_SUPPORTED;
					}
				}
			}
			else if ( wcslen( pProfileData->pwcUserName ) > 0 )
			{
				AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::using user credentials" ) ) );

				//
				// We retrieve the password later
				//
				memcpy( pUserData->pwcUsername, 
						pProfileData->pwcUserName, 
						sizeof( pUserData->pwcUsername ) );

				memcpy( pUserData->pwcDomain, 
						pProfileData->pwcUserDomain, 
						sizeof( pUserData->pwcDomain ) );
			}
			else
				dwRet = ERROR_NO_SUCH_USER;
		}

		if( dwRet == NO_ERROR )
		{
			//
			// It is possible to put the domain name in the following form:
			// tom@tom.com
			//
			if( ( pwcTemp = wcsstr( pUserData->pwcUsername, L"@" ) ) )
			{
				memset( pwcUsername, 0, UNLEN *sizeof( WCHAR ) );

				wcsncpy( pwcUsername, pUserData->pwcUsername, wcslen( pUserData->pwcUsername ) - wcslen( pwcTemp ) );

				//
				// strip domain from pwcUsername and copy it to pwcDomain
				//
				pwcTemp++;

				memcpy( pUserData->pwcDomain, pwcTemp, ( wcslen( pwcTemp ) * sizeof( WCHAR ) ) );

				memset( pUserData->pwcUsername, 0, UNLEN * sizeof( WCHAR ) );

				wcscpy( pUserData->pwcUsername, pwcUsername );
			}

			AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::Username: %s" ), pUserData->pwcUsername ) );
			AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::Domain: %s" ), pUserData->pwcDomain ) );

			//
			// Small bug fix, Tom Rixom
			// Checked alternate ident incorrectly
			//
			if( pProfileData->bUseAlternateOuter )
			{
				if( pProfileData->bUseAlternateAnonymous )
				{
					//
					// Outer authentication will be anonymous@domain
					//
					if( ( pwcIdentity = ( WCHAR* ) malloc( ( ( wcslen( TLS_ANONYMOUS_USERNAME ) + 1 + wcslen( pUserData->pwcDomain ) + 1 ) * sizeof( WCHAR ) ) ) ) )
					{
						*ppUserDataOut = ( PBYTE ) pUserData;
						*pdwSizeOfUserDataOut = sizeof( SW2_USER_DATA );

						wcscpy( pwcIdentity, TLS_ANONYMOUS_USERNAME );

						if( wcslen( pUserData->pwcDomain ) > 0 )
						{
							wcscat( pwcIdentity, L"@" );
							wcscat( pwcIdentity, pUserData->pwcDomain );
						}

						*ppwcIdentity = pwcIdentity;

						AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::Anonymous user: %s" ), *ppwcIdentity ) );
					}
					else
					{
						AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::could not allocate memory for pwcIdentity" ) ) );

						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
				}
				else
				{
					//
					// Outer authentication will alternate username
					//
					if( ( pwcIdentity = ( WCHAR* ) malloc( ( ( wcslen( pProfileData->pwcAlternateOuter ) + 1 ) * sizeof( WCHAR ) ) ) ) )
					{
						*ppUserDataOut = ( PBYTE ) pUserData;
						*pdwSizeOfUserDataOut = sizeof( SW2_USER_DATA );

						wcscpy( pwcIdentity, pProfileData->pwcAlternateOuter );

						*ppwcIdentity = pwcIdentity;

						AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::Alternate identity: %ws" ), *ppwcIdentity ) );
					}
					else
					{
						AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::could not allocate memory for pwcIdentity" ) ) );

						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
				}
			}
			else
			{
				//
				// Outer authentication will be user@domain
				//
				if( ( pwcIdentity = ( WCHAR* ) malloc( ( ( wcslen( pUserData->pwcUsername ) + 1 + wcslen( pUserData->pwcDomain ) + 1 ) * sizeof( WCHAR ) ) ) ) )
				{
					*ppUserDataOut = ( PBYTE ) pUserData;
					*pdwSizeOfUserDataOut = sizeof( SW2_USER_DATA );

					wcscpy( pwcIdentity, pUserData->pwcUsername );

					if( wcslen( pUserData->pwcDomain ) > 0 )
					{
						wcscat( pwcIdentity, L"@" );
						wcscat( pwcIdentity, pUserData->pwcDomain );
					}

					*ppwcIdentity = pwcIdentity;

					AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::Anonymous user: %s" ), *ppwcIdentity ) );
				}
				else
				{
					AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::could not allocate memory for pwcIdentity" ) ) );

					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
		}

		//
		// Something went wrong so clean up allocated memory
		//
		if( dwRet != NO_ERROR )
			free( pUserData );
	}
	else
	{
		AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::could not allocate memory for pUserData" ) ) );

		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	AA_TRACE( ( TEXT( "RasEapGetPAPIdentity::returning %ld" ), dwRet ) );

	return dwRet;
}

#ifndef _WIN32_WCE
//
// Name: RasEapGetGinaIdentity
// Description: RasEapGetGinaIdentity is called when we want to retreive the Identiry from the SW2 Gina
// Author: Tom Rixom
// Created: 4 November 2004
//
DWORD
RasEapGetGinaIdentity(	PSW2_PROFILE_DATA	pProfileData,	
						IN DWORD			dwEapTypeId,
						IN HWND				hwndParent,
						IN DWORD			dwFlags,
						IN const WCHAR *	pwcPhonebook,
						IN const WCHAR *	pwcEntry,
						IN BYTE *			pConnectionDataIn,
						IN DWORD			dwSizeOfConnectionDataIn,
						IN BYTE *			pUserDataIn,
						IN DWORD			dwSizeOfUserDataIn,
						OUT PBYTE *			ppUserDataOut,
						OUT DWORD *			pdwSizeOfUserDataOut,
						OUT WCHAR **		ppwcIdentity  )
{
	HKEY				hKey;
	PSW2_USER_DATA		pUserData;
	WCHAR				pwcUsername[UNLEN];
	WCHAR				*pwcIdentity;
	WCHAR				*pwcTemp;
	PBYTE				pbData;
	PBYTE				pbXorData;
	DWORD				cbData;
	DWORD				dwRet;
	DWORD				dwRet2;

	dwRet = NO_ERROR;
	dwRet2 = NO_ERROR;

	AA_TRACE( ( TEXT( "RasEapGetGinaIdentity" ) ) );

	if( ( pUserData = ( PSW2_USER_DATA ) malloc( sizeof( SW2_USER_DATA ) ) ) )
	{
		memset( pUserData, 0, sizeof( SW2_USER_DATA ) );

		pUserData->PrevAuthResult = PREV_AUTH_RESULT_pending;

		if( ( dwRet = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
									AA_GINA_LOCATION,
									0,
									KEY_ALL_ACCESS,
									&hKey ) ) == ERROR_SUCCESS )
		{
			AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::opened gina reg key" ) ) );

			if( ( dwRet = AA_RegGetValue( hKey,
							L"UserName",
							&pbData,
							&cbData ) ) == NO_ERROR )
			{
				AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::found username" ) ) );

				memset( pUserData->pwcUsername, 0, sizeof( pUserData->pwcUsername ) );
				memcpy( pUserData->pwcUsername, pbData, cbData );

				AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::%s" ), pUserData->pwcUsername ) );

				free( pbData );
			}

			if( ( dwRet = AA_RegGetValue( hKey,
							L"Domain",
							&pbData,
							&cbData ) ) == NO_ERROR )
			{
				AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::found domain" ) ) );

				memset( pUserData->pwcDomain, 0, sizeof( pUserData->pwcDomain) );
				memcpy( pUserData->pwcDomain, pbData, cbData );

				AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::%s" ), pUserData->pwcDomain ) );

				free( pbData );
			}

			if( ( dwRet = AA_RegGetValue( hKey,
							L"Password",
							&pbData,
							&cbData ) ) == NO_ERROR )
			{
				AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::found password" ) ) );

				if( ( dwRet = AA_XorData( pbData, 
										cbData, 
										AA_SECRET, 
										( DWORD ) strlen( AA_SECRET ),
										&pbXorData ) ) == NO_ERROR )
				{
					memset( pUserData->pwcPassword, 0, sizeof( pUserData->pwcPassword ) );

					memcpy( pUserData->pwcPassword, pbXorData, cbData );

					AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::%s" ), pUserData->pwcPassword ) );

					free( pbXorData );
				}

				free( pbData );
			}

			RegCloseKey( hKey );
		}
		else
		{
			AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::FAILED opening reg key: %s (%ld)" ), AA_GINA_LOCATION, dwRet ) );
		}

		if( dwRet == NO_ERROR )
		{
			//
			// It is possible to put the domain name in the following form:
			// tom@tom.com
			//
			if( ( pwcTemp = wcsstr( pUserData->pwcUsername, L"@" ) ) )
			{
				memset( pwcUsername, 0, UNLEN *sizeof( WCHAR ) );

				wcsncpy( pwcUsername, pUserData->pwcUsername, wcslen( pUserData->pwcUsername ) - wcslen( pwcTemp ) );

				//
				// strip domain from pwcUsername and copy it to pwcDomain
				//
				pwcTemp++;

				memcpy( pUserData->pwcDomain, pwcTemp, ( wcslen( pwcTemp ) * sizeof( WCHAR ) ) );

				memset( pUserData->pwcUsername, 0, UNLEN * sizeof( WCHAR ) );

				wcscpy( pUserData->pwcUsername, pwcUsername );
			}

			//
			// If we have a GinaDomainName overwrite domain name
			//
			if( wcslen( pProfileData->GinaConfigData.pwcGinaDomainName ) > 0 )
			{
				memset( pUserData->pwcDomain, 0, sizeof( pUserData->pwcDomain) );
				wcscpy( pUserData->pwcDomain, pProfileData->GinaConfigData.pwcGinaDomainName );
			}

			AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::Username: %s" ), pUserData->pwcUsername ) );
			AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::Domain: %s" ), pUserData->pwcDomain ) );

			if( pProfileData->bUseAlternateOuter )
			{
				if( pProfileData->bUseAlternateAnonymous )
				{
					//
					// Outer authentication will be anonymous@domain
					//
					if( ( pwcIdentity = ( WCHAR* ) malloc( ( ( wcslen( TLS_ANONYMOUS_USERNAME ) + 1 + wcslen( pUserData->pwcDomain ) + 1 ) * sizeof( WCHAR ) ) ) ) )
					{
						*ppUserDataOut = ( PBYTE ) pUserData;
						*pdwSizeOfUserDataOut = sizeof( SW2_USER_DATA );

						wcscpy( pwcIdentity, TLS_ANONYMOUS_USERNAME );

						if( wcslen( pUserData->pwcDomain ) > 0 )
						{
							wcscat( pwcIdentity, L"@" );
							wcscat( pwcIdentity, pUserData->pwcDomain );
						}

						*ppwcIdentity = pwcIdentity;

						AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::Anonymous user: %s" ), *ppwcIdentity ) );
					}
					else
					{
						AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::could not allocate memory for pwcIdentity" ) ) );

						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
				}
				else
				{
					//
					// Outer authentication will alternate username
					//
					if( ( pwcIdentity = ( WCHAR* ) malloc( ( ( wcslen( pProfileData->pwcAlternateOuter ) + 1 ) * sizeof( WCHAR ) ) ) ) )
					{
						*ppUserDataOut = ( PBYTE ) pUserData;
						*pdwSizeOfUserDataOut = sizeof( SW2_USER_DATA );

						wcscpy( pwcIdentity, pProfileData->pwcAlternateOuter );

						*ppwcIdentity = pwcIdentity;

						AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::Alternate identity: %ws" ), *ppwcIdentity ) );
					}
					else
					{
						AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::could not allocate memory for pwcIdentity" ) ) );

						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
				}
			}
			else
			{
				//
				// Outer authentication will be user@domain
				//
				if( ( pwcIdentity = ( WCHAR* ) malloc( ( ( wcslen( pUserData->pwcUsername ) + 1 + wcslen( pUserData->pwcDomain ) + 1 ) * sizeof( WCHAR ) ) ) ) )
				{
					*ppUserDataOut = ( PBYTE ) pUserData;
					*pdwSizeOfUserDataOut = sizeof( SW2_USER_DATA );

					wcscpy( pwcIdentity, pUserData->pwcUsername );

					if( wcslen( pUserData->pwcDomain ) > 0 )
					{
						wcscat( pwcIdentity, L"@" );
						wcscat( pwcIdentity, pUserData->pwcDomain );
					}

					*ppwcIdentity = pwcIdentity;

					AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::Anonymous user: %s" ), *ppwcIdentity ) );
				}
				else
				{
					AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::could not allocate memory for pwcIdentity" ) ) );

					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
		}
		else
			dwRet = ERROR_NO_SUCH_USER;

		//
		// Something went wrong so clean up allocated memory
		//
		if( dwRet != NO_ERROR )
			free( pUserData );
	}
	else
	{
		AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::could not allocate memory for pUserData" ) ) );

		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::error: %ld" ), dwRet ) );

	//
	// Only write result if something failed (except if we could not find user credentials)
	//
	if( ( dwRet != NO_ERROR ) && 
		( dwRet != ERROR_NO_SUCH_USER ) )
	{
		AA_WriteResult( dwRet );
	}

	AA_TRACE( ( TEXT( "RasEapGetGinaIdentity::returning %ld" ), dwRet ) );

	return dwRet;
}
#endif // _WIN32_WCE

//
// Name: RasEapGetIdentity
// Description: DLL entry point for RasEapGetIdentity, is called when Windows want you to identify the user
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
APIENTRY
RasEapGetIdentity(	IN DWORD			dwEapTypeId,
					IN HWND				hwndParent,
					IN DWORD			dwFlags,
					IN const WCHAR *	pwcPhonebook,
					IN const WCHAR *	pwcEntry,
					IN BYTE *			pConnectionDataIn,
					IN DWORD			dwSizeOfConnectionDataIn,
					IN BYTE *			pUserDataIn,
					IN DWORD			dwSizeOfUserDataIn,
					OUT PBYTE *			ppUserDataOut,
					OUT DWORD *			pdwSizeOfUserDataOut,
					OUT WCHAR **		ppwcIdentity  )
{
	SW2_CONFIG_DATA		ConfigData;
	SW2_PROFILE_DATA	ProfileData;
	PSW2_USER_DATA		pUserData;
	DWORD				dwRet;

	dwRet = NO_ERROR;

	*ppwcIdentity = NULL;
	*ppUserDataOut = NULL;
	*pdwSizeOfUserDataOut = 0;

	AA_TRACE( ( TEXT( "RasEapGetIdentity::dwFlags: %x" ), dwFlags ) );

	if( pwcPhonebook )
		AA_TRACE( ( TEXT( "RasEapGetIdentity::pwcPhonebook: %ws" ), pwcPhonebook ) );

	if( pwcEntry )
		AA_TRACE( ( TEXT( "RasEapGetIdentity::pwcEntry: %ws" ), pwcEntry ) );

    if( dwFlags & RAS_EAP_FLAG_ROUTER )
    {
		AA_TRACE( ( TEXT( "RasEapGetIdentity:: RAS_EAP_FLAG_ROUTER" ) ) );

		dwRet = ERROR_NOT_SUPPORTED;
	}
    else
    {
		AA_TRACE( ( TEXT( "RasEapGetIdentity:: NOT RAS_EAP_FLAG_ROUTER" ) ) );

		if( dwFlags & RAS_EAP_FLAG_NON_INTERACTIVE )
			AA_TRACE( ( TEXT( "RasEapGetIdentity::RAS_EAP_FLAG_NON_INTERACTIVE" ) ) );
	
		if( dwFlags & RAS_EAP_FLAG_LOGON )
			AA_TRACE( ( TEXT( "RasEapGetIdentity::RAS_EAP_FLAG_LOGON" ) ) );

		if( dwFlags & RAS_EAP_FLAG_PREVIEW )
			AA_TRACE( ( TEXT( "RasEapGetIdentity::RAS_EAP_FLAG_PREVIEW" ) ) );

		if( dwFlags & RAS_EAP_FLAG_FIRST_LINK )
			AA_TRACE( ( TEXT( "RasEapGetIdentity::RAS_EAP_FLAG_FIRST_LINK" ) ) );

		if( dwFlags & RAS_EAP_FLAG_MACHINE_AUTH )
			AA_TRACE( ( TEXT( "RasEapGetIdentity::RAS_EAP_FLAG_MACHINE_AUTH" ) ) );

		if( dwFlags & RAS_EAP_FLAG_GUEST_ACCESS )
			AA_TRACE( ( TEXT( "RasEapGetIdentity::RAS_EAP_FLAG_GUEST_ACCESS" ) ) );

		if( dwFlags & RAS_EAP_FLAG_8021X_AUTH )
			AA_TRACE( ( TEXT( "RasEapGetIdentity::RAS_EAP_FLAG_8021X_AUTH" ) ) );

#ifndef _WIN32_WCE
		if( dwFlags & RAS_EAP_FLAG_HOSTED_IN_PEAP )
			AA_TRACE( ( TEXT( "RasEapGetIdentity::RAS_EAP_FLAG_HOSTED_IN_PEAP" ) ) );
#endif // _WIN32_WCE

		memset( &ConfigData, 0, sizeof( PSW2_CONFIG_DATA ) );

		if( pConnectionDataIn && ( dwSizeOfConnectionDataIn == sizeof( SW2_CONFIG_DATA ) ) )
		{
			memcpy( &ConfigData, pConnectionDataIn, sizeof( SW2_CONFIG_DATA ) );
		}
		else
			wcscpy( ConfigData.pwcProfileId, L"DEFAULT" );

		if( ( dwRet = AA_ReadProfile( ConfigData.pwcProfileId,
										NULL,
										&ProfileData ) ) == NO_ERROR )
		{
			if( wcscmp( ProfileData.pwcInnerAuth, L"PAP" ) == 0 )
			{
				dwRet = RasEapGetPAPIdentity(	&ProfileData, 
												ProfileData.dwCurrentInnerEapMethod,
												hwndParent,
												dwFlags,
												pwcPhonebook,
												pwcEntry,
												pConnectionDataIn,
												dwSizeOfConnectionDataIn,
												pUserDataIn,
												dwSizeOfUserDataIn,
												ppUserDataOut,
												pdwSizeOfUserDataOut,
												ppwcIdentity );
			}
			else if(  wcscmp( ProfileData.pwcInnerAuth, L"EAP" ) == 0 )
			{
				dwRet = RasEapGetEAPIdentity(	&ProfileData, 
												ProfileData.dwCurrentInnerEapMethod,
												hwndParent,
												dwFlags,
												pwcPhonebook,
												pwcEntry,
												pConnectionDataIn,
												dwSizeOfConnectionDataIn,
												pUserDataIn,
												dwSizeOfUserDataIn,
												ppUserDataOut,
												pdwSizeOfUserDataOut,
												ppwcIdentity );
			}
			else
			{
				dwRet = ERROR_NOT_SUPPORTED;
			}

			if( dwRet == NO_ERROR )
			{
				//
				// Save the phone book and adapter name so we can
				// use it later to refresh the adapter ip
				//
				pUserData = ( PSW2_USER_DATA ) *ppUserDataOut;
			}
		}
    }

	AA_TRACE( ( TEXT( "RasEapGetIdentity:: Returning %d" ), dwRet ) );

	return dwRet;
}

//
// Name: RasEapBegin
// Description: DLL entry point for RasEapBegin, called at the beginning of a session
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
APIENTRY
RasEapBegin(	OUT	VOID**			ppWorkBuf,
				IN	PPP_EAP_INPUT*  pInput )
{
	PSW2_SESSION_DATA	pSessionData;
	SW2_CONFIG_DATA		ConfigData;
	PINNEREAPGETINFO	pInnerEapGetInfo;
	PPP_EAP_INFO		EapInfo;
	DWORD				dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "RasEapBegin" ) ) );

	if( pInput->fFlags & RAS_EAP_FLAG_ROUTER )
	{
		AA_TRACE( ( TEXT( "RasEapBegin::RAS_EAP_FLAG_ROUTER" ) ) );
	}
	else
	{
		if( pInput->fAuthenticator )
		{
			AA_TRACE( ( TEXT( "RasEapBegin::running on server machine" ) ) );
		}
		else
		{
			AA_TRACE( ( TEXT( "RasEapBegin::running on client machine" ) ) );

			*ppWorkBuf = NULL;

			if( ( pSessionData = ( PSW2_SESSION_DATA ) malloc( sizeof( SW2_SESSION_DATA ) ) ) )
			{
				AA_TRACE( ( TEXT( "RasEapBegin::allocated mem for session data" ) ) );

				//
				// Initialise pSessionData
				//
				memset( pSessionData, 0, sizeof( SW2_SESSION_DATA ) );

				pSessionData->AuthState = AUTH_STATE_Start;

				pSessionData->fAuthenticator = pInput->fAuthenticator;

				pSessionData->dwSeqNum = -1;

				pSessionData->hTokenImpersonateUser = pInput->hTokenImpersonateUser;

				AA_TRACE( ( TEXT( "RasEapBegin::pInput->dwSizeOfUserData: %ld" ), pInput->dwSizeOfUserData ) );

				//
				// Did we receive user and connection data
				// and is it the correct size?
				//
				if( !pInput->pUserData )
				{
					AA_TRACE( ( TEXT( "RasEapBegin::no user data" ) ) );

					//
					// If the userdata is not provided maybe we are being called by
					// someone who didn't use our RasEapGetIdenty
					// the username and password should then be in the pInput struct
					//
					if( ( pSessionData->pUserData = ( PSW2_USER_DATA ) malloc( sizeof( SW2_USER_DATA ) ) ) )
					{
						memset( pSessionData->pUserData, 0, sizeof( SW2_USER_DATA ) );

						pSessionData->pUserData->PrevAuthResult = PREV_AUTH_RESULT_pending;

						if( pInput->pwszIdentity && pInput->pwszPassword )
						{
							//
							// Copy identity
							//
							if( ( wcslen( pInput->pwszIdentity ) + ( 1 * sizeof( WCHAR ) ) ) < UNLEN )
							{
								wcscpy( pSessionData->pUserData->pwcUsername, pInput->pwszIdentity );

								//
								// Copy password
								//
								if( ( wcslen( pInput->pwszPassword ) + ( 1 * sizeof( WCHAR ) ) ) < PWLEN )
									wcscpy( pSessionData->pUserData->pwcPassword, pInput->pwszPassword );
								else
									dwRet = NO_ERROR;
							}
							else
							{
								dwRet = ERROR_NOT_ENOUGH_MEMORY;
							}
						}
						else
							dwRet = ERROR_NO_SUCH_USER;

						if( dwRet != NO_ERROR )
							free( pSessionData->pUserData );
					}
					else
					{
						AA_TRACE( ( TEXT( "RasEapBegin::ERROR::could not allocate memory for pSessionData->pConfig" ) ) );

						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
				}
				else
				{
					AA_TRACE( ( TEXT( "RasEapBegin::using user data provided by own DLL" ) ) );

					if( ( pInput->dwSizeOfUserData == sizeof( SW2_USER_DATA ) ) )
					{
						//
						// Save user and connection stuff
						//
						if( ( pSessionData->pUserData = ( PSW2_USER_DATA ) malloc( sizeof( SW2_USER_DATA ) ) ) )
						{
							memset( pSessionData->pUserData, 0, sizeof( SW2_USER_DATA ) );

							memcpy( pSessionData->pUserData, pInput->pUserData, pInput->dwSizeOfUserData );
						}
						else
						{
							AA_TRACE( ( TEXT( "RasEapBegin::ERROR::could not allocate memory for pSessionData->pConfig" ) ) );
	
							dwRet = ERROR_NOT_ENOUGH_MEMORY;
						}
					}
					else
						dwRet = ERROR_NO_SUCH_USER;
				}

				if( dwRet == NO_ERROR )
				{
					memset( &ConfigData, 0, sizeof( SW2_CONFIG_DATA ) );

					//
					// Did windows supplies us with a config?
					//
					if( pInput->pConnectionData && 
						( pInput->dwSizeOfConnectionData == sizeof( SW2_CONFIG_DATA ) ) )
					{
						AA_TRACE( ( TEXT( "RasEapBegin::user and connection data available" ) ) );

						memcpy( &ConfigData, pInput->pConnectionData, sizeof( SW2_CONFIG_DATA ) );
					}
					else
						wcscpy( ConfigData.pwcProfileId, L"DEFAULT" );

					//
					// Copy over the current profile id
					//
					memcpy( pSessionData->pwcCurrentProfileId, 
							ConfigData.pwcProfileId, 
							sizeof( pSessionData->pwcCurrentProfileId ) );

					//
					// Allocate a profile
					//
					if( ( pSessionData->pProfileData = 
											( PSW2_PROFILE_DATA ) malloc( sizeof( SW2_PROFILE_DATA ) ) ) )
					{
						//
						// Read in Profile
						//
						if( ( dwRet = AA_ReadProfile( ConfigData.pwcProfileId,
														pSessionData->hTokenImpersonateUser,
														pSessionData->pProfileData ) ) == NO_ERROR )
						{
							//
							// Enable session resumption? (Only if previous authentication was success)
							//
							AA_TRACE( ( TEXT( "RasEapBegin::previous authentication result: %ld" ), pSessionData->pUserData->PrevAuthResult ) );

							if( !pSessionData->pProfileData->bUseSessionResumption || 
								pSessionData->pUserData->PrevAuthResult != PREV_AUTH_RESULT_success )
							{
								AA_TRACE( ( TEXT( "RasEapBegin::not resuming session" ) ) );

								memset( pSessionData->pUserData->pbTLSSessionID, 0, sizeof( pSessionData->pUserData->pbTLSSessionID ) );

								pSessionData->pUserData->cbTLSSessionID = 0;
							}
							else
								AA_TRACE( ( TEXT( "RasEapBegin::resuming session" ) ) );

							AA_TRACE( ( TEXT( "RasEapBegin::checking version" ) ) );

							//
							// If set retrieve the pre-configured password
							//
							if( !( pInput->fFlags & RAS_EAP_FLAG_MACHINE_AUTH ) )
							{
								if( !pSessionData->pProfileData->bPromptUser )
								{
									AA_TRACE( ( TEXT( "RasEapBegin::copying password(%ld): %s" ), wcslen( pSessionData->pProfileData->pwcUserPassword ), pSessionData->pProfileData->pwcUserPassword ) );

									//
									// Copy pre-configured user password
									//
									if( wcslen( pSessionData->pProfileData->pwcUserPassword ) > 0 )
										wcscpy( pSessionData->pUserData->pwcPassword, 
												pSessionData->pProfileData->pwcUserPassword );
									else
										dwRet = ERROR_NO_SUCH_USER;
								}
							}

							AA_TRACE( ( TEXT( "RasEapBegin::password: %s" ), pSessionData->pUserData->pwcPassword ) );

							if( dwRet == NO_ERROR )
							{
								//
								// If we are using EAP then load in the current EAP config
								//
								if( wcscmp( pSessionData->pProfileData->pwcInnerAuth, L"EAP" ) == 0 )
								{
									//
									// Read in config data for current EAP method 
									//
									if( ( pSessionData->InnerSessionData.pInnerEapConfigData = 
										( PSW2_INNER_EAP_CONFIG_DATA ) malloc( sizeof( SW2_INNER_EAP_CONFIG_DATA ) ) ) )
									{
										if( ( dwRet = AA_ReadInnerEapMethod( 
													pSessionData->pProfileData->dwCurrentInnerEapMethod,
													pSessionData->pwcCurrentProfileId,
													pSessionData->InnerSessionData.pInnerEapConfigData ) ) == NO_ERROR )
										{
											AA_TRACE( ( TEXT( "RasEapBegin::connecting to method %ld" ), pSessionData->pProfileData->dwCurrentInnerEapMethod ) );

											//
											// Connect to EAP DLL
											//
											if( ( pSessionData->InnerSessionData.hInnerEapInstance = 
												LoadLibrary( pSessionData->InnerSessionData.pInnerEapConfigData->pwcEapPath ) ) )
											{
#ifndef _WIN32_WCE
												if( ( pInnerEapGetInfo = ( PINNEREAPGETINFO ) 
													GetProcAddress( pSessionData->InnerSessionData.hInnerEapInstance, "RasEapGetInfo" ) ) )
#else
												if( ( pInnerEapGetInfo = ( PINNEREAPGETINFO ) 
													GetProcAddress( pSessionData->InnerSessionData.hInnerEapInstance, L"RasEapGetInfo" ) ) )
#endif
												{
													EapInfo.dwSizeInBytes = sizeof( EapInfo );

													if( ( dwRet = pInnerEapGetInfo( 
														pSessionData->InnerSessionData.pInnerEapConfigData->dwEapType, 
														&EapInfo ) ) == NO_ERROR )
													{
														AA_TRACE( ( TEXT( "RasEapBegin::got EapInfo" ) ) );

														pSessionData->InnerSessionData.pInnerEapInitialize = EapInfo.RasEapInitialize;
														pSessionData->InnerSessionData.pInnerEapBegin = EapInfo.RasEapBegin;
														pSessionData->InnerSessionData.pInnerEapEnd = EapInfo.RasEapEnd;
														pSessionData->InnerSessionData.pInnerEapMakeMessage = EapInfo.RasEapMakeMessage;

														if( pSessionData->InnerSessionData.pInnerEapInitialize )
														{
															if( ( dwRet = pSessionData->InnerSessionData.pInnerEapInitialize( TRUE ) ) == NO_ERROR )
															{
																AA_TRACE( ( TEXT( "RasEapBegin::called Inner EAP function RasEapInitialize" ) ) );
															}
															else
															{
																AA_TRACE( ( TEXT( "RasEapBegin::Inner EAP function RasEapInitialize FAILED: %ld" ), dwRet ) );
															}
														}

														if( dwRet == NO_ERROR )
														{
															memset( &( pSessionData->InnerSessionData.InnerEapInput ), 0, sizeof( pSessionData->InnerSessionData.InnerEapInput ) );

															pSessionData->InnerSessionData.InnerEapInput.dwSizeInBytes = sizeof( pSessionData->InnerSessionData.InnerEapInput );

															pSessionData->InnerSessionData.InnerEapInput.bInitialId = 0;

															pSessionData->InnerSessionData.InnerEapInput.dwAuthResultCode = 0;

															pSessionData->InnerSessionData.InnerEapInput.pConnectionData = pSessionData->InnerSessionData.pInnerEapConfigData->pbConnectionData;
															pSessionData->InnerSessionData.InnerEapInput.dwSizeOfConnectionData = pSessionData->InnerSessionData.pInnerEapConfigData->cbConnectionData;

															pSessionData->InnerSessionData.InnerEapInput.dwSizeOfDataFromInteractiveUI = 0;
															pSessionData->InnerSessionData.InnerEapInput.pDataFromInteractiveUI = NULL;

															pSessionData->InnerSessionData.InnerEapInput.dwSizeOfUserData = pSessionData->pUserData->InnerEapUserData.cbUserData;

															pSessionData->InnerSessionData.InnerEapInput.pUserData = pSessionData->pUserData->InnerEapUserData.pbUserData;

															pSessionData->InnerSessionData.InnerEapInput.fAuthenticationComplete = FALSE;

															pSessionData->InnerSessionData.InnerEapInput.fAuthenticator = FALSE;

															pSessionData->InnerSessionData.InnerEapInput.fDataReceivedFromInteractiveUI = FALSE;

															pSessionData->InnerSessionData.InnerEapInput.fFlags = pInput->fFlags;

															pSessionData->InnerSessionData.InnerEapInput.fSuccessPacketReceived = FALSE;

															pSessionData->InnerSessionData.InnerEapInput.hReserved = 0;

															pSessionData->InnerSessionData.InnerEapInput.hTokenImpersonateUser = pInput->hTokenImpersonateUser;
															
															pSessionData->InnerSessionData.InnerEapInput.pUserAttributes = pInput->pUserAttributes;
															
															pSessionData->InnerSessionData.InnerEapInput.pwszIdentity = pSessionData->pUserData->InnerEapUserData.pwcIdentity;

															AA_TRACE( ( TEXT( "RasEapBegin::Identity: %s" ), pSessionData->InnerSessionData.InnerEapInput.pwszIdentity ) );

															//
															// If required set password
															//
															if( ( pSessionData->InnerSessionData.pInnerEapConfigData->dwInvokePasswordDlg == 1 ) )
															{
																AA_TRACE( ( TEXT( "RasEapBegin::setting password: %s" ), pSessionData->pUserData->pwcPassword ) );

																pSessionData->InnerSessionData.InnerEapInput.pwszPassword = pSessionData->pUserData->pwcPassword;

																pSessionData->InnerSessionData.InnerEapInput.fFlags = pSessionData->InnerSessionData.InnerEapInput.fFlags | RAS_EAP_FLAG_LOGON;
															}
															else
																pSessionData->InnerSessionData.InnerEapInput.pwszPassword = NULL;

															if( ( dwRet = pSessionData->InnerSessionData.pInnerEapBegin( &( pSessionData->InnerSessionData.pbInnerEapSessionData ), &( pSessionData->InnerSessionData.InnerEapInput ) ) ) == NO_ERROR )
															{
																AA_TRACE( ( TEXT( "RasEapBegin::Inner EAP function RasEapBegin successfull" ) ) );

																pSessionData->InnerSessionData.InnerAuthState = INNER_AUTH_STATE_Start;
															}
															else
																AA_TRACE( ( TEXT( "RasEapBegin::Inner EAP function RasEapBegin failed: %ld" ), dwRet ) );
														}
													}
												}
												else
												{
													dwRet = ERROR_DLL_INIT_FAILED;
												}

												if( dwRet != NO_ERROR )
													FreeLibrary( pSessionData->InnerSessionData.hInnerEapInstance  );
											}
											else
											{
												dwRet = ERROR_DLL_INIT_FAILED;
											}
										}

										if( dwRet != NO_ERROR )
											free( pSessionData->InnerSessionData.pInnerEapConfigData );
									}
									else
										dwRet = ERROR_NOT_ENOUGH_MEMORY;
								}
							}
						}

						if( dwRet != NO_ERROR )
						{
#ifndef _WIN32_WCE
							//
							// If using a SecureW2 Gina, write result back
							//
							if( pSessionData->pProfileData->GinaConfigData.bUseSW2Gina )
							{
								AA_WriteResult( dwRet );
							}
#endif // _WIN32_WCE
							free( pSessionData->pProfileData );
						}
					}
					else
						dwRet = ERROR_NOT_ENOUGH_MEMORY;

					if( dwRet != NO_ERROR )
						free( pSessionData->pUserData );
				}

				if( dwRet == NO_ERROR )
				{
					*ppWorkBuf = pSessionData;
				}
			}
			else
			{
				AA_TRACE( ( TEXT( "RasEapBegin::Not enough memory for pSessionData" ) ) );

		        dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
	}

	AA_TRACE( ( TEXT( "RasEapBegin::returning %d" ), dwRet ) );

	//
	// Report error to event viewer
	//	
	if( dwRet != NO_ERROR )
		AA_ReportEvent( L"RasEapBegin Failed", EVENTLOG_ERROR_TYPE, dwRet );

    return dwRet;
}

//
// Name: RasEapEnd
// Description: DLL entry point for RasEapEnd, is called at the end of a EAP session
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
APIENTRY
RasEapEnd( IN VOID* pWorkBuf )
{
	PSW2_SESSION_DATA	pSessionData;
	int					i;
#ifndef _WIN32_WCE
	HANDLE				hThread;
	DWORD				dwThreadID;
#endif // _WIN32_WCE
	DWORD				dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "RasEapEnd" ) ) );
	
	if( pWorkBuf )
		 pSessionData = ( PSW2_SESSION_DATA ) pWorkBuf;
	else
	{
		AA_TRACE( ( TEXT( "RasEapEnd::Windows gave me a NULL pointer, idiots!" ) ) );

		return dwRet;
	}

/*
 *	For some reason this prevents the MPPE keys from being read correctly under Windows 2000
	AA_TRACE( ( TEXT( "RasEapEnd::Killing remaining windows" ) ) );
	//
	// Kill remaining windows
	//
	AA_KillWindow( pSessionData->hTokenImpersonateUser, WC_DIALOG, L"SecureW2 Credentials" );
	AA_KillWindow( pSessionData->hTokenImpersonateUser, WC_DIALOG, L"SecureW2 Unknown Server" );
*/

	AA_TRACE( ( TEXT( "RasEapEnd::Cleaning up Crypto" ) ) );


	//
	// Cleanup Crypto
	//
	if( pSessionData->hReadKey )
		CryptDestroyKey( pSessionData->hReadKey );

	if( pSessionData->hWriteKey )
		CryptDestroyKey( pSessionData->hWriteKey );

	if( pSessionData->hCSP )
		CryptReleaseContext( pSessionData->hCSP, 0 );

	if( wcscmp( pSessionData->pProfileData->pwcInnerAuth, L"EAP" ) == 0 )
	{
		AA_TRACE( ( TEXT( "RasEapEnd::Cleaning up Inner EAP" ) ) );


		if( ( dwRet = pSessionData->InnerSessionData.pInnerEapEnd( pSessionData->InnerSessionData.pbInnerEapSessionData ) ) == NO_ERROR )
		{
			if( pSessionData->InnerSessionData.pInnerEapInitialize )
				pSessionData->InnerSessionData.pInnerEapInitialize( FALSE );

			FreeLibrary( pSessionData->InnerSessionData.hInnerEapInstance );
		}
		else
		{
			AA_TRACE( ( TEXT( "RasEapEnd::Inner EAP function RasEapEnd FAILED: %ld" ), dwRet ) );
		}

		if( pSessionData->InnerSessionData.pInnerEapConfigData )
			free( pSessionData->InnerSessionData.pInnerEapConfigData );
	}

#ifndef _WIN32_WCE

	//
	// DHCP Fix
	//
	if( pSessionData->pProfileData->bRenewIP &&
		pSessionData->pUserData->PrevAuthResult == PREV_AUTH_RESULT_success )
	{
		AA_TRACE( ( TEXT( "RasEapEnd::DHCP Fix: %s" ) , pSessionData->pUserData->pwcEntry ) );

		dwThreadID = 0;

		if( hThread = CreateThread( NULL,
									0,
									AA_RenewIP,
									pSessionData->pUserData->pwcEntry,
									0,
									&dwThreadID ) )
		{
			//
			// Allow thread to copy entry name
			//
			Sleep( 500 );

			CloseHandle( hThread );
		}
	}

#endif // _WIN32_WCE

	AA_TRACE( ( TEXT( "RasEapEnd::Cleaning up UserAttributes" ) ) );

	//
	// free UserAttributes
	//
	if( pSessionData->pUserAttributes )
	{
		if( pSessionData->pUserAttributes[0].Value )
			free( pSessionData->pUserAttributes[0].Value );

		if( pSessionData->pUserAttributes[1].Value )
			free( pSessionData->pUserAttributes[1].Value );

		free( pSessionData->pUserAttributes );
	}

	//
	// If using the SecureW2 Gina write result
	//
#ifndef _WIN32_WCE
	if( pSessionData->pProfileData->GinaConfigData.bUseSW2Gina )
	{
		if( pSessionData->pUserData->PrevAuthResult == PREV_AUTH_RESULT_success )
			AA_WriteResult( dwRet );
	}
#endif // _WIN32_WCE

	AA_TRACE( ( TEXT( "RasEapEnd::freeing user and config data" ) ) );

	//
	// Free user and config data
	//
	if( pSessionData->pUserData )
		free( pSessionData->pUserData );

	if( pSessionData->pProfileData )
		free( pSessionData->pProfileData );

	AA_TRACE( ( TEXT( "RasEapEnd::freeing user handshake messages" ) ) );

	//
	// Cleanup handshake msgs
	//
	for( i=0; ( DWORD ) i < pSessionData->dwHandshakeMsgCount; i++ )
		free( pSessionData->pbHandshakeMsg[i] );

	free( pSessionData );

	AA_TRACE( ( TEXT( "RasEapEnd::returning" ) ) );

    return dwRet;
}

//
// Name: RasEapFreeMemory
// Description: DLL entry point for RasEapFreeMemory, is called when Windows want to cleanup memory
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
APIENTRY
RasEapFreeMemory( IN BYTE* pbMemory )
{
	AA_TRACE( ( TEXT( "RasEapFreeMemory" ) ) );

	if( pbMemory )
		free( pbMemory );

	AA_TRACE( ( TEXT( "RasEapFreeMemory:: Returning" ) ) );

    return NO_ERROR;
}

//
// Name: RasEapInvokeConfigUI
// Description: DLL entry point for RasEapInvokeConfigUI, will show config dialog
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
APIENTRY
RasEapInvokeConfigUI(	IN  DWORD       dwEapTypeId,
						IN  HWND        hWndParent,
						IN  DWORD       dwFlags,
						IN  BYTE*       pConnectionDataIn,
						IN  DWORD       dwSizeOfConnectionDataIn,
						OUT BYTE**      ppConnectionDataOut,
						OUT DWORD*      pdwSizeOfConnectionDataOut )
{
	PSW2_CONFIG_DATA	pConfigData;
	DWORD				dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "RasEapInvokeConfigUI::EAP::%ld" ), dwEapTypeId ) );

    if( dwEapTypeId != EAP_PROTOCOL_ID )
    {
		AA_TRACE( ( TEXT( "RasEapInvokeConfigUI::Incorrect EAP_TYPE: %ld" ), dwEapTypeId ) );

		//
		// Report error to event viewer
		//	
		AA_ReportEvent( L"RasEapInvokeConfigUI Failed", EVENTLOG_ERROR_TYPE, ERROR_NOT_SUPPORTED );

		return ERROR_NOT_SUPPORTED;
    }

	*ppConnectionDataOut = NULL;
	*pdwSizeOfConnectionDataOut = 0;

	if( ( pConfigData = ( PSW2_CONFIG_DATA ) malloc( sizeof( SW2_CONFIG_DATA ) ) ) )
	{
		memset( pConfigData, 0, sizeof( SW2_CONFIG_DATA ) );

		if( pConnectionDataIn && ( sizeof( SW2_CONFIG_DATA ) == dwSizeOfConnectionDataIn ) )
		{
			AA_TRACE( ( TEXT( "RasEapInvokeConfigUI:: received pConnectionDataIn from Windows" ) ) );

			memcpy( pConfigData, pConnectionDataIn, dwSizeOfConnectionDataIn );
		}
		else
			dwRet = ERROR_NOT_ENOUGH_MEMORY;

		if( dwRet != NO_ERROR )
		{
			dwRet = NO_ERROR;
		
			AA_TRACE( ( TEXT( "RasEapInvokeConfigUI:: using default config" ) ) );

			swprintf( pConfigData->pwcProfileId, L"DEFAULT" );
		}

		if( dwRet == NO_ERROR )
		{
			AA_TRACE( ( TEXT( "RasEapInvokeConfigUI:: pConfigData->pwcProfileId: %s" ), pConfigData->pwcProfileId ) );

			if( DialogBoxParam( ghInstance,
							MAKEINTRESOURCE( IDD_CONFIG_DLG ),
							hWndParent,
							ConfigDlgProc,
							( LPARAM ) pConfigData ) )
			{
				*ppConnectionDataOut = ( PBYTE ) pConfigData;
				*pdwSizeOfConnectionDataOut = sizeof( SW2_CONFIG_DATA );
			}
			else
			{
				AA_TRACE( ( TEXT( "RasEapInvokeConfigUI::User cancelled" ) ) );

				dwRet = ERROR_CANCELLED;
			}
		}

		if( dwRet != NO_ERROR )
			free( pConfigData );
	}
	else
		dwRet = ERROR_NOT_ENOUGH_MEMORY;

	if( dwRet != NO_ERROR && dwRet != ERROR_CANCELLED )
		AA_ReportEvent( L"RasEapInvokeConfigUI Failed", EVENTLOG_ERROR_TYPE, dwRet );

	AA_TRACE( ( TEXT( "RasEapInvokeConfigUI::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: RasEapInvokeInteractiveUI
// Description: DLL entry point for RasEapInvokeInteractiveUI, not sure
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
APIENTRY
RasEapInvokeInteractiveUI(	IN DWORD	dwEapTypeId,
							IN  HWND	hWndParent,
							IN  PBYTE	pUIContextData,
							IN  DWORD	dwSizeofUIContextData,
							OUT PBYTE*	ppDataFromInteractiveUI,
							OUT DWORD*	lpdwSizeOfDataFromInteractiveUI )
{
	PSW2_SESSION_DATA 				pSessionData;
	SW2_INNER_EAP_CONFIG_DATA		InnerEapConfigData;
	SW2_PROFILE_DATA				ProfileData;
	PINNEREAPINVOKEINTERACTIVEUI	pInnerEapInvokeInteractiveUI;
	PINNEREAPFREEMEMORY				pInnerEapFreeMemory;
	PBYTE							pbInnerEapDataFromInteractiveUI;
	DWORD							dwInnerEapSizeOfDataFromInteractiveUI;
	HINSTANCE						hEapInstance;
	WCHAR							*pwcReturn;
	WCHAR							pwcTemp[1024];
	PBYTE							pbReturn;
	DWORD							dwRet;

	AA_TRACE( ( TEXT( "RasEapInvokeInteractiveUI: %x" ), ghInstance ) );

    if( dwEapTypeId != EAP_PROTOCOL_ID )
    {
		AA_TRACE( ( TEXT( "RasEapInvokeInteractiveUI::Incorrect EAP_TYPE: %ld" ), dwEapTypeId ) );

		//
		// Report error to event viewer
		//	
		AA_ReportEvent( L"RasEapInvokeInteractiveUI Failed", EVENTLOG_ERROR_TYPE, ERROR_NOT_SUPPORTED );

		return ERROR_NOT_SUPPORTED;
    }

	dwRet = NO_ERROR;

	*ppDataFromInteractiveUI = NULL;
	*lpdwSizeOfDataFromInteractiveUI = 0;

	if( !pUIContextData )
	{
		AA_TRACE( ( TEXT( "RasEapInvokeInteractiveUI::Invalid pointer to Context Data" ) ) );
		//
		// Report error to event viewer
		//
		AA_ReportEvent( L"RasEapInvokeInteractiveUI Failed", EVENTLOG_ERROR_TYPE, ERROR_CANCELLED );

		return ERROR_CANCELLED;
	}
	else
		AA_TRACE( ( TEXT( "RasEapInvokeInteractiveUI::dwSizeofUIContextData: %ld" ), dwSizeofUIContextData ) );

	pSessionData = ( PSW2_SESSION_DATA ) pUIContextData;

	if( pSessionData->bInteractiveUIType == UI_TYPE_VERIFY_CERT )
	{
		memset( &ProfileData, 0, sizeof( ProfileData ) );

		pSessionData->pProfileData = &ProfileData;

		if( ( dwRet = AA_ReadProfile( pSessionData->pwcCurrentProfileId,
										NULL,
										pSessionData->pProfileData ) ) == NO_ERROR )
		{
			//
			// Show server trust dialog
			//
			if( DialogBoxParam( ghInstance,
								MAKEINTRESOURCE( IDD_SERVER_TRUST_DLG ),
								hWndParent,
								TLSServerTrustDlgProc,
								( LPARAM ) pSessionData ) )
			{
				AA_TRACE( ( TEXT( "RasEapInvokeInteractiveUI(), user pressed ok" ) ) );

				//
				// User managed to install certificates
				//
				if( ( pwcReturn = ( WCHAR* ) malloc( ( wcslen( L"ERROR_OK" ) + 1 ) * sizeof( WCHAR ) ) ) )
				{
					wcscpy( pwcReturn, L"ERROR_OK" );

					AA_TRACE( ( TEXT( "RasEapInvokeInteractiveUI(), returning %ws" ), pwcReturn ) );

					*ppDataFromInteractiveUI = ( PBYTE ) pwcReturn;
														
					*lpdwSizeOfDataFromInteractiveUI = ( DWORD ) ( wcslen( pwcReturn ) + 1 ) * sizeof( WCHAR );
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
			else
			{
				//
				// User cancelled
				//
				if( ( pwcReturn = ( WCHAR* ) malloc( ( wcslen( L"ERROR_CANCELLED" ) + 1 ) * sizeof( WCHAR ) ) ) )
				{
					wcscpy( pwcReturn, L"ERROR_CANCELLED" );

					AA_TRACE( ( TEXT( "RasEapInvokeInteractiveUI(), returning %ws" ), pwcReturn ) );

					*ppDataFromInteractiveUI = ( PBYTE ) pwcReturn;
														
					*lpdwSizeOfDataFromInteractiveUI = ( DWORD ) ( wcslen( pwcReturn ) + 1 ) * sizeof( WCHAR );
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
		}
	}
	else if( pSessionData->bInteractiveUIType == UI_TYPE_INNER_EAP )
	{
		AA_TRACE( ( TEXT( "RasEapInvokeInteractiveUI(), UI_TYPE_INNER_EAP" ) ) );

		if( ( dwRet = AA_ReadProfile( pSessionData->pwcCurrentProfileId,
										NULL,
										&ProfileData ) ) == NO_ERROR )
		{
			if( ( dwRet = AA_ReadInnerEapMethod( ProfileData.dwCurrentInnerEapMethod, 
												ProfileData.pwcCurrentProfileId,
												&InnerEapConfigData ) ) == NO_ERROR )
			{
				//
				// Connect to EAP DLL
				//
				if( ( hEapInstance = LoadLibrary( InnerEapConfigData.pwcEapInteractiveUIPath ) ) )
				{
#ifndef _WIN32_WCE
					if( ( pInnerEapInvokeInteractiveUI = ( PINNEREAPINVOKEINTERACTIVEUI ) 
						GetProcAddress( hEapInstance, "RasEapInvokeInteractiveUI" ) ) )
#else
					if( ( pInnerEapInvokeInteractiveUI = ( PINNEREAPINVOKEINTERACTIVEUI ) 
						GetProcAddress( hEapInstance, L"RasEapInvokeInteractiveUI" ) ) )
#endif // _WIN32_WCE
					{
						AA_TRACE( ( TEXT( "RasEapInvokeInteractiveUI(), UI_TYPE_INNER_EAP:: calling pInnerEapInvokeInteractiveUI" ) ) );

						if(	( dwRet = pInnerEapInvokeInteractiveUI( InnerEapConfigData.dwEapType,
																	hWndParent,
																	pSessionData->pbInnerUIContextData,
																	pSessionData->dwInnerSizeOfUIContextData,
																	&pbInnerEapDataFromInteractiveUI,
																	&dwInnerEapSizeOfDataFromInteractiveUI ) ) == NO_ERROR )
						{
							AA_TRACE( ( TEXT( "RasEapInvokeInteractiveUI(), UI_TYPE_INNER_EAP:: dwInnerEapSizeOfDataFromInteractiveUI: %ld" ), dwInnerEapSizeOfDataFromInteractiveUI ) );

#ifndef _WIN32_WCE
							if( ( pInnerEapFreeMemory = ( PINNEREAPFREEMEMORY ) 
								GetProcAddress( hEapInstance, "RasEapFreeMemory" ) ) )
#else
							if( ( pInnerEapFreeMemory = ( PINNEREAPFREEMEMORY ) 
								GetProcAddress( hEapInstance, L"RasEapFreeMemory" ) ) )
#endif // _WIN32_WCE
							{
								if( ( pbReturn = ( PBYTE ) malloc( dwInnerEapSizeOfDataFromInteractiveUI ) ) )
								{
									memcpy( pbReturn, 
											pbInnerEapDataFromInteractiveUI, 
											dwInnerEapSizeOfDataFromInteractiveUI );

									*ppDataFromInteractiveUI = pbReturn;
															
									*lpdwSizeOfDataFromInteractiveUI = dwInnerEapSizeOfDataFromInteractiveUI;

									pInnerEapFreeMemory( ( PBYTE ) pbInnerEapDataFromInteractiveUI );
								}
								else
								{
									dwRet = ERROR_NOT_ENOUGH_MEMORY;
								}
							}
							else
							{
								dwRet = ERROR_DLL_INIT_FAILED;
							}
						}
						else
						{
							AA_TRACE( ( TEXT( "RasEapInvokeInteractiveUI::pInnerInvokeInteractiveUI FAILED: %d" ), dwRet ) );
						}
					}
					else
					{

						AA_TRACE( ( TEXT( "RasEapInvokeInteractiveUI:: GetProcAddress FAILED" ) ) );

						dwRet = ERROR_DLL_INIT_FAILED;
					}

					FreeLibrary( hEapInstance );
				}
				else
				{
					AA_TRACE( ( TEXT( "RasEapInvokeInteractiveUI:: LoadLibrary FAILED" ) ) );

					dwRet = ERROR_DLL_INIT_FAILED;
				}
			}
		}
	}
	else if( pSessionData->bInteractiveUIType == UI_TYPE_ERROR )
	{
		memset( &ProfileData, 0, sizeof( ProfileData ) );

		pSessionData->pProfileData = &ProfileData;

		if( ( dwRet = AA_ReadProfile( pSessionData->pwcCurrentProfileId,
										NULL,
										pSessionData->pProfileData ) ) == NO_ERROR )
		{
			//
			// Show error
			//
			if (FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | 
								FORMAT_MESSAGE_IGNORE_INSERTS,
								NULL,
								GetLastError(),
								MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
								(LPTSTR) &pwcTemp,
								sizeof( pwcTemp ) * sizeof (WCHAR),
								NULL ))
			{
				MessageBox( hWndParent, 
							pwcTemp,
							L"SecureW2 Error",
							MB_ICONEXCLAMATION|MB_OK );
			}
		}
	}
	else if( pSessionData->bInteractiveUIType == UI_TYPE_CREDENTIALS )
	{
		memset( &ProfileData, 0, sizeof( ProfileData ) );

		pSessionData->pProfileData = &ProfileData;

		if( ( dwRet = AA_ReadProfile( pSessionData->pwcCurrentProfileId,
										NULL,
										pSessionData->pProfileData ) ) == NO_ERROR )
		{
			// nothing yet
		}
	}
	else
	{
		AA_TRACE( ( TEXT( "RasEapInvokeInteractiveUI(), unknown pSessionData->bInteractiveUIType %x" ), pSessionData->bInteractiveUIType ) );

		dwRet = ERROR_CANCELLED;
	}

	AA_TRACE( ( TEXT( "RasEapInvokeInteractiveUI(), returning %d" ), dwRet ) );

	//
	// Report error to event viewer
	//	
	if( dwRet != NO_ERROR )
		AA_ReportEvent( L"RasEapInvokeInteractiveUI Failed", EVENTLOG_ERROR_TYPE, dwRet );

	return dwRet;
}

//
// Name: RasEapMakeMessage
// Description: DLL entry point for RasEapMakeMessage, called when EAP messages have been received and
// must be sent
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD 
APIENTRY
RasEapMakeMessage( IN  VOID*            pWorkBuf,
				IN  PPP_EAP_PACKET*     pReceivePacket,
				OUT PPP_EAP_PACKET*     pSendPacket,
				IN  DWORD               cbSendPacket,
				OUT PPP_EAP_OUTPUT*     pEapOutput,
				IN  PPP_EAP_INPUT*      pEapInput )
{
	PSW2_SESSION_DATA	pSessionData;
	DWORD				dwEAPPacketLength;
	HCRYPTPROV			hCSP;
	WCHAR				*pwcSubjectName;
	DWORD				cwcSubjectName;
	PBYTE				pbSHA1;
	DWORD				cbSHA1;
	DWORD				dwType = 0;
	PCCERT_CONTEXT		pCertContext;
	WCHAR				*pwcTemp;
	int					i=0;
	DWORD				dwErr;
	DWORD				dwRet;

	AA_TRACE( ( TEXT( "RasEapMakeMessage: %x" ), ghInstance ) );

	dwRet = NO_ERROR;

	if( !pWorkBuf )
	{
		AA_TRACE( ( TEXT( "RasEapMakeMessage::ERROR::pWorkBuf is NULL" ) ) );

		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}
	else
	{
		pSessionData = ( PSW2_SESSION_DATA ) pWorkBuf;

		//
		// Tom Rixom, 22-07-2004
		// Copy user token
		//
		pSessionData->hTokenImpersonateUser = pEapInput->hTokenImpersonateUser;

		//
		// Copy the packet ID for later use
		//
		if( pReceivePacket )
		{
			AA_TRACE( ( TEXT( "RasEapMakeMessage::Received packet ID: %d" ), pReceivePacket->Id ) );
			AA_TRACE( ( TEXT( "RasEapMakeMessage::Received packet(%d): %s" ), AA_WireToHostFormat16( pReceivePacket->Length ), AA_ByteToHex( ( PBYTE ) pReceivePacket, AA_WireToHostFormat16( pReceivePacket->Length ) ) ) );

			pSendPacket->Id = pReceivePacket->Id;
			pSessionData->bPacketId = pReceivePacket->Id;
		}

		switch( pSessionData->AuthState )
		{
			case AUTH_STATE_Start:

				AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Start" ) ) );

				if( pReceivePacket )
				{
					switch( pReceivePacket->Code )
					{
						case EAPCODE_Request:

							if( pReceivePacket->Data[1] & TLS_REQUEST_START )
							{
								AA_TRACE( ( TEXT( "RasEapMakeMessage::EAPTTLS_REQUEST_START") ) );

								dwRet = TLSBuildResponsePacket( pSessionData, pSendPacket, cbSendPacket, pEapInput, pEapOutput );
							}
							else
							{
								AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Start::WARNING:Expected TLS Start") ) );

								dwRet = ERROR_PPP_INVALID_PACKET;
							}

						break;

						case EAPCODE_Response:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Client_Hello::Response Packet->" ) ) );

							dwRet = ERROR_PPP_INVALID_PACKET;

						break;

						case EAPCODE_Success:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Start::Success Packet->" ) ) );

							dwRet = ERROR_PPP_INVALID_PACKET;

						break;

						case EAPCODE_Failure:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Start::Failure Packet->" ) ) );

							dwRet = ERROR_AUTH_INTERNAL;

						break;

						default:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Start::WARNING:unexpected packet") ) );

							dwRet = ERROR_PPP_INVALID_PACKET;

						break;
					}
				}
				else
				{
					AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Start::WARNING: pReceivePacket == NULL" ) ) );
				}

			break;

			case AUTH_STATE_Server_Hello:

				AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Server_Hello" ) ) );

				if( pReceivePacket )
				{
					switch( pReceivePacket->Code )
					{
						case EAPCODE_Request:

							dwEAPPacketLength = AA_WireToHostFormat16(  &( pReceivePacket->Length[0] ) );

							//
							// This function will read all the information in the fragged messages
							//
							dwRet = TLSReadMessage( pSessionData->pbReceiveMsg,
													&( pSessionData->cbReceiveMsg ),
													&( pSessionData->dwReceiveCursor ),
													pSessionData->bPacketId,
													pReceivePacket, 
													pSendPacket, 
													cbSendPacket, 
													pEapInput, 
													pEapOutput, 
													dwEAPPacketLength );
						
							if( ( pEapOutput->Action != EAPACTION_Send ) && dwRet == NO_ERROR )
							{
								AA_TRACE( ( TEXT( "RasEapMakeMessage::TLS_STATE_Client_Hello::total message(%d): %s" ), pSessionData->cbReceiveMsg, AA_ByteToHex( pSessionData->pbReceiveMsg, pSessionData->cbReceiveMsg ) ) );

								if( ( dwRet = TLSParseServerPacket( pSessionData, pSessionData->pbReceiveMsg, pSessionData->cbReceiveMsg ) ) == NO_ERROR )
								{
									pEapOutput->fInvokeInteractiveUI = FALSE;

									if( pSessionData->bServerFinished && 
										pSessionData->bCipherSpec && 
										pSessionData->pProfileData->bUseSessionResumption )
									{
										//
										// Found a change cipher spec and a finished message which means we are allowed to resume a session
										// if we want to resume as well then everything is ok else fail...
										//
										//
										// Set appropiate state
										//
										pSessionData->AuthState = AUTH_STATE_Resume_Session;

										dwRet = TLSBuildResponsePacket( pSessionData, 
																		pSendPacket, 
																		cbSendPacket, 
																		pEapInput, 
																		pEapOutput );
									}
									else
									{
										//
										// Continue with TLS handshake
										//
										//
										// Check if we have a certificate
										//
										if( pSessionData->pbCertificate[0] )
										{
											//
											// Should we verify the TTLS server certificate?
											//
											if( pSessionData->pProfileData->bVerifyServer )
											{
												AA_TRACE( ( TEXT( "RasEapMakeMessage::TLS_STATE_Client_Hello::Verifying certificate" ) ) );

												//
												// Connect to help CSP
												//
												if( !CryptAcquireContext( &hCSP,
																			NULL,
																			MS_DEF_PROV,
																			PROV_RSA_FULL,
																			0 ) )
												{
													dwErr = GetLastError();

													if( dwErr == NTE_BAD_KEYSET )
													{
														if( !CryptAcquireContext( &hCSP,
																				NULL,
																				MS_DEF_PROV,
																				PROV_RSA_FULL,
																				CRYPT_NEWKEYSET ) )
														{
															AA_TRACE( ( TEXT( "AA_CertAddTrustedCA::CryptAcquireContext(NEWKEYSET):: FAILED (%d)" ), GetLastError() ) );

															dwRet = ERROR_ENCRYPTION_FAILED;
														}
													}
													else
													{
														AA_TRACE( ( TEXT( "AA_CertAddTrustedCA::CryptAcquireContext(0):: FAILED (%d)" ), GetLastError() ) );

														dwRet = ERROR_ENCRYPTION_FAILED;
													}

												}

												//
												// Verify using SecureW2 CA list
												//
												if( dwRet == NO_ERROR )
												{
													if( ( pCertContext = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
																										pSessionData->pbCertificate[pSessionData->dwCertCount-1], 
																										pSessionData->cbCertificate[pSessionData->dwCertCount-1] ) ) )
													{
														if( ( dwRet = TLSGetSHA1( hCSP, 
																		pCertContext->pbCertEncoded, 
																		pCertContext->cbCertEncoded, 
																		&pbSHA1, &cbSHA1 ) ) == NO_ERROR )
														{
															dwRet = AA_VerifyCertificateInList( pSessionData, pbSHA1 );

															free( pbSHA1 );
														}									

														CertFreeCertificateContext( pCertContext );
													}
													else
														dwRet = ERROR_NOT_ENOUGH_MEMORY;

													CryptReleaseContext( hCSP, 0 );
												}

												//
												// Verify server certificate
												//
												if( ( pCertContext = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
																									pSessionData->pbCertificate[0], 
																									pSessionData->cbCertificate[0] ) ) )
												{
													//
													// Verify certificate chain
													//

													if( dwRet == NO_ERROR )
													{
														//
														// Tom Rixom, 20-07-2004
														//
														// If we only have 1 certificate in the chain
														// this means we have a self signed certificate
														// For SecureW2 to trust this it MUST be installed
														// in the local "MY" store
														//
														// If we have more than 1 certificate continue as usual
														//
														if( pSessionData->dwCertCount > 1 )
														{
															//
															// Verify chain
															//
															if( ( dwRet = AA_VerifyCertificateChain( pCertContext ) ) == NO_ERROR )
															{
																//
																// If required verify if certificate is installed locally
																//
																if( pSessionData->pProfileData->bServerCertificateLocal && dwRet == NO_ERROR )
																	dwRet = AA_VerifyCertificateInStore( pCertContext );
															}
														}
														else
															dwRet = AA_VerifyCertificateInStore( pCertContext );

														if( dwRet == NO_ERROR )
														{
															//
															// If required verify MS Extensions
															//
															if( pSessionData->pProfileData->bVerifyMSExtension )
																dwRet = AA_CertCheckEnhkeyUsage( pCertContext );
														}
													}

                                                    if( dwRet == NO_ERROR )
													{
														//
														// If required check server namespace
														//
														if( pSessionData->pProfileData->bVerifyServerName )
														{
															if( ( cwcSubjectName  = CertGetNameString( pCertContext,
																									CERT_NAME_SIMPLE_DISPLAY_TYPE,
																									0,
																									&dwType,
																									NULL,
																									0 ) ) > 0 )
															{
																if( ( pwcSubjectName = ( WCHAR* ) malloc( cwcSubjectName * sizeof( WCHAR ) ) ) )
																{
																	if( CertGetNameString( pCertContext,
																							CERT_NAME_SIMPLE_DISPLAY_TYPE,
																							0,
																							&dwType,
																							pwcSubjectName,
																							cwcSubjectName ) > 0 )
																	{
																		AA_TRACE( ( TEXT( "AA_VerifyServerCertificate(): %ws" ), pwcSubjectName ) );

																		if( pwcTemp = wcsstr( pwcSubjectName, pSessionData->pProfileData->pwcServerName ) )
																		{
																			//
																			// Check if the servername is found on the end of the Subjectname
																			//
																			if( ( int ) ( pwcTemp - pwcSubjectName ) != ( int ) ( ( wcslen( pwcSubjectName ) - wcslen( pSessionData->pProfileData->pwcServerName ) ) ) )
																				dwRet = ERROR_INVALID_DOMAINNAME;
																		}
																		else
																			dwRet = ERROR_INVALID_DOMAINNAME;
																	}

																	free( pwcSubjectName );
																}
																else
																	dwRet = ERROR_NOT_ENOUGH_MEMORY;
															}
															else
																dwRet = ERROR_INVALID_DOMAINNAME;
														}												
													}
													else if( pSessionData->pProfileData->bAllowNewConnection )
													{
														//
														// Could not validate chain
														//
														//
														// If we are already showing a dialog then
														// cancel this request
														if( FindWindow( WC_DIALOG, L"SecureW2 Unknown Server" ) )
														{
															AA_TRACE( ( TEXT( "RasEapMakeMessage::Unknown Server Dialog already shown" ) ) );

															dwRet = PENDING;
														}
														else
														{
															AA_TRACE( ( TEXT( "RasEapMakeMessage::setting context data" ) ) );

															pEapOutput->fInvokeInteractiveUI = TRUE;

															pSessionData->bInteractiveUIType = UI_TYPE_VERIFY_CERT;

															pSessionData->AuthState = AUTH_STATE_Verify_Cert;

															pSessionData->bVerifyMSExtension = pSessionData->pProfileData->bVerifyMSExtension;

															pSessionData->bServerCertificateLocal = pSessionData->pProfileData->bServerCertificateLocal;

															pEapOutput->pUIContextData = ( PBYTE ) pSessionData;

															pEapOutput->dwSizeOfUIContextData = sizeof( SW2_SESSION_DATA );

															pEapOutput->Action = EAPACTION_NoAction;

															dwRet = NO_ERROR;
														}									
													}

													if( pCertContext )
														CertFreeCertificateContext( pCertContext );
												}
												else
													dwRet = ERROR_NOT_ENOUGH_MEMORY;
											}

											//
											// If did not encounter an error and we do not need to show the InteractiveUI
											// then continue with next response
											//
											if( dwRet == NO_ERROR && !pEapOutput->fInvokeInteractiveUI )
												dwRet = TLSBuildResponsePacket( pSessionData, pSendPacket, cbSendPacket, pEapInput, pEapOutput );
										}
										else
										{
											//
											// Could not find a certificate, fail
											//
											dwRet = ERROR_AUTH_INTERNAL;
										}
									}
								}

								memset( pSessionData->pbReceiveMsg, 0, sizeof( pSessionData->pbReceiveMsg ) );
								pSessionData->cbReceiveMsg = 0;
								pSessionData->dwReceiveCursor = 0;
							}
							else if( dwRet != NO_ERROR )
							{
								memset( pSessionData->pbReceiveMsg, 0, sizeof( pSessionData->pbReceiveMsg ) );
								pSessionData->cbReceiveMsg = 0;
								pSessionData->dwReceiveCursor = 0;
							}


						break;

						case EAPCODE_Response:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Client_Hello::Response Packet->" ) ) );

							dwRet = ERROR_PPP_INVALID_PACKET;

						break;

						case EAPCODE_Success:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Client_Hello::Success Packet->" ) ) );

							dwRet = ERROR_PPP_INVALID_PACKET;

						break;

						case EAPCODE_Failure:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Client_Hello::Failure Packet->" ) ) );

							dwRet = ERROR_AUTH_INTERNAL;

						break;

						default:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Client_Hello::WARNING:unexpected packet") ) );

							dwRet = ERROR_PPP_INVALID_PACKET;

						break;
					}
				}
				else
				{
					AA_TRACE( ( TEXT( "RasEapMakeMessage::TLS_STATE_Client_Hello::WARNING: pReceivePacket == NULL" ) ) );
				}

			break;

			case AUTH_STATE_Resume_Session_Ack:

				AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Resume_Session_Ack" ) ) );

				if( pReceivePacket )
				{
					switch( pReceivePacket->Code )
					{
						case EAPCODE_Request:

							dwEAPPacketLength = AA_WireToHostFormat16(  &( pReceivePacket->Length[0] ) );

							//
							// Should be an TTLS-Request
							//
							if( pReceivePacket->Data[1] == 0 )
							{
								//
								// If we are ready for session resumption then send back
								// an ack
								//
								if( pSessionData->pProfileData->bUseSessionResumption && 
									pSessionData->bCipherSpec && pSessionData->bServerFinished && 
									pSessionData->bSentFinished )
								{
									//
									// This means the tunnel was setup succesfully
									// start inner authentication
									//
									dwRet = TLSBuildResponsePacket( pSessionData, 
																	pSendPacket, 
																	cbSendPacket, 
																	pEapInput, 
																	pEapOutput );
								}
								else
								{
									AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Resume_Session_Ack::ERROR::either no change cipher spec was found or the server did not send a finished packet" ) ) );

									dwRet = ERROR_PPP_INVALID_PACKET;
								}
							}
							else
							{
								dwRet = ERROR_PPP_INVALID_PACKET;
							}

						break;

						case EAPCODE_Response:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Resume_Session_Ack::Response Packet->" ) ) );

							dwRet = ERROR_PPP_INVALID_PACKET;

						break;

						case EAPCODE_Success:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Resume_Session_Ack::Success Packet->" ) ) );

							//
							// I should deny this request, we should first get an TTLS-Request
							// then send a ACK then we get a success, but for some reason
							// Funk follows the EAP-TLS RFC (which send a success directly after the TLS tunnel has been setup)
							// and not Funk's own RFC, 
							// but... why follow your own RFC? ;)
							//
							//dwRet = ERROR_PPP_INVALID_PACKET;

							if( ( dwRet = MakeMPPEKey( pSessionData->hCSP,
														pSessionData->pbRandomClient,
														pSessionData->pbRandomServer,
														pSessionData->pUserData->pbMS,
														&( pSessionData->pUserAttributes ) ) ) == NO_ERROR )
							{
								pEapOutput->pUserAttributes = pSessionData->pUserAttributes;

								pEapOutput->Action = EAPACTION_Done;
								pSessionData->AuthState = AUTH_STATE_Finished;
							}

						break;

						case EAPCODE_Failure:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Resume_Session_Ack::Failure Packet->" ) ) );

							dwRet = ERROR_AUTH_INTERNAL;

						break;

						default:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Resume_Session_Ack::WARNING:unexpected packet") ) );

							dwRet = ERROR_PPP_INVALID_PACKET;

						break;
					}
				}
				else
				{
					AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Resume_Session_Ack::WARNING: pReceivePacket == NULL" ) ) );
				}

			break;

			case  AUTH_STATE_Verify_Cert:

				AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Verify_Cert" ) ) );

				if( !pEapInput->fDataReceivedFromInteractiveUI )
				{
					AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Verify_Cert::User has not exited from VerifyCertificate dialog yet" ) ) );

					dwRet = PENDING;
				}
				else
				{
					if( pEapInput->dwSizeOfDataFromInteractiveUI > 0 )
					{
						AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Verify_Cert::user returned data from InteractiveUI" ) ) );

						pwcTemp = ( WCHAR* ) pEapInput->pDataFromInteractiveUI;

						if( wcscmp( pwcTemp, L"ERROR_OK" ) == 0 )
						{
							//
							// Everything is OK
							//
						}
						else
						{
							dwRet = ERROR_CANCELLED;
						}
					}

					if( dwRet == NO_ERROR )
						dwRet = TLSBuildResponsePacket( pSessionData, pSendPacket, cbSendPacket, pEapInput, pEapOutput );
				}

			break;

			case AUTH_STATE_Change_Cipher_Spec:

				AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Change_Cipher_Spec" ) ) );

				if( pReceivePacket )
				{
					switch( pReceivePacket->Code )
					{
						case EAPCODE_Request:

							dwEAPPacketLength = AA_WireToHostFormat16( &( pReceivePacket->Length[0] ) );

							//
							// This function will read all the information in the fragged messages
							//
							dwRet = TLSReadMessage( pSessionData->pbReceiveMsg,
													&( pSessionData->cbReceiveMsg ),
													&( pSessionData->dwReceiveCursor ),
													pSessionData->bPacketId,
													pReceivePacket, 
													pSendPacket, 
													cbSendPacket, 
													pEapInput, 
													pEapOutput, 
													dwEAPPacketLength );
						
							if( ( pEapOutput->Action != EAPACTION_Send ) && dwRet == NO_ERROR )
							{
								AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Change_Cipher_Spec::total message(%d): %s" ), pSessionData->cbReceiveMsg, AA_ByteToHex( pSessionData->pbReceiveMsg, pSessionData->cbReceiveMsg ) ) );

								if( ( dwRet = TLSParseServerPacket( pSessionData, pSessionData->pbReceiveMsg, pSessionData->cbReceiveMsg ) ) == NO_ERROR )
								{
									if( pSessionData->bCipherSpec && pSessionData->bServerFinished )
									{
										//
										// This means the tunnel was setup succesfully
										// start inner authentication
										//
										dwRet = TLSBuildResponsePacket( pSessionData, pSendPacket, cbSendPacket, pEapInput, pEapOutput );
									}
									else
									{
										AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Change_Cipher_Spec::ERROR::either no change cipher spec was found or the server did not send a finished packet" ) ) );

										dwRet = ERROR_PPP_INVALID_PACKET;
									}
								}

								memset( pSessionData->pbReceiveMsg, 0, sizeof( pSessionData->pbReceiveMsg ) );
								pSessionData->cbReceiveMsg = 0;
								pSessionData->dwReceiveCursor = 0;
							}
							else if( dwRet != NO_ERROR )
							{
								memset( pSessionData->pbReceiveMsg, 0, sizeof( pSessionData->pbReceiveMsg ) );
								pSessionData->cbReceiveMsg = 0;
								pSessionData->dwReceiveCursor = 0;
							}


						break;

						case EAPCODE_Response:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Change_Cipher_Spec::Response Packet->" ) ) );

							dwRet = ERROR_PPP_INVALID_PACKET;

						break;

						case EAPCODE_Success:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Change_Cipher_Spec::Success Packet->" ) ) );

							dwRet = ERROR_PPP_INVALID_PACKET;

						break;

						case EAPCODE_Failure:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Change_Cipher_Spec::Failure Packet->" ) ) );

							dwRet = ERROR_AUTH_INTERNAL;

						break;

						default:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Change_Cipher_Spec::WARNING:unexpected packet") ) );
							
							dwRet = ERROR_PPP_INVALID_PACKET;

						break;
					}
				}
				else
				{
					AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Change_Cipher_Spec::WARNING: pReceivePacket == NULL" ) ) );
				}

			break;

			case AUTH_STATE_Inner_Authentication:

				if( pReceivePacket )
				{
					switch( pReceivePacket->Code )
					{
						case EAPCODE_Request:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Inner_Authentication::Request Packet->" ) ) );


							dwEAPPacketLength = AA_WireToHostFormat16(  &( pReceivePacket->Length[0] ) );

							//
							// This function will read all the information in the fragged messages
							//
							dwRet = TLSReadMessage( pSessionData->pbReceiveMsg,
													&( pSessionData->cbReceiveMsg ),
													&( pSessionData->dwReceiveCursor ),
													pSessionData->bPacketId,
													pReceivePacket, 
													pSendPacket, 
													cbSendPacket, 
													pEapInput, 
													pEapOutput, 
													dwEAPPacketLength );
						
							if( ( pEapOutput->Action != EAPACTION_Send ) && dwRet == NO_ERROR )
							{
								AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Inner_Authentication::total message(%d): %s" ), pSessionData->cbReceiveMsg, AA_ByteToHex( pSessionData->pbReceiveMsg, pSessionData->cbReceiveMsg ) ) );

								if( ( dwRet = TLSParseServerPacket( pSessionData, pSessionData->pbReceiveMsg, pSessionData->cbReceiveMsg ) ) == NO_ERROR )
									dwRet = TLSBuildResponsePacket( pSessionData, pSendPacket, cbSendPacket, pEapInput, pEapOutput );

								memset( pSessionData->pbReceiveMsg, 0, sizeof( pSessionData->pbReceiveMsg ) );
								pSessionData->cbReceiveMsg = 0;
								pSessionData->dwReceiveCursor = 0;
							}
							else if( dwRet != NO_ERROR )
							{
								memset( pSessionData->pbReceiveMsg, 0, sizeof( pSessionData->pbReceiveMsg ) );
								pSessionData->cbReceiveMsg = 0;
								pSessionData->dwReceiveCursor = 0;
							}

						break;

						case EAPCODE_Response:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Inner_Authentication::Response Packet->" ) ) );

							dwRet = ERROR_PPP_INVALID_PACKET;

						break;

						case EAPCODE_Success:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Inner_Authentication::Success Packet->" ) ) );

							if( dwRet == NO_ERROR )
							{
								if( ( dwRet = MakeMPPEKey( pSessionData->hCSP,
															pSessionData->pbRandomClient,
															pSessionData->pbRandomServer,
															pSessionData->pUserData->pbMS,
															&( pSessionData->pUserAttributes ) ) ) == NO_ERROR )
								{
									pEapOutput->pUserAttributes = pSessionData->pUserAttributes;

									pEapOutput->Action = EAPACTION_Done;
									pSessionData->AuthState = AUTH_STATE_Finished;
								}
							}

						break;

						case EAPCODE_Failure:

								AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Inner_Authentication::Failure Packet->" ) ) );

								pEapOutput->Action = EAPACTION_NoAction;

								dwRet = ERROR_AUTHENTICATION_FAILURE;

						break;

						default:

							AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Change_Cipher_Spec::WARNING:unexpected packet") ) );

							dwRet = ERROR_PPP_INVALID_PACKET;

						break;
					}
				}
				else
				{
					//
					// Could be that the interactive userinterface was invoked
					//
					dwRet = TLSBuildResponsePacket( pSessionData, pSendPacket, cbSendPacket, pEapInput, pEapOutput );
				}

			break;

			case AUTH_STATE_Error:

				AA_TRACE( ( TEXT( "RasEapMakeMessage::AUTH_STATE_Error" ) ) );

				dwRet = ERROR_AUTH_INTERNAL;

			break;

			default:

				AA_TRACE( ( TEXT( "RasEapMakeMessage::Unknown State" ) ) );

				dwRet = ERROR_PPP_INVALID_PACKET;

			break;
		}
	}

	AA_TRACE( ( TEXT( "RasEapMakeMessage::updating states" ) ) );

	//
	// Update the authentication state
	//
	if( pReceivePacket )
	{
		if( pReceivePacket->Code == EAPCODE_Failure )
		{
			pSessionData->pUserData->PrevAuthResult = PREV_AUTH_RESULT_failed;
		}
		else if( pReceivePacket->Code == EAPCODE_Success )
		{
			pSessionData->pUserData->PrevAuthResult = PREV_AUTH_RESULT_success;
		}
	}

	//
	// Tom Rixom, 21-05-2004
	// If we had a success packet and we are done and finished then
	// check to see if we want to save the user credentials
	// if so then do it...
	//
	if( pReceivePacket )
	{
		if( pReceivePacket->Code == EAPCODE_Success &&
			pEapOutput->Action == EAPACTION_Done &&
			pSessionData->AuthState == AUTH_STATE_Finished )
		{
			if( pSessionData->pUserData->bSaveUserCredentials )
			{
				memcpy( pSessionData->pProfileData->pwcUserName,
						pSessionData->pUserData->pwcUsername,
						sizeof( pSessionData->pProfileData->pwcUserName ) );

				memcpy( pSessionData->pProfileData->pwcUserPassword,
						pSessionData->pUserData->pwcPassword,
						sizeof( pSessionData->pProfileData->pwcUserPassword ) );

				memcpy( pSessionData->pProfileData->pwcUserDomain,
						pSessionData->pUserData->pwcDomain,
						sizeof( pSessionData->pProfileData->pwcUserDomain ) );

#ifndef _WIN32_WCE
				if( pSessionData->pProfileData->bUseCredentialsForComputer &&
					!pSessionData->pProfileData->bUseAlternateComputerCred )
				{
					memcpy( pSessionData->pProfileData->pwcCompName, pSessionData->pProfileData->pwcUserName, sizeof( pSessionData->pProfileData->pwcCompName ) );
					memcpy( pSessionData->pProfileData->pwcCompPassword, pSessionData->pProfileData->pwcUserPassword, sizeof( pSessionData->pProfileData->pwcCompPassword ) );
					memcpy( pSessionData->pProfileData->pwcCompDomain, pSessionData->pProfileData->pwcUserDomain, sizeof( pSessionData->pProfileData->pwcCompDomain ) );
				}
#endif // _WIN32_WCE

				pSessionData->pProfileData->bPromptUser = FALSE;

				AA_WriteProfile( pSessionData->pwcCurrentProfileId, 
								pSessionData->hTokenImpersonateUser,
								*( pSessionData->pProfileData ) );
			}
		}
		else if(pReceivePacket->Code == EAPCODE_Failure &&
			pSessionData->AuthState == AUTH_STATE_Inner_Authentication )
		{
			//
			// Authentication failed in the inner authentication
			// Reset the configuration of SW2 to ask the user for
			// new credentials in the next authentication run
			//
			pSessionData->pProfileData->bPromptUser = TRUE;

			AA_WriteProfile( pSessionData->pwcCurrentProfileId, 
								pSessionData->hTokenImpersonateUser,
								*( pSessionData->pProfileData ) );
		}
	}
		
	//
	// Save the user data
	//
	pEapOutput->pUserData = ( PBYTE ) pSessionData->pUserData;
	pEapOutput->dwSizeOfUserData = sizeof( SW2_USER_DATA );
	pEapOutput->fSaveUserData = TRUE;

	AA_TRACE( ( TEXT( "RasEapMakeMessage::what are we sending?" ) ) );

	if( pSendPacket )
	{
		if( AA_WireToHostFormat16( pSendPacket->Length ) > 0 )
		{
			AA_TRACE( ( TEXT( "RasEapMakeMessage::Sending packet ID: %d" ), pSendPacket->Id ) );
			AA_TRACE( ( TEXT( "RasEapMakeMessage::Sending packet(%d): %s" ), AA_WireToHostFormat16( pSendPacket->Length ), AA_ByteToHex( ( PBYTE ) pSendPacket, AA_WireToHostFormat16( pSendPacket->Length ) ) ) );
		}
	}

	if( pEapOutput->fInvokeInteractiveUI )
	{
		AA_TRACE( ( TEXT( "RasEapMakeMessage::Invoking Interactive UI(%ld)" ), pEapOutput->dwSizeOfUIContextData ) );
	}

	//
	// Handle error
	//	
	if( dwRet != NO_ERROR )
	{
#ifndef _WIN32_WCE
		//
		// If using the SecureW2 Gina write result
		//
		if( pSessionData->pProfileData->GinaConfigData.bUseSW2Gina )
			AA_WriteResult( dwRet );
#endif // _WIN32_WCE

		AA_ReportEvent( L"RasEapMakeMessage Failed", EVENTLOG_ERROR_TYPE, dwRet );
/*
		// 
		// Show error (except of course if this has already been shown)
		// NOT IMPLEMENTED YET
		//
		if ( pSessionData->AuthState != AUTH_STATE_Error )
		{
			AA_TRACE( ( TEXT( "RasEapMakeMessage::calling interactive UI" ) ) );

			pEapOutput->fInvokeInteractiveUI = TRUE;

			pSessionData->bInteractiveUIType = UI_TYPE_ERROR;

			pSessionData->dwError = dwRet;

			pEapOutput->pUIContextData = ( PBYTE ) pSessionData;

			pEapOutput->dwSizeOfUIContextData = sizeof( SW2_SESSION_DATA );

			pSessionData->AuthState = AUTH_STATE_Error;

			pEapOutput->Action = EAPACTION_NoAction;

			dwRet = NO_ERROR;
		}
		else
		{
*/
			//
			// Handle ERROR
			// If authentication failed, return no action to start reauthentication
			// immediatly, except if Gina is enabled!
			//
			if( dwRet == ERROR_PPP_INVALID_PACKET 
				|| dwRet == PENDING 
#ifndef _WIN32_WCE
				|| ( dwRet == ERROR_AUTHENTICATION_FAILURE && !pSessionData->pProfileData->GinaConfigData.bUseSW2Gina ) 
#endif // _WIN32_WCE
				)
				pEapOutput->Action = EAPACTION_NoAction;
			else if( dwRet != NO_ERROR )
			{
				pEapOutput->Action = EAPACTION_Done;

				pEapOutput->dwAuthResultCode = dwRet;
		//	}
		}
	}

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "RasEapMakeMessage::returning, action: %x, authcode: %x, error: %x" ), pEapOutput->Action, pEapOutput->dwAuthResultCode, dwRet ) );

	return dwRet;
}

#ifndef _WIN32_WCE
//
// Name: AA_RenewIP
// Description: Renew the IP adresses off all the currently active
//				adapters, this is not normally a function for a EAP
//				module but the DHCP on a Windows 2000 Machine does not
//				work well with 802.1X
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
WINAPI
AA_RenewIP( LPVOID lpvoid )
{
	PIP_ADAPTER_INFO	pAdaptersInfo;
	PIP_ADAPTER_INFO	p;
	DWORD				dwAdaptersInfoSize;
	WCHAR				pwcEntry[UNLEN];
	CHAR				pcDescription[UNLEN];
	PIP_INTERFACE_INFO	pInterfaceInfo;
	DWORD				dwInterfaceInfoSize;
	int					i;
	WCHAR				pwcGUID[UNLEN];
	WCHAR				pwcKey[UNLEN];
	DWORD				cwcKey;
	PBYTE				pbName;
	DWORD				cbName;
	WCHAR				*pwcName;
	FILETIME 			ftLastWriteTime;
	HKEY				hKey1;
	HKEY				hKey2;
	DWORD				dwRet;

	dwRet = NO_ERROR;

	if( !lpvoid )
	{
		AA_TRACE( ( TEXT( "AA_RenewIP::!lpvoid" ) ) );

		return ERROR_NO_DATA;
	}

	wcscpy( pwcEntry, ( WCHAR * ) lpvoid );

	AA_TRACE( ( TEXT( "AA_RenewIP::renewing IP address for %ws" ), pwcEntry ) );

	//
	// Allow Ras to cleanup and initialize connection
	//
	Sleep( 2000 );

	//
	// Translate the friendly name to a GUID
	//
	if( ( dwRet =  RegOpenKeyEx( HKEY_LOCAL_MACHINE,
								TEXT( "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}" ),
								0,
								KEY_READ,
								&hKey1 ) ) == NO_ERROR )
	{
		AA_TRACE( ( TEXT( "AA_RenewIP::opened key" ) ) );

		for (i = 0; dwRet == NO_ERROR; i++) 
		{ 
			cwcKey = sizeof( pwcKey );

			if( ( dwRet = RegEnumKeyEx( hKey1, 
										i, 
										pwcKey, 
										&cwcKey, 
										NULL, 
										NULL, 
										NULL, 
										&ftLastWriteTime ) ) == NO_ERROR )
			{
				AA_TRACE( ( TEXT( "AA_RenewIP::found adapter key: %ws" ), pwcKey ) );

				//
				// Copy keyname which contains the GUID for later use
				//
				wcscpy( pwcGUID, pwcKey );

				wcscat( pwcKey, L"\\Connection" );

				if( RegOpenKeyEx( hKey1,
								pwcKey,
								0,
								KEY_QUERY_VALUE,
								&hKey2 ) == NO_ERROR )
				{
					AA_TRACE( ( TEXT( "AA_RenewIP::found connection entry" ) ) );

					//
					// Read time stamp
					//
					if( ( dwRet = AA_RegGetValue( hKey2, L"Name", &pbName, &cbName ) ) == NO_ERROR )
					{
						pwcName = ( WCHAR * ) pbName;

						AA_TRACE( ( TEXT( "AA_RenewIP::found name value: %s" ), pwcName ) );

						if( wcscmp( pwcName, pwcEntry ) == 0 )
						{
							AA_TRACE( ( TEXT( "AA_RenewIP::found equal" ) ) );

							break;
						}

						free( pbName );
					}

					RegCloseKey( hKey2 );
				}
			}
		}

		RegCloseKey( hKey1 );
	}

	if( dwRet != NO_ERROR )
	{
		AA_TRACE( ( TEXT( "AA_RenewIP::using description" ) ) );

		//
		// Couldn't find GUID by searching by entry name
		// so try searching for guid using the friendly name (Description)
		//
		if( ( WideCharToMultiByte( CP_ACP, 0, pwcEntry, -1, pcDescription, sizeof( pcDescription ), NULL, NULL ) ) > 0 )
		{
			AA_TRACE( ( TEXT( "AA_RenewIP::pcDescription: %s" ), pcDescription ) );

			dwAdaptersInfoSize = 0;

			dwRet = GetAdaptersInfo( NULL, &dwAdaptersInfoSize );

			if( dwRet == ERROR_BUFFER_OVERFLOW )
			{
				if( ( pAdaptersInfo = ( PIP_ADAPTER_INFO ) malloc( dwAdaptersInfoSize ) ) )
				{
					if( ( dwRet = GetAdaptersInfo( pAdaptersInfo, &dwAdaptersInfoSize ) ) == NO_ERROR )
					{
						AA_TRACE( ( TEXT( "AA_RenewIP:: got adapter info" ) ) );

						p = pAdaptersInfo;

						//
						// loop through the adapters till we find a corresponding friendly name
						//
						while( p )
						{
							AA_TRACE( ( TEXT( "AA_RenewIP:: found adapter: %s" ), p->Description ) );

							if( strcmp( p->Description, pcDescription  ) == 0 )
							{
								//
								// Found equal, now copy GUID
								//
								if( ( DWORD ) strlen( p->AdapterName ) <= UNLEN )
								{
									if( MultiByteToWideChar( CP_ACP, 0, p->AdapterName, -1, pwcGUID, sizeof( pwcGUID ) ) > 0 )
									{
										AA_TRACE( ( TEXT( "AA_RenewIP:: translated Description to GUID: %s" ), pwcGUID ) );
									}
								}

								break;
							}

							AA_TRACE( ( TEXT( "AA_RenewIP:: looping" ) ) );

							p = p->Next;
						}
					}

					free( pAdaptersInfo );
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
	}

	if( dwRet == NO_ERROR )
	{
		AA_TRACE( ( TEXT( "AA_RenewIP::translated: %s to %s" ), pwcEntry, pwcGUID ) );

		dwInterfaceInfoSize = 0;
			
		dwRet = GetInterfaceInfo( NULL, &dwInterfaceInfoSize );

		if( dwRet == ERROR_INSUFFICIENT_BUFFER )
		{
			if( ( pInterfaceInfo = ( PIP_INTERFACE_INFO ) malloc( dwInterfaceInfoSize ) ) )
			{
				if( ( dwRet = GetInterfaceInfo( pInterfaceInfo, &dwInterfaceInfoSize ) ) == NO_ERROR )
				{
					AA_TRACE( ( TEXT( "AA_RenewIP::found %ld adapters" ), pInterfaceInfo->NumAdapters ) );

					for( i=0; i < pInterfaceInfo->NumAdapters; i++ )
					{
						AA_TRACE( ( TEXT( "AA_RenewIP::pInterfaceInfo->Adapter[i].Name: %s" ), pInterfaceInfo->Adapter[i].Name ) );

						//
						// Compare the GUIDs and if they match renew the adapter
						//
						if( wcsstr( pInterfaceInfo->Adapter[i].Name, pwcGUID ) )
						{
							AA_TRACE( ( TEXT( "AA_RenewIP::releasing adapter %ws" ), pInterfaceInfo->Adapter[i].Name ) );

							if( ( dwRet = IpReleaseAddress( &pInterfaceInfo->Adapter[i] ) ) == NO_ERROR )
							{
								AA_TRACE( ( TEXT( "AA_RenewIP::renewing ip address" ) ) );

								IpRenewAddress( &pInterfaceInfo->Adapter[i] );
							}

							break;
						}
					}
				}

				free( pInterfaceInfo );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
	}

	AA_TRACE( ( TEXT( "AA_RenewIP:: returning: %ld" ), dwRet ) );

	return dwRet;
}
#endif //_WIN32_WCE
