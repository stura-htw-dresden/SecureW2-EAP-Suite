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
// Name: CommonProfile.c
// Description: Contains the common functionality for profiles
// Author: Tom Rixom
// Created: 10 December 2004
// Version: 1.0
// Last revision: 10 Februari 2004 
//
// ----------------------------- Revisions -------------------------------
//
// Revision - <Date of revision> <Version of file which has been revised> <Name of author>
// <Description of what has been revised>
//

#include "Common.h"
#ifndef _WIN32_WCE
#include <shlwapi.h>
#include <aclapi.h>
#include <Sddl.h>
#endif // _WIN32_WCE

//
// Name: AA_InitDefaultProfile
// Description: Initializes a ProfileData to the Default values
// Author: Tom Rixom
// Created: 12 May 2004
//
VOID
AA_InitDefaultProfile( PSW2_PROFILE_DATA pProfileData )
{
	AA_TRACE( ( TEXT( "AA_InitDefaultProfile" ) ) );

	memset( pProfileData, 0, sizeof( SW2_PROFILE_DATA ) );

	wcscpy( pProfileData->pwcInnerAuth, L"PAP" );
	pProfileData->bVerifyServer = TRUE;
	pProfileData->bPromptUser = TRUE;
	pProfileData->bUseAlternateOuter = TRUE;
	pProfileData->bUseAlternateAnonymous = TRUE;
#ifndef _WIN32_WCE
	pProfileData->bRenewIP = FALSE;
#endif // _WIN32_WCE
	pProfileData->iVersion = AA_CONFIG_VERSION;

#ifndef _WIN32_WCE
	AA_InitDefaultGinaConfig( &( pProfileData->GinaConfigData ) );

	wcscpy( pProfileData->GinaConfigData.pwcGinaType, GINA_TYPE_Microsoft );
#endif // _WIN32_WCE

}

#ifndef _WIN32_WCE
//
// Name: AA_InitDefaultGinaConfig
// Description: Initializes a GinaConfig to the Default values
// Author: Tom Rixom
// Created: 12 May 2004
//
VOID
AA_InitDefaultGinaConfig( PSW2_GINA_CONFIG_DATA pGinaConfigData )
{
	AA_TRACE( ( TEXT( "AA_InitDefaultGinaConfig" ) ) );

	memset( pGinaConfigData, 0, sizeof( SW2_GINA_CONFIG_DATA ) );

	wcscpy( pGinaConfigData->pwcGinaType, GINA_TYPE_Novell );
}
#endif // _WIN32_WCE

//
// Name: AA_CreateProfile
// Description: Create a profile in the registry using the pwcProfileID
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
AA_CreateProfile( IN WCHAR *pwcProfileID )
{
	HKEY	hKey;
	DWORD	dwDisposition = 0;
	DWORD	dwRet;
	WCHAR	pwcTemp[1024];

	dwRet = NO_ERROR;

	swprintf( pwcTemp, TEXT( "%s\\%s"), AA_CLIENT_PROFILE_LOCATION, pwcProfileID );

	AA_TRACE( ( TEXT( "AA_CreateProfile: Path: %ws" ), pwcTemp ) );

	if( ( dwRet = AA_CreateSecureKey( HKEY_LOCAL_MACHINE, pwcTemp, &hKey, &dwDisposition ) ) == NO_ERROR )
	{
		if( dwDisposition != REG_CREATED_NEW_KEY )
			dwRet = ERROR_ALREADY_EXISTS;

		RegCloseKey( hKey );
	}

	return dwRet;
}

//
// Name: AA_DeleteProfile
// Description: Remove a profile from the registry using the pwcProfileID
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
AA_DeleteProfile( IN WCHAR	*pwcProfileID )
{
	WCHAR	pwcTemp[MAX_PATH*2];
	DWORD	dwRet;

	dwRet = NO_ERROR;

	swprintf( pwcTemp, TEXT( "%s\\%s"), AA_CLIENT_PROFILE_LOCATION, pwcProfileID );

	AA_TRACE( ( TEXT( "AA_DeleteProfile: Path: %ws" ), pwcTemp ) );

#ifdef _WIN32_WCE
	dwRet = RegDeleteKey( HKEY_LOCAL_MACHINE, pwcTemp );
#else
	dwRet = SHDeleteKey( HKEY_LOCAL_MACHINE, pwcTemp );
#endif // _WIN32_WCE

	AA_TRACE( ( TEXT( "AA_DeleteProfile: returning: %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: AA_ReadProfile
// Description: Read a profile in the registry using the pwcProfileID
//				If hTokenImpersonateUser is defined and valid use it
//				to read the profile information of the logged on user 
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
AA_ReadProfile( IN WCHAR					*pwcProfileID,
				IN HANDLE					hTokenImpersonateUser,
				IN OUT PSW2_PROFILE_DATA	pProfileData )
{
	HKEY	hKeyLM;
	HKEY	hKeyCU = NULL;
	HANDLE	hToken = NULL;
	WCHAR	pwcTemp[MAX_PATH*2];
	int		i = 0;
	PBYTE	pbData;
	DWORD	cbData = 0;
	PBYTE	pbProfileData;
#ifndef _WIN32_WCE
	PBYTE	pbCompPassword;
#endif // _WIN32_WCE
	PBYTE	pbUserPassword;
	DWORD	dwRet;

	AA_TRACE( ( TEXT( "AA_ReadProfile" ) ) );

	dwRet = NO_ERROR;

	if( pwcProfileID )
		swprintf( pwcTemp, 
					TEXT( "%s\\%s" ), 
					AA_CLIENT_PROFILE_LOCATION,
					pwcProfileID );
	else
		swprintf( pwcTemp, 
					TEXT( "%s\\DEFAULT" ), 
					AA_CLIENT_PROFILE_LOCATION );

	if( ( dwRet = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
								pwcTemp,
								0,
								KEY_READ,
								&hKeyLM ) ) == ERROR_SUCCESS )
	{
		AA_TRACE( ( TEXT( "AA_ReadProfile: opened key (HKEY_LOCAL_MACHINE\\%s)" ), pwcTemp ) );

		//
		// Load previous config if any
		//
		if( ( dwRet = AA_RegGetValue( hKeyLM, 
									L"Data", 
									&pbData,
									&cbData ) ) == NO_ERROR )
		{
			AA_TRACE( ( TEXT( "AA_ReadProfile: found Data(%ld)" ), cbData ) );

			if( cbData == sizeof( SW2_PROFILE_DATA ) )
			{
				if( ( dwRet = AA_XorData( pbData, 
									cbData, 
									AA_SECRET, 
									( DWORD ) strlen( AA_SECRET ),
									&pbProfileData ) ) == NO_ERROR )
				{
					AA_TRACE( ( TEXT( "AA_ReadProfile: copying data" ) ) );

					memcpy( pProfileData,
							pbProfileData,
							cbData );

					if( pProfileData->iVersion != AA_CONFIG_VERSION )
					{
						AA_TRACE( ( TEXT( "AA_ReadProfile: incorrect version" ) ) );

						memset( pProfileData, 0, sizeof( SW2_PROFILE_DATA ) );

						dwRet = ERROR_NOT_SUPPORTED;
					}

					AA_TRACE( ( TEXT( "AA_ReadProfile: freeing pbProfileData" ) ) );

					free( pbProfileData );
				}
			}
			else
				dwRet = ERROR_NOT_ENOUGH_MEMORY;

			free( pbData );
		}

		RegCloseKey( hKeyLM );
	}

	if( dwRet == NO_ERROR )
	{
		AA_TRACE( ( TEXT( "AA_ReadProfile: read initial data" ) ) );

		//
		// First initialize certificates, default user and computer credential parameters
		//
		for( i=0; i < AA_MAX_CA; i++ )
			memset( pProfileData->pbTrustedRootCAList[i], 0, 20 );

		pProfileData->dwNrOfTrustedRootCAInList = 0;

		pProfileData->bPromptUser = TRUE;
		memset( pProfileData->pwcUserName, 0, sizeof( pProfileData->pwcUserName ) );
		memset( pProfileData->pwcUserPassword, 0, sizeof( pProfileData->pwcUserPassword ) );
		memset( pProfileData->pwcUserDomain, 0, sizeof( pProfileData->pwcUserDomain ) );
#ifndef _WIN32_WCE
		memset( pProfileData->pwcCompPassword, 0, sizeof( pProfileData->pwcCompPassword ) );
#endif // _WIN32_WCE

		AA_TRACE( ( TEXT( "AA_ReadProfile: going to read credentials" ) ) );

		dwRet = AA_ReadCertificates( pwcProfileID, pProfileData );

		if( pwcProfileID )
			swprintf( pwcTemp, 
						TEXT( "%s\\%s\\Credentials" ), 
						AA_CLIENT_PROFILE_LOCATION,
						pwcProfileID );
		else
			swprintf( pwcTemp, 
						TEXT( "%s\\DEFAULT\\Credentials" ), 
						AA_CLIENT_PROFILE_LOCATION );

#ifndef _WIN32_WCE

		//
		// computer credentials
		//
		if( ( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
							pwcTemp,
							0,
							KEY_READ,
							&hKeyLM ) == ERROR_SUCCESS ) )
		{
			AA_TRACE( ( TEXT( "AA_ReadProfile: opened key (HKEY_LOCAL_MACHINE\\%ws)" ), pwcTemp ) );

			//
			// Now try and read out the computer password credentials
			// ignore any errors
			//
			if( AA_RegGetValue( hKeyLM, 
								L"ComputerPassword", 
								&pbData,
								&cbData ) == NO_ERROR )
			{
				AA_TRACE( ( TEXT( "AA_ReadProfile: found cbData(%ld)" ), cbData ) );

				if( ( dwRet = AA_XorData( pbData, 
									cbData, 
									AA_SECRET, 
									( DWORD ) strlen( AA_SECRET ),
									&pbCompPassword ) ) == NO_ERROR )
				{
					memset( pProfileData->pwcCompPassword, 0, sizeof( pProfileData->pwcCompPassword ) );

					memcpy( pProfileData->pwcCompPassword,
							pbCompPassword,
							cbData );

					free( pbCompPassword );
				}

				free( pbData );
			}

			RegCloseKey( hKeyLM );
		}

		//
		// Check if we have a user token so we can read out Sid
		//
		if( hTokenImpersonateUser )
			hToken = hTokenImpersonateUser;
		else
		{
			AA_TRACE( ( TEXT( "AA_ReadProfile: using thread token" ) ) );

			if( !OpenThreadToken( GetCurrentThread(),
									TOKEN_QUERY,
									TRUE,
									&hToken ) )
			{
				AA_TRACE( ( TEXT( "AA_ReadProfile: FAILED to read user thread token: %ld" ), GetLastError() ) );

				hToken = NULL;

				//
				// Try by process
				//
				if( !OpenProcessToken( GetCurrentThread(),
										TOKEN_QUERY,
										&hToken ) )
				{
					AA_TRACE( ( TEXT( "AA_ReadProfile: FAILED to read user process token: %ld" ), GetLastError() ) );

					hToken = NULL;
				}
			}
		}

		if( hToken )
		{
			PBYTE		pbData;
			DWORD		cbData;
			PTOKEN_USER	pTokenUser;
			WCHAR		pwcSid[UNLEN];
			DWORD		cwcSid;

			cbData = 0;
						
			GetTokenInformation( hToken, 
									TokenUser,
									NULL,
									0,
									&cbData );

			if( ( pbData = ( PBYTE ) malloc( cbData ) ) )
			{
				if( GetTokenInformation( hToken, 
										TokenUser,
										pbData,
										cbData,
										&cbData ) )
				{
					cwcSid = sizeof( pwcSid );

					pTokenUser = ( PTOKEN_USER ) pbData;

					if( AA_GetTextualSid( pTokenUser->User.Sid,
										pwcSid,
										&cwcSid ) )
					{
						AA_TRACE( ( TEXT( "AA_ReadProfile: SID: %ws" ), pwcSid ) );

						if( pwcProfileID )
							swprintf( pwcTemp, 
										TEXT( "%s\\%s\\%s\\Credentials" ), 
										pwcSid,
										AA_CLIENT_PROFILE_LOCATION,
										pwcProfileID );
						else
							swprintf( pwcTemp, 
										TEXT( "%s\\%s\\DEFAULT\\Credentials" ), 
										pwcSid,
										AA_CLIENT_PROFILE_LOCATION );


						AA_TRACE( ( TEXT( "AA_ReadProfile: opening key: %ws" ), pwcTemp ) );

						dwRet = RegOpenKeyEx( HKEY_USERS,
											pwcTemp,
											0,
											KEY_READ,
											&hKeyCU );
					}
					else
					{
						AA_TRACE( ( TEXT( "AA_ReadProfile: AA_GetTextualSid FAILED: %ld" ), GetLastError() ) );		
						dwRet = ERROR_CANTOPEN;
					}
				}
				else
				{
					AA_TRACE( ( TEXT( "AA_ReadProfile: GetTokenInformation FAILED: %ld" ), GetLastError() ) );		
					dwRet = ERROR_CANTOPEN;
				}

				free( pbData );
			}
			else
				dwRet = ERROR_NOT_ENOUGH_MEMORY;

			if( !hTokenImpersonateUser )
				CloseHandle( hToken );
		}
		else
		{
			AA_TRACE( ( TEXT( "AA_ReadProfile: opening key: %ws" ), pwcTemp ) );

			dwRet = RegOpenKeyEx( HKEY_CURRENT_USER,
								pwcTemp,
								0,
								KEY_READ,
								&hKeyCU );

			AA_TRACE( ( TEXT( "AA_ReadProfile: dwRet: %ld, %ld" ), dwRet, GetLastError() ) );
		}

		if( dwRet == NO_ERROR )
		{
#else
		if( ( dwRet =  RegOpenKeyEx( HKEY_CURRENT_USER,
									pwcTemp,
									0,
									KEY_READ,
									&hKeyCU ) ) == ERROR_SUCCESS )
		{
#endif // _WIN32_WCE
			AA_TRACE( ( TEXT( "AA_ReadProfile: opened key (%ws)" ), pwcTemp ) );

			if( AA_RegGetValue( hKeyCU, 
								L"PromptUser", 
								&pbData,
								&cbData ) == NO_ERROR )
			{
				AA_TRACE( ( TEXT( "AA_ReadProfile: PromptUser" ) ) );

				if( cbData == 1 )
					memcpy( &pProfileData->bPromptUser, pbData, 1 );

				free( pbData );
			}

			if( AA_RegGetValue( hKeyCU, 
								L"UserName", 
								&pbData,
								&cbData ) == NO_ERROR )
			{
				AA_TRACE( ( TEXT( "AA_ReadProfile: UserName" ) ) );

				if( cbData <= sizeof( pProfileData->pwcUserName ) )
					memcpy( pProfileData->pwcUserName, pbData, cbData );

				free( pbData );
			}

			if( AA_RegGetValue( hKeyCU, 
								L"UserPassword", 
								&pbData,
								&cbData ) == NO_ERROR )
			{
				AA_TRACE( ( TEXT( "AA_ReadProfile: UserPassword" ) ) );

				if( ( dwRet = AA_XorData( pbData, 
									cbData, 
									AA_SECRET, 
									( DWORD ) strlen( AA_SECRET ),
									&pbUserPassword ) ) == NO_ERROR )
				{
					memset( pProfileData->pwcUserPassword, 0, sizeof( pProfileData->pwcUserPassword ) );

					memcpy( pProfileData->pwcUserPassword,
							pbUserPassword,
							cbData );

					free( pbUserPassword );
				}

				free( pbData );
			}

			if( AA_RegGetValue( hKeyCU, 
								L"UserDomain", 
								&pbData,
								&cbData ) == NO_ERROR )
			{
				if( cbData <= sizeof( pProfileData->pwcUserDomain ) )
					memcpy( pProfileData->pwcUserDomain, pbData, cbData );

				free( pbData );
			}

			RegCloseKey( hKeyCU );
		}

		//
		// Errors during user credentials are ignored
		//
		dwRet = NO_ERROR;
	}

#ifndef _WIN32_WCE
	if( dwRet == NO_ERROR )
	{
		dwRet = AA_ReadGinaConfig( &( pProfileData->GinaConfigData ) );
	}
#endif // _WIN32_WCE

	if( dwRet != NO_ERROR )
	{
		AA_TRACE( ( TEXT( "AA_ReadProfile: Failed: %ld, %ld, Creating Default profile" ), dwRet, GetLastError() ) );

		AA_InitDefaultProfile( pProfileData );
	}

	if( pwcProfileID )
		wcscpy( pProfileData->pwcCurrentProfileId, pwcProfileID );
	else
		wcscpy( pProfileData->pwcCurrentProfileId, L"DEFAULT" );

	dwRet = NO_ERROR;

	return dwRet;
}

DWORD
AA_ReadCertificates( IN WCHAR *pwcProfileID, IN OUT PSW2_PROFILE_DATA pProfileData )
{
	HKEY	hKeyLM;
	PBYTE	pbCertificate;
	WCHAR	pwcTemp[MAX_PATH*2];
	WCHAR	pwcTemp2[MAX_PATH*2];
	DWORD	i;
	PBYTE	pbData;
	DWORD	cbData;
	DWORD	dwDisposition = 0;
	DWORD	dwRet = 0;

	//
	// Certificates
	//
	if( pwcProfileID )
		swprintf( pwcTemp, 
					TEXT( "%s\\%s\\RootCACert" ), 
					AA_CLIENT_PROFILE_LOCATION,
					pwcProfileID );
	else
		swprintf( pwcTemp, 
					TEXT( "%s\\DEFAULT\\RootCACert" ), 
					AA_CLIENT_PROFILE_LOCATION );


	pProfileData->dwNrOfTrustedRootCAInList = 0;

	if( ( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
						pwcTemp,
						0,
						KEY_READ,
						&hKeyLM ) == ERROR_SUCCESS ) )
	{
		AA_TRACE( ( TEXT( "AA_ReadProfile: opened key (HKEY_LOCAL_MACHINE\\%s)" ), pwcTemp ) );

		//
		// Now try and read out the computer password credentials
		// ignore any errors
		//
		memset( pwcTemp2, 0, sizeof( pwcTemp2 ) );

		swprintf( pwcTemp2, TEXT( "Certificate.0" ) );

		i = 1;

		while( AA_RegGetValue( hKeyLM, 
							pwcTemp2, 
							&pbData,
							&cbData ) == NO_ERROR )
		{
			AA_TRACE( ( TEXT( "AA_ReadProfile: found cbData(%ld)" ), cbData ) );

			if( ( dwRet = AA_XorData( pbData, 
								cbData, 
								AA_SECRET, 
								( DWORD ) strlen( AA_SECRET ),
								&pbCertificate ) ) == NO_ERROR )
			{
				memcpy( pProfileData->pbTrustedRootCAList[pProfileData->dwNrOfTrustedRootCAInList],
						pbCertificate,
						cbData );

				AA_TRACE( ( TEXT( "AA_ReadProfile: pbTrustedRootCAList[%ld]: %s" ), pProfileData->dwNrOfTrustedRootCAInList, AA_ByteToHex( pProfileData->pbTrustedRootCAList[pProfileData->dwNrOfTrustedRootCAInList], 20 )  ) );

				pProfileData->dwNrOfTrustedRootCAInList++;

				free( pbCertificate );
			}

			swprintf( pwcTemp2, TEXT( "Certificate.%ld" ), i );

			i++;

			free( pbData );
		}

		RegCloseKey( hKeyLM );
	}

	AA_TRACE( ( TEXT( "AA_ReadCertificates: returning %ld, found %ld certificates" ), dwRet, pProfileData->dwNrOfTrustedRootCAInList ) );

	return dwRet;
}

//
// Name: AA_WriteCertificates
// Description: Writes the trusted Root CA List to the registry
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
AA_WriteCertificates( IN WCHAR * pwcProfileId, IN SW2_PROFILE_DATA ProfileData )
{
	HKEY	hKeyLM;
	PBYTE	pbCertificate;
	WCHAR	pwcTemp[MAX_PATH*2];
	DWORD	i;
	DWORD	dwDisposition = 0;
	DWORD	dwRet;

	dwRet = NO_ERROR;

	swprintf( pwcTemp, 
			TEXT( "%s\\%s\\RootCACert" ), 
			AA_CLIENT_PROFILE_LOCATION,
			pwcProfileId );
				
	if( ( dwRet = AA_CreateSecureKey( HKEY_LOCAL_MACHINE,
									pwcTemp,
									&hKeyLM,
									&dwDisposition ) ) == NO_ERROR )
	{
		AA_TRACE( ( TEXT( "AA_WriteCertificates: created key: HKEY_LOCAL_MACHINE\\%s" ), pwcTemp ) );

		//
		// Remove previous certificates if any
		//
		i = 0;

		memset( pwcTemp, 0, sizeof( pwcTemp ) );

		swprintf( pwcTemp, TEXT( "Certificate.0" ) );

		while( RegDeleteValue( hKeyLM,
								pwcTemp ) == ERROR_SUCCESS )
		{
			AA_TRACE( ( TEXT( "AA_WriteCertificates: removed certificate %s" ), pwcTemp ) );

			i++;

			swprintf( pwcTemp, TEXT( "Certificate.%ld" ), i );
		}

		AA_TRACE( ( TEXT( "AA_WriteCertificates: removed certificates" ) ) );

		for( i=0; i < ProfileData.dwNrOfTrustedRootCAInList; i++ )
		{
			if( ( dwRet = AA_XorData( ( PBYTE ) ProfileData.pbTrustedRootCAList[i], 
							sizeof( ProfileData.pbTrustedRootCAList[i] ), 
							AA_SECRET, 
							( DWORD ) strlen( AA_SECRET ),
							&pbCertificate ) ) == NO_ERROR )
			{
				memset( pwcTemp, 0, sizeof( pwcTemp ) );

				swprintf( pwcTemp, TEXT( "Certificate.%ld" ), i );

				AA_TRACE( ( TEXT( "AA_WriteCertificates: writing certificate Certificate.%ld" ), i ) );

				if( RegSetValueEx( hKeyLM,
									pwcTemp,
									0,
									REG_BINARY,
									pbCertificate,
									20 ) != ERROR_SUCCESS )
				{
					dwRet = ERROR_CANTOPEN;
				}

				free( pbCertificate );

			}
		}
							
		RegCloseKey( hKeyLM );
	}


	return dwRet;
}

//
// Name: AA_WriteProfile
// Description: Writes a profile to the registry using the pwcProfileID
//				If hTokenImpersonateUser is defined and valid use it
//				to write the profile information of the logged on user 
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
AA_WriteProfile( IN WCHAR *pwcProfileID,
				IN HANDLE hTokenImpersonateUser,
				IN SW2_PROFILE_DATA ProfileData )
{
	HKEY				hKeyLM;
	HKEY				hKeyCU;
	HANDLE				hToken = NULL;
	WCHAR				pwcTemp[MAX_PATH*2];
	PBYTE				pbProfileData;
	DWORD				dwDisposition;
#ifndef _WIN32_WCE
	PBYTE				pbCompPassword;
#endif // _WIN32_WCE
	PBYTE				pbUserPassword;
	SW2_PROFILE_DATA	ProfileData2;
	DWORD				i = 0;
	DWORD				dwRet;

	dwRet = NO_ERROR;

 	//
	// First let's make a copy of the profile data 
	// we wish to write to the registry
	//
	memcpy( &ProfileData2, &ProfileData, sizeof( ProfileData ) );

	//
	// Clear CA List
	//
	for( i = 0; i < AA_MAX_CA; i++ )
		memset( ProfileData2.pbTrustedRootCAList[i], 0, 20 );

	ProfileData2.dwNrOfTrustedRootCAInList = 0;

	//
	// Clear computer credentials
	//
#ifndef _WIN32_WCE
	memset( ProfileData2.pwcCompPassword, 0, sizeof( ProfileData2.pwcCompPassword ) );
#endif // _WIN32_WCE

	//
	// Clear user credentials
	//
	memset( ProfileData2.pwcUserName, 0, sizeof( ProfileData2.pwcUserName ) );
	memset( ProfileData2.pwcUserPassword, 0, sizeof( ProfileData2.pwcUserPassword ) );
	memset( ProfileData2.pwcUserDomain, 0, sizeof( ProfileData2.pwcUserDomain ) );

	memset( pwcTemp, 0, sizeof( pwcTemp ) );

	swprintf( pwcTemp, 
				TEXT( "%s\\%s" ), 
				AA_CLIENT_PROFILE_LOCATION,
				pwcProfileID );

	AA_TRACE( ( TEXT( "AA_WriteProfile: opening key: %s" ), pwcTemp ) );

	if( AA_CreateSecureKey( HKEY_LOCAL_MACHINE,
									pwcTemp,
									&hKeyLM,
									&dwDisposition ) == ERROR_SUCCESS )
	{
		AA_TRACE( ( TEXT( "AA_WriteProfile: writing %ld bytes" ), sizeof( ProfileData2 ) ) );

		if( ( dwRet = AA_XorData( ( PBYTE ) &ProfileData2, 
							sizeof( ProfileData2 ), 
							AA_SECRET, 
							( DWORD ) strlen( AA_SECRET ),
							&pbProfileData ) ) == NO_ERROR )
		{
			if( RegSetValueEx( hKeyLM,
								L"Data",
								0,
								REG_BINARY,
								pbProfileData,
								sizeof( ProfileData2 ) ) != ERROR_SUCCESS )
			{
				AA_TRACE( ( TEXT( "AA_WriteProfile: failed to write Data: %ld" ), GetLastError() ) );

				dwRet = ERROR_CANTOPEN;
			}

			free( pbProfileData );
		}

		RegCloseKey( hKeyLM );

		dwRet = AA_WriteCertificates( pwcProfileID,
										ProfileData );

		swprintf( pwcTemp, 
					TEXT( "%s\\%s\\Credentials" ), 
					AA_CLIENT_PROFILE_LOCATION,
					pwcProfileID );

#ifndef _WIN32_WCE

		//
		// Write the computer password
		//
		if( AA_CreateAdminKey( HKEY_LOCAL_MACHINE,
										pwcTemp,
										&hKeyLM,
										&dwDisposition ) == NO_ERROR )
		{
			AA_TRACE( ( TEXT( "AA_WriteProfile: created key: HKEY_LOCAL_MACHINE\\%s" ), pwcTemp ) );

			if( ( dwRet = AA_XorData( ( PBYTE ) ProfileData.pwcCompPassword, 
								sizeof( ProfileData.pwcCompPassword ), 
								AA_SECRET, 
								( DWORD ) strlen( AA_SECRET ),
								&pbCompPassword ) ) == NO_ERROR )
			{
				if( RegSetValueEx( hKeyLM,
									L"ComputerPassword",
									0,
									REG_BINARY,
									pbCompPassword,
									sizeof( ProfileData.pwcCompPassword ) ) != ERROR_SUCCESS )
				{
					dwRet = ERROR_CANTOPEN;
				}

				free( pbCompPassword );
			}

			RegCloseKey( hKeyLM );
		}
#endif // _WIN32_WCE

	}
	else
		dwRet = ERROR_CANTOPEN;

	memset( &ProfileData2, 0, sizeof( ProfileData2 ) );

#ifndef _WIN32_WCE

	//
	// Check if we have a user token so we can read out Sid
	//
	if( hTokenImpersonateUser )
	{
		AA_TRACE( ( TEXT( "AA_WriteProfile::received impersonate token" ) ) );

		hToken = hTokenImpersonateUser;
	}
	else
	{
		if( !OpenThreadToken( GetCurrentThread(),
								TOKEN_QUERY,
								TRUE,
								&hToken ) )
		{
			AA_TRACE( ( TEXT( "AA_WriteProfile: FAILED to read user thread token: %ld" ), GetLastError() ) );

			hToken = NULL;

			//
			// Try by process
			//
			if( !OpenProcessToken( GetCurrentThread(),
									TOKEN_QUERY,
									&hToken ) )
			{
				AA_TRACE( ( TEXT( "AA_WriteProfile: FAILED to read user process token: %ld" ), GetLastError() ) );

				hToken = NULL;
			}
		}
	}

	if( hTokenImpersonateUser )
	{
		PBYTE		pbData;
		DWORD		cbData;
		PTOKEN_USER	pTokenUser;
		WCHAR		pwcSid[UNLEN];
		DWORD		cwcSid;

		cbData = 0;
					
		GetTokenInformation( hTokenImpersonateUser, 
								TokenUser,
								NULL,
								0,
								&cbData );

		if( ( pbData = ( PBYTE ) malloc( cbData ) ) )
		{
			if( GetTokenInformation( hTokenImpersonateUser, 
									TokenUser,
									pbData,
									cbData,
									&cbData ) )
			{
				cwcSid = sizeof( pwcSid );

				pTokenUser = ( PTOKEN_USER ) pbData;

				if( AA_GetTextualSid( pTokenUser->User.Sid,
									pwcSid,
									&cwcSid ) )
				{
					AA_TRACE( ( TEXT( "AA_WriteProfile: SID: %ws" ), pwcSid ) );

					memset( pwcTemp, 0, sizeof( pwcTemp ) );

					swprintf( pwcTemp, 
								TEXT( "%s\\%s\\%s\\Credentials" ), 
								pwcSid,
								AA_CLIENT_PROFILE_LOCATION,
								pwcProfileID );

					dwRet = RegCreateKeyEx(	HKEY_USERS, 
											pwcTemp, 
											0, 
											NULL, 
											0, 
											KEY_READ | KEY_WRITE, 
											NULL,
											&hKeyCU, 
											&dwDisposition );
				}
				else
				{
					AA_TRACE( ( TEXT( "AA_WriteProfile: AA_GetTextualSid FAILED: %ld" ), GetLastError() ) );		
					dwRet = ERROR_CANTOPEN;
				}
			}
			else
			{
				AA_TRACE( ( TEXT( "AA_WriteProfile: GetTokenInformation FAILED: %ld" ), GetLastError() ) );		
				dwRet = ERROR_CANTOPEN;
			}

			free( pbData );
		}
		else
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}
	else
	{
		swprintf( pwcTemp, 
				TEXT( "%s\\%s\\Credentials" ), 
				AA_CLIENT_PROFILE_LOCATION,
				pwcProfileID );

		dwRet = RegCreateKeyEx(	HKEY_CURRENT_USER, 
								pwcTemp, 
								0, 
								NULL, 
								0, 
								KEY_READ | KEY_WRITE, 
								NULL,
								&hKeyCU, 
								&dwDisposition );
	}

	if( dwRet != NO_ERROR )
	{
		//
		// Clear error and continue
		//
		dwRet = NO_ERROR;
	}
	else
	{
#else
	if( RegCreateKeyEx(	HKEY_CURRENT_USER, 
						pwcTemp, 
						0, 
						NULL, 
						0, 
						KEY_READ | KEY_WRITE, 
						NULL,
						&hKeyCU, 
						&dwDisposition ) == ERROR_SUCCESS )
	{
#endif // _WIN32_WCE
		AA_TRACE( ( TEXT( "AA_WriteProfile: created key: %s" ), pwcTemp ) );

		if( ( dwRet = AA_XorData( ( PBYTE ) ProfileData.pwcUserPassword, 
							sizeof( ProfileData.pwcUserPassword ), 
							AA_SECRET, 
							( DWORD ) strlen( AA_SECRET ),
							&pbUserPassword ) ) == NO_ERROR )
		{
			//
			// Save user configuration
			//
			//
			// PromptUser
			//
			if( RegSetValueEx( hKeyCU,
								L"PromptUser",
								0,
								REG_BINARY,
								( PBYTE ) &ProfileData.bPromptUser,
								1 ) != ERROR_SUCCESS )
			{
				dwRet = ERROR_CANTOPEN;
			}

			AA_TRACE( ( TEXT( "AA_WriteProfile: PromptUser: %ld" ), ProfileData.bPromptUser ) );

			//
			// Username
			//
			if( RegSetValueEx( hKeyCU,
								L"UserName",
								0,
								REG_EXPAND_SZ,
								( PBYTE ) ProfileData.pwcUserName,
								sizeof( ProfileData.pwcUserName ) ) != ERROR_SUCCESS )
			{
				dwRet = ERROR_CANTOPEN;
			}

			AA_TRACE( ( TEXT( "AA_WriteProfile: UserName(%ld): %s" ), sizeof( ProfileData.pwcUserName ), ProfileData.pwcUserName ) );

			//
			// Pasword
			//
			if( RegSetValueEx( hKeyCU,
								L"UserPassword",
								0,
								REG_BINARY,
								pbUserPassword,
								sizeof( ProfileData.pwcUserPassword ) ) != ERROR_SUCCESS )
			{
				dwRet = ERROR_CANTOPEN;
			}

			AA_TRACE( ( TEXT( "AA_WriteProfile: Password(%ld): %s" ), sizeof( ProfileData.pwcUserPassword ), ProfileData.pwcUserPassword ) );

			//
			// Domain
			//
			if( RegSetValueEx( hKeyCU,
								L"UserDomain",
								0,
								REG_EXPAND_SZ,
								( PBYTE ) ProfileData.pwcUserDomain,
								sizeof( ProfileData.pwcUserDomain ) ) != ERROR_SUCCESS )
			{
				dwRet = ERROR_CANTOPEN;
			}

			AA_TRACE( ( TEXT( "AA_WriteProfile: Domain(%ld): %s" ), sizeof( ProfileData.pwcUserDomain ), ProfileData.pwcUserDomain ) );

			free( pbUserPassword );
		}

		RegCloseKey( hKeyCU );
	}

	AA_TRACE( ( TEXT( "AA_WriteProfile: returning: %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: AA_ReadInnerEapMethod
// Description: Read the inner EAP information out of the registry
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
AA_ReadInnerEapMethod( IN DWORD dwEapType, 
						IN WCHAR *pwcCurrentProfileId, 
						OUT PSW2_INNER_EAP_CONFIG_DATA pInnerEapConfigData )
{
	HKEY		hKey;
	HKEY		hKeyConfig;
	DWORD		dwType;
	DWORD		dwDisposition;
	PBYTE		pbConfigData;
	DWORD		cbConfigData;
	WCHAR		pwcTemp[MAX_PATH];
	WCHAR		*pwcFriendlyName;
	DWORD		cwcFriendlyName;
	WCHAR		*pwcConfigUiPath;
	DWORD		cwcConfigUiPath;
	WCHAR		*pwcIdentityPath;
	DWORD		cwcIdentityPath;
	WCHAR		*pwcInteractiveUIPath;
	DWORD		cwcInteractiveUIPath;
	WCHAR		*pwcPath;
	DWORD		cwcPath;
	DWORD		dwRet;
	DWORD		dwErr = ERROR_SUCCESS;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "AA_ReadInnerEapMethod( %ld )" ), dwEapType ) );

	memset( pInnerEapConfigData, 0, sizeof( SW2_INNER_EAP_CONFIG_DATA ) );

	pInnerEapConfigData->dwEapType = dwEapType;

	swprintf( pwcTemp, L"%s\\%ld", EAP_EAP_METHOD_LOCATION, dwEapType );

	AA_TRACE( ( TEXT( "AA_ReadInnerEapMethod::path:%s" ), pwcTemp ) );

	if( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
						pwcTemp,
						0,
						KEY_QUERY_VALUE,
						&hKey ) == ERROR_SUCCESS )
	{
		AA_TRACE( ( TEXT( "AA_ReadInnerEapMethod::RegOpenKeyEx::success" ) ) );

		dwType = 0;

		//
		// Read friendly name
		//
		if( ( dwRet = AA_RegGetValue( hKey, 
										L"FriendlyName", 
										( PBYTE * ) &pwcFriendlyName, 
										&cwcFriendlyName ) ) == NO_ERROR )
		{
			if( ( wcslen( pwcFriendlyName ) > 0 ) && 
				( wcslen( pwcFriendlyName ) + ( 1 * sizeof( WCHAR ) ) < UNLEN ) )
			{
#ifdef _WIN32_WCE
				memcpy( pInnerEapConfigData->pwcEapFriendlyName, 
						pwcFriendlyName, cwcFriendlyName );
#else
				if( ExpandEnvironmentStrings( pwcFriendlyName, 
												pInnerEapConfigData->pwcEapFriendlyName,
												UNLEN ) > 0 )
				{
					AA_TRACE( ( TEXT( "AA_ReadInnerEapMethod: Friendly Name: %ws" ), pInnerEapConfigData->pwcEapFriendlyName ) );
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}
#endif // _WIN32_WCE
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}

			free( pwcFriendlyName );
		}

		//
		// Read ConfigUiPath
		//
		if( dwRet == NO_ERROR )
		{
			if( ( dwRet = AA_RegGetValue( hKey, 
										L"ConfigUiPath", 
										( PBYTE * ) &pwcConfigUiPath, 
										&cwcConfigUiPath ) ) == NO_ERROR )
			{
				if( ( wcslen( pwcConfigUiPath ) > 0 ) && 
					( wcslen( pwcConfigUiPath ) + ( 1 * sizeof( WCHAR ) ) < UNLEN ) )
				{
#ifdef _WIN32_WCE
					memcpy( pInnerEapConfigData->pwcEapConfigUiPath, pwcConfigUiPath, cwcConfigUiPath );
#else

					if( ExpandEnvironmentStrings( pwcConfigUiPath,
													pInnerEapConfigData->pwcEapConfigUiPath, UNLEN ) > 0 )
					{
						AA_TRACE( ( TEXT( "AA_ReadInnerEapMethod: ConfigUiPath: %ws" ), pInnerEapConfigData->pwcEapConfigUiPath ) );
					}
					else
					{
						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
#endif // _WIN32_WCE
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				free( pwcConfigUiPath );
			}
			else
			{
				//
				// If this failed it just means we cannot configure the
				// EAP method
				//
				dwRet = NO_ERROR;

				memset( pInnerEapConfigData->pwcEapConfigUiPath, 0, UNLEN );
			}
		}

		//
		// Read IdentityPath
		//
		if( dwRet == NO_ERROR )
		{
			if( ( dwRet = AA_RegGetValue( hKey, 
											L"IdentityPath", 
											( PBYTE * ) &pwcIdentityPath, 
											&cwcIdentityPath ) ) == NO_ERROR )
			{
				if( ( wcslen( pwcIdentityPath ) > 0 ) && 
					( wcslen( pwcIdentityPath ) + ( 1 * sizeof( WCHAR ) ) < UNLEN ) )
				{
#ifdef _WIN32_WCE
					memcpy( pInnerEapConfigData->pwcEapIdentityPath, pwcIdentityPath, cwcIdentityPath );
#else

					if( ExpandEnvironmentStrings( pwcIdentityPath, 
													pInnerEapConfigData->pwcEapIdentityPath, 
													UNLEN ) > 0 )
					{
						AA_TRACE( ( TEXT( "AA_ReadInnerEapMethod: IdentityPath: %ws" ), pInnerEapConfigData->pwcEapIdentityPath ) );
					}
					else
					{
						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
#endif // _WIN32_WCE
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				free( pwcIdentityPath );
			}
			else
			{
				//
				// If this failed it just means we cannot use this function with the
				// EAP method
				//
				dwRet = NO_ERROR;

				memset( pInnerEapConfigData->pwcEapIdentityPath, 0, UNLEN );
			}
		}

		//
		// Read InteractiveUIPath
		//
		if( dwRet == NO_ERROR )
		{
			if( ( dwRet = AA_RegGetValue( hKey, 
											L"InteractiveUIPath", 
											( PBYTE * ) &pwcInteractiveUIPath, 
											&cwcInteractiveUIPath ) ) == NO_ERROR )
			{
				if( ( wcslen( pwcInteractiveUIPath ) > 0 ) && 
					( wcslen( pwcInteractiveUIPath ) + ( 1 * sizeof( WCHAR ) ) < UNLEN ) )
				{
#ifdef _WIN32_WCE
					memcpy( pInnerEapConfigData->pwcEapInteractiveUIPath, 
							pwcInteractiveUIPath, 
							cwcInteractiveUIPath );
#else

					if( ExpandEnvironmentStrings( pwcInteractiveUIPath, 
													pInnerEapConfigData->pwcEapInteractiveUIPath, 
UNLEN ) > 0 )
					{
						AA_TRACE( ( TEXT( "AA_ReadInnerEapMethod: InteractiveUIPath: %ws" ), pInnerEapConfigData->pwcEapInteractiveUIPath ) );
					}
					else
					{
						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
#endif // _WIN32_WCE
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				free( pwcInteractiveUIPath );
			}
			else
			{
				//
				// If this failed it just means we cannot use this function with the
				// EAP method
				//
				dwRet = NO_ERROR;

				memset( pInnerEapConfigData->pwcEapIdentityPath, 0, UNLEN );
			}
		}

		//
		// Read Path
		//
		if( dwRet == NO_ERROR )
		{
			if( ( dwRet = AA_RegGetValue( hKey, 
										L"Path", 
										( PBYTE * ) 
										&pwcPath, 
										&cwcPath ) ) == NO_ERROR )
			{
				if( ( wcslen( pwcPath ) > 0 ) && 
					( wcslen( pwcPath ) + ( 1 * sizeof( WCHAR ) ) < UNLEN ) )
				{
#ifdef _WIN32_WCE
					memcpy( pInnerEapConfigData->pwcEapPath, pwcPath, cwcPath );
#else
					if( ExpandEnvironmentStrings( pwcPath, 
													pInnerEapConfigData->pwcEapPath, 
													UNLEN ) > 0 )
					{
						AA_TRACE( ( TEXT( "AA_ReadInnerEapMethod: Path: %ws" ), pInnerEapConfigData->pwcEapPath ) );
					}
					else
					{
						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}
#endif // _WIN32_WCE
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				free( pwcPath );
			}
		}

		if( dwRet == NO_ERROR )
		{
			pInnerEapConfigData->dwInvokeUsernameDlg = 0;

			if( AA_RegGetDWORDValue( hKey, 
									L"InvokeUsernameDialog", 
									&pInnerEapConfigData->dwInvokeUsernameDlg ) != NO_ERROR )
				pInnerEapConfigData->dwInvokeUsernameDlg = 0;

			AA_TRACE( ( TEXT( "AA_ReadInnerEapMethod: dwInvokeUsernameDlg: %ld" ), pInnerEapConfigData->dwInvokeUsernameDlg ) );

			if( AA_RegGetDWORDValue( hKey, 
									L"InvokePasswordDialog", 
									&pInnerEapConfigData->dwInvokePasswordDlg ) != NO_ERROR )
				pInnerEapConfigData->dwInvokePasswordDlg = 0;

			AA_TRACE( ( TEXT( "AA_ReadInnerEapMethod: dwInvokePasswordDlg: %ld" ), pInnerEapConfigData->dwInvokePasswordDlg ) );
		}

		//
		// Read configuration data
		//
		swprintf( pwcTemp, 
					L"%s\\%s\\%ld", 
					AA_CLIENT_PROFILE_LOCATION, 
					pwcCurrentProfileId,
					dwEapType );
		//
		// Create/Open Registry entry for this inner EAP module
		//
		if( dwRet == NO_ERROR )
		{
			AA_TRACE( ( TEXT( "AA_ReadInnerEapMethod: Path: %ws" ), pwcTemp ) );

			if( AA_CreateSecureKey( HKEY_LOCAL_MACHINE,
									pwcTemp,
									&hKeyConfig,
									&dwDisposition ) == ERROR_SUCCESS )
			{
				if( dwDisposition == REG_CREATED_NEW_KEY )
				{
					AA_TRACE( ( TEXT( "AA_ReadInnerEapMethod: created new key" ) ) );

					//
					// Create new empty config
					//
					memset( pInnerEapConfigData->pbConnectionData, 
							0,
							sizeof( pInnerEapConfigData->pbConnectionData ) );

					pInnerEapConfigData->cbConnectionData = 0;
				}
				else
				{
					AA_TRACE( ( TEXT( "AA_ReadInnerEapMethod: reading previous key" ) ) );

					//
					// Load previous config if any else create new config
					//
					if( ( dwRet = AA_RegGetValue( hKeyConfig, 
												L"ConfigData", 
												&pbConfigData,
												&cbConfigData ) ) == NO_ERROR )
					{
						AA_TRACE( ( TEXT( "AA_ReadInnerEapMethod: found configdata(%ld)" ), cbConfigData ) );

						if( cbConfigData <= EAP_MAX_INNER_DATA )
						{
							pInnerEapConfigData->cbConnectionData = cbConfigData;

							memcpy( pInnerEapConfigData->pbConnectionData,
									pbConfigData,
									pInnerEapConfigData->cbConnectionData );
						}
						else
							dwRet = ERROR_NOT_ENOUGH_MEMORY;

						free( pbConfigData );

						cbConfigData = 0;
					}

					if( dwRet != NO_ERROR )
					{
						//
						// Couldn't read config so default back to empty config
						// reset error
						//
						dwRet = NO_ERROR;

						memset( pInnerEapConfigData->pbConnectionData, 
								0,
								sizeof( pInnerEapConfigData->pbConnectionData ) );

						pInnerEapConfigData->cbConnectionData = 0;
					}
				}

				RegCloseKey( hKeyConfig );
			}
		}

		RegCloseKey( hKey );
	}
	else
		dwRet = ERROR_CANTOPEN;

	AA_TRACE( ( TEXT( "AA_ReadInnerEapMethod: returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: AA_WriteInnerEapMethod
// Description: Write the inner EAP information to the registry
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
AA_WriteInnerEapMethod( IN DWORD dwEapType, 
						IN WCHAR *pwcCurrentProfileId,
						IN OUT SW2_INNER_EAP_CONFIG_DATA InnerEapConfigData )
{
	HKEY		hKey;
	WCHAR		pwcTemp[1024];
	DWORD		dwRet;
	DWORD		dwDisposition;
	DWORD		dwErr = ERROR_SUCCESS;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "AA_WriteInnerEapMethod( %ld )" ), dwEapType ) );

	//
	// Write configuration data
	//
	swprintf( pwcTemp, 
				L"%s\\%s\\%ld", 
				AA_CLIENT_PROFILE_LOCATION, 
				pwcCurrentProfileId,
				dwEapType );

	//
	// Open Registry entry for this inner EAP module
	//
	AA_TRACE( ( TEXT( "AA_WriteInnerEapMethod: Path: %ws" ), pwcTemp ) );

	if( AA_CreateSecureKey( HKEY_LOCAL_MACHINE,
							pwcTemp,
							&hKey,
							&dwDisposition ) == ERROR_SUCCESS )
	{
		//
		// Save previous config if any else create new config
		//
		if( RegSetValueEx( hKey,
							L"ConfigData",
							0,
							REG_BINARY,
							InnerEapConfigData.pbConnectionData,
							InnerEapConfigData.cbConnectionData ) != ERROR_SUCCESS )
		{
			dwRet = ERROR_CANTOPEN;
		}
		else
			AA_TRACE( ( TEXT( "AA_WriteInnerEapMethod: wrote InnerEapConfigData.cbConnectionData(%ld)" ), InnerEapConfigData.cbConnectionData ) );

		RegCloseKey( hKey );
	}
	else
		dwRet = ERROR_CANTOPEN;

	AA_TRACE( ( TEXT( "AA_WriteInnerEapMethod: returning %ld" ), dwRet ) );

	return ERROR_NOT_ENOUGH_MEMORY;
}