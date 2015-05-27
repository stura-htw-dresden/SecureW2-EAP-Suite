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
#include <Setupapi.h>
#include <lmcons.h>
#include <shlwapi.h>
#include <Netprov.h>

#include "..\..\..\..\Common\release 3\version 0\source\Common.h"
#include "..\..\..\..\WZCLib\release 2\version 0\source\WZCLib.h"

#include "resource.h"

#include "exdll.h"

HINSTANCE	g_hInstance;

DWORD
AA_GetWZCVersion( DWORD	*pdwVersion )
{
	VS_FIXEDFILEINFO*	pvsFileInfo;
	DWORD				dwvsFileInfoSize;
	PBYTE				pbVersion;
	DWORD				dwHandle = 0;
	DWORD				cbVersion;
	DWORD				dwRet;

	dwRet = NO_ERROR;

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
				if( pvsFileInfo->dwProductVersionLS == 143857554 )
				{
					*pdwVersion = WZCS_DLL_VERSION_5_0_6034; // Windows 2000 SP3 + hotfix
				}
				else if( pvsFileInfo->dwProductVersionLS == 143858124 )
				{
					*pdwVersion = WZCS_DLL_VERSION_5_0_6604; // Windows 2000 SP4
				}
				else if( pvsFileInfo->dwProductVersionLS == 170393600 )
				{
					*pdwVersion = WZCS_DLL_VERSION_5_1_2600; // Windows XP SP0
				}
				else if( pvsFileInfo->dwProductVersionLS == 170394706 )
				{
					*pdwVersion = WZCS_DLL_VERSION_5_1_2600_1106; // Windows XP SP1
				}
				else if( pvsFileInfo->dwProductVersionLS == 170394781 )
				{
					*pdwVersion = WZCS_DLL_VERSION_5_1_2600_1181; // Windows XP SP1 + WPA
				}
				else if( pvsFileInfo->dwProductVersionLS >= 170395749 )
				{
					*pdwVersion = WZCS_DLL_VERSION_5_1_2600_2149; // Windows XP SP2 Release candidate 2
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

	return dwRet;
}

DWORD
AA_InstallCertificate( HINF hInf, WCHAR *pwcCertificate, DWORD iCount )
{
	HANDLE			hFile;
	PCCERT_CONTEXT	pCertContext;
	HCERTSTORE		hCertStore;
	WCHAR			pwcLocation[1024];
	DWORD			cwcLocation;
	BYTE			pbBuffer[8096];
	DWORD			cbBuffer;
	DWORD			dwRet;

	dwRet = NO_ERROR;

	if( SetupGetLineText( NULL,
							hInf,
							L"Certificates",
							pwcCertificate,
							pwcLocation,
							sizeof( pwcLocation ),
							&cwcLocation ) )
	{
		if( ( hFile = CreateFile( pwcLocation,
								GENERIC_READ,
								0,
								NULL,
								OPEN_EXISTING,
								FILE_ATTRIBUTE_NORMAL,
								NULL ) ) != INVALID_HANDLE_VALUE )
		{
			cbBuffer = 0;

			memset( pbBuffer, 0, sizeof( pbBuffer ) );

			if( ReadFile( hFile,
							pbBuffer,
							sizeof( pbBuffer ),
							&cbBuffer,
							NULL ) )
			{
				if( ( pCertContext = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
																pbBuffer, 
																cbBuffer) ) )
				{
					//
					// If this is the first certificate in line (server certificate) then 
					// put it in the MY store, else in the ROOT (CA certificate
					//
					if( iCount == 0 )
					{
						hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM,
													X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
													( HCRYPTPROV  ) NULL, 
													CERT_SYSTEM_STORE_LOCAL_MACHINE,
													L"MY" );
					}
					else
					{
						hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM,
													X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
													( HCRYPTPROV  ) NULL, 
													CERT_SYSTEM_STORE_LOCAL_MACHINE,
													L"ROOT" );
					}

					if( hCertStore )
					{
						if( !CertAddCertificateContextToStore( hCertStore, 
																pCertContext, 
																CERT_STORE_ADD_NEW, 
																NULL ) )
						{
							if(  GetLastError() ==  CRYPT_E_EXISTS )
							{
								//
								// Certificate already exists
								//
							}
							else
								dwRet = ERROR_CANTREAD;
						}

						CertCloseStore( hCertStore, CERT_CLOSE_STORE_FORCE_FLAG );
					}
					else
					{

						dwRet = ERROR_CANTREAD;
					}

					CertFreeCertificateContext( pCertContext );

					pCertContext = NULL;
				}
				else
				{
					dwRet = ERROR_CANTREAD;
				}
			}
			else
				dwRet = ERROR_CANTREAD;

			CloseHandle( hFile );
		}
		else
		{
			dwRet = ERROR_CANTOPEN;
		}
	}
	else
	{
		//
		// If this was a Certificate.0 operation this may fail when
		// trying to open as it is not necesarry to install the server certificate
		//
		if( iCount > 0 )
			dwRet = ERROR_NO_DATA;
	}

	return dwRet;
}

INT_PTR
CALLBACK
InstallDlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
   PSW2_PROFILE_DATA	pProfileData;
   WCHAR				pwcTemp[UNLEN];
   WCHAR				pwcPassword2[PWLEN];

    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			pProfileData = ( PSW2_PROFILE_DATA ) lParam;

			SetWindowText( GetDlgItem( hWnd, IDC_INSTALL_PROFILE ), pProfileData->pwcCurrentProfileId );

			if( wcslen( pProfileData->pwcProfileDescription ) > 0 )
			{
				EnableWindow( GetDlgItem( hWnd, IDC_INSTALL_DOMAIN ), FALSE );
				SetWindowText( GetDlgItem( hWnd, IDC_PROFILE_DESCRIPTION ), pProfileData->pwcProfileDescription );
			}

			SetWindowText( GetDlgItem( hWnd, IDC_INSTALL_DOMAIN ), pProfileData->pwcUserDomain );

			SetFocus( GetDlgItem( hWnd, IDC_INSTALL_USERNAME ) );

			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pProfileData );

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_INSTALL_USERNAME:

					if( HIWORD( wParam ) == EN_CHANGE )
					{
						if( GetWindowText( GetDlgItem( hWnd, IDC_INSTALL_USERNAME ), pwcTemp, UNLEN ) > 0 )
						{
							if( wcschr( pwcTemp, '@' ) )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_INSTALL_DOMAIN_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_INSTALL_DOMAIN ), FALSE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_INSTALL_DOMAIN_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_INSTALL_DOMAIN ), TRUE );
							}
						}
					}

					return FALSE;

				break;

				case IDOK:

					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );


					//
					//
					// Both the username and password must be filled in, domain is optional
					//
					//
					// Username
					//
					if( GetWindowTextLength( GetDlgItem( hWnd, IDC_INSTALL_USERNAME ) ) > 0 )
					{
						GetWindowText( GetDlgItem( hWnd, IDC_INSTALL_USERNAME ), pProfileData->pwcUserName, UNLEN );

						//
						// Password
						//
						if( GetWindowTextLength( GetDlgItem( hWnd, IDC_INSTALL_PASSWORD2 ) ) > 0 )
						{
							GetWindowText( GetDlgItem( hWnd, IDC_INSTALL_PASSWORD ), pProfileData->pwcUserPassword, PWLEN );

							if( GetWindowTextLength( GetDlgItem( hWnd, IDC_INSTALL_PASSWORD2 ) ) > 0 )
							{
								GetWindowText( GetDlgItem( hWnd, IDC_INSTALL_PASSWORD2 ), pwcPassword2, PWLEN );							

								if( wcscmp( pProfileData->pwcUserPassword, pwcPassword2 ) == 0 )
								{
									//
									// Domain
									//
									GetWindowText( GetDlgItem( hWnd, IDC_INSTALL_DOMAIN ), pProfileData->pwcUserDomain, UNLEN );

									EndDialog( hWnd, TRUE );
								}
								else
								{
									MessageBox( hWnd, L"Password mismatch", L"SecureW2", MB_OK | MB_ICONWARNING );
								}
							}
						}
						else
						{
							MessageBox( hWnd, L"Please re-enter your password", L"SecureW2", MB_OK | MB_ICONWARNING );
						}
					}
					
					return TRUE;

				break;

				case IDCANCEL:

					EndDialog( hWnd, FALSE );

				default:

					return FALSE;

				break;

			}

		break;

		default:

			return FALSE;

		break;

    }

    return FALSE;
}

DWORD
AA_ReadProfileConfig( HWND hWnd, HINF hInf, WCHAR *pwcProfile )
{
	PBYTE				pbData;
	WCHAR				pwcBuffer[1024];
	WCHAR				pwcTemp[1024];	
	CHAR				pcBuffer[1024];
	DWORD				ccBuffer = 0;
	SW2_PROFILE_DATA	SW2ProfileData;
	int					i = 0;
	DWORD				dwRet;

	dwRet = NO_ERROR;

	//
	// Profile Name
	//
	AA_InitDefaultProfile( &SW2ProfileData );

	ccBuffer = sizeof( SW2ProfileData.pwcCurrentProfileId );

	if( SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"Name",
							SW2ProfileData.pwcCurrentProfileId,
							sizeof( SW2ProfileData.pwcCurrentProfileId ),
							&ccBuffer ) )
	{
		memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

		ccBuffer = sizeof( SW2ProfileData.pwcProfileDescription );

		//
		// Description
		//
		SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"Description",
							SW2ProfileData.pwcProfileDescription,
							sizeof( SW2ProfileData.pwcProfileDescription ),
							&ccBuffer );

		//
		// Connection configuration
		//

		ccBuffer = sizeof( pwcBuffer );

		//
		// UseAlternateIdentity
		//
		if( SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"UseAlternateIdentity",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&ccBuffer ) )
		{
			if( wcscmp( _wcsupr( pwcBuffer ), L"TRUE" ) == 0 )
				SW2ProfileData.bUseAlternateOuter = TRUE;
			else
				SW2ProfileData.bUseAlternateOuter = FALSE;
		}

		memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

		ccBuffer = sizeof( pwcBuffer );

		//
		// UseAnonymousIdentity 
		//
		if( SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"UseAnonymousIdentity",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&ccBuffer ) )
		{
			if( wcscmp( _wcsupr( pwcBuffer ), L"TRUE" ) == 0 )
				SW2ProfileData.bUseAlternateAnonymous = TRUE;
			else
				SW2ProfileData.bUseAlternateAnonymous = FALSE;
		}

		ccBuffer = sizeof( SW2ProfileData.pwcAlternateOuter );

		//
		// AlternateOuterIdentity  
		//
		if( !SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"AlternateOuterIdentity",
							SW2ProfileData.pwcAlternateOuter,
							sizeof( SW2ProfileData.pwcAlternateOuter ),
							&ccBuffer ) )
			memset( SW2ProfileData.pwcAlternateOuter, 0, sizeof( SW2ProfileData.pwcAlternateOuter ) );

		memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

		ccBuffer = sizeof( pwcBuffer );

		//
		// EnableSessionResumption 
		//
		if( SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"EnableSessionResumption",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&ccBuffer ) )
		{
			if( wcscmp( _wcsupr( pwcBuffer ), L"TRUE" ) == 0 )
				SW2ProfileData.bUseSessionResumption = TRUE;
			else
				SW2ProfileData.bUseSessionResumption = FALSE;
		}

		memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

		ccBuffer = sizeof( pwcBuffer );

		//
		// VerifyServerCertificate 
		//
		if( SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"VerifyServerCertificate",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&ccBuffer ) )
		{
			if( wcscmp( _wcsupr( pwcBuffer ), L"TRUE" ) == 0 )
				SW2ProfileData.bVerifyServer = TRUE;
			else
				SW2ProfileData.bVerifyServer = FALSE;
		}

		for( i=0; i < AA_MAX_CA; i++ )
		{
			swprintf( pwcTemp, L"TrustedRootCA.%d", i );

			memset( pwcBuffer, 0, sizeof( pwcBuffer ) );
			ccBuffer = sizeof( pwcBuffer );

			//
			// TrustedRootAuthorities
			//
			if( SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								pwcTemp,
								pwcBuffer,
								sizeof( pwcBuffer ),
								&ccBuffer ) )
			{
				//
				// Is a hex representation of a 20 byte SHA1 has of the CA certificate
				//
				if( ( WideCharToMultiByte( CP_ACP, 0, pwcBuffer, -1, pcBuffer, sizeof( pcBuffer ), NULL, NULL ) ) > 0 )
				{
					if( ( pbData = AA_HexToByte( ( PCHAR ) pcBuffer, &ccBuffer ) ))
					{
						memcpy( SW2ProfileData.pbTrustedRootCAList[i], pbData, sizeof( SW2ProfileData.pbTrustedRootCAList[i] ) );

						SW2ProfileData.dwNrOfTrustedRootCAInList++;

						free( pbData );
					}
				}
			}
		}

		ccBuffer = sizeof( SW2ProfileData.pwcServerName );

		//
		// VerifyServerName 
		//
		if( SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"VerifyServerName",
							SW2ProfileData.pwcServerName,
							sizeof( SW2ProfileData.pwcServerName ),
							&ccBuffer ) )
		{
			SW2ProfileData.bVerifyServerName = TRUE;
		}
		else
			memset( SW2ProfileData.pwcServerName, 0, sizeof( SW2ProfileData.pwcServerName ) );

		ccBuffer = sizeof( SW2ProfileData.pwcInnerAuth );

		//
		// AuthenticationMethod  
		//
		if( !SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"AuthenticationMethod",
							SW2ProfileData.pwcInnerAuth,
							sizeof( SW2ProfileData.pwcInnerAuth ),
							&ccBuffer ) )
			wcscpy( SW2ProfileData.pwcInnerAuth, L"PAP" );

		memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

		ccBuffer = sizeof( pwcBuffer );

		//
		// EAPType
		//
		if( SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"EAPType",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&ccBuffer ) )
		{
			SW2ProfileData.dwCurrentInnerEapMethod = _wtol( pwcBuffer );
		}
		else
			SW2ProfileData.dwCurrentInnerEapMethod = 0;


		//
		// User account
		//

		memset( pwcBuffer, 0, sizeof( pwcBuffer ) );
		ccBuffer = sizeof( pwcBuffer );

		//
		// PromptUserForCredentials 
		//
		if( SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"PromptUserForCredentials",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&ccBuffer ) )
		{
			if( wcscmp( _wcsupr( pwcBuffer ), L"TRUE" ) == 0 )
				SW2ProfileData.bPromptUser = TRUE;
			else
				SW2ProfileData.bPromptUser = FALSE;
		}

		ccBuffer = sizeof( SW2ProfileData.pwcUserName );

		//
		// UserName 
		//
		if( !SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"UserName",
							SW2ProfileData.pwcUserName,
							sizeof( SW2ProfileData.pwcUserName ),
							&ccBuffer ) )
			memset( SW2ProfileData.pwcUserName, 0, sizeof( SW2ProfileData.pwcUserName ) );

		ccBuffer = sizeof( SW2ProfileData.pwcUserDomain );

		//
		// UserDomain 
		//
		if( !SetupGetLineText( NULL,
							hInf,
							pwcProfile,
							L"UserDomain",
							SW2ProfileData.pwcUserDomain,
							sizeof( SW2ProfileData.pwcUserDomain ),
							&ccBuffer ) )
			memset( SW2ProfileData.pwcUserDomain, 0, sizeof( SW2ProfileData.pwcUserDomain ) );

		if( wcscmp( SW2ProfileData.pwcUserName, L"PROMPTUSER" ) == 0 )
		{
			if( !DialogBoxParam( g_hInstance,
								MAKEINTRESOURCE( IDD_INSTALL_DLG ),
								hWnd,
								InstallDlgProc,
								( LPARAM ) &SW2ProfileData ) )
			{
				dwRet = ERROR_CANCELLED;
			}
		}
		else
		{
			ccBuffer = sizeof( SW2ProfileData.pwcUserPassword );

			//
			// UserPassword 
			//
			if( !SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"UserPassword",
								SW2ProfileData.pwcUserPassword,
								sizeof( SW2ProfileData.pwcUserPassword ),
								&ccBuffer ) )
				memset( SW2ProfileData.pwcUserPassword, 0, sizeof( SW2ProfileData.pwcUserPassword ) );
		}

		if( dwRet == NO_ERROR )
		{
			ccBuffer = sizeof( pwcBuffer );

			//
			// UseUserCredentialsForComputer  
			//
			if( SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"UseUserCredentialsForComputer",
								pwcBuffer,
								sizeof( pwcBuffer ),
								&ccBuffer ) )
			{
				if( wcscmp( _wcsupr( pwcBuffer ), L"TRUE" ) == 0 )
					SW2ProfileData.bUseCredentialsForComputer = TRUE;
				else
					SW2ProfileData.bUseCredentialsForComputer = FALSE;
			}

			memset( pwcBuffer, 0, sizeof( pwcBuffer ) );
			ccBuffer = sizeof( pwcBuffer );

			//
			// UseAlternateComputerCredentials
			//
			if( SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"UseAlternateComputerCredentials",
								pwcBuffer,
								sizeof( pwcBuffer ),
								&ccBuffer ) )
			{
				if( wcscmp( _wcsupr( pwcBuffer ), L"TRUE" ) == 0 )
					SW2ProfileData.bUseAlternateComputerCred = TRUE;
				else
					SW2ProfileData.bUseAlternateComputerCred = FALSE;
			}

			//
			// Computer account
			//
			ccBuffer = sizeof( SW2ProfileData.pwcCompName );

			//
			// ComputerUserName 
			//
			if( !SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"ComputerUserName",
								SW2ProfileData.pwcCompName,
								sizeof( SW2ProfileData.pwcCompName ),
								&ccBuffer ) )
				memset( SW2ProfileData.pwcCompName, 0, sizeof( SW2ProfileData.pwcCompName ) );

			ccBuffer = sizeof( SW2ProfileData.pwcCompPassword );

			//
			// ComputerPassword 
			//
			if( !SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"ComputerPassword",
								SW2ProfileData.pwcCompPassword,
								sizeof( SW2ProfileData.pwcCompPassword ),
								&ccBuffer ) )
				memset( SW2ProfileData.pwcCompPassword, 0, sizeof( SW2ProfileData.pwcCompPassword ) );

			ccBuffer = sizeof( SW2ProfileData.pwcCompDomain );

			//
			// ComputerDomain 
			//
			if( !SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"ComputerDomain",
								SW2ProfileData.pwcCompDomain,
								sizeof( SW2ProfileData.pwcCompDomain ),
								&ccBuffer ) )
				memset( SW2ProfileData.pwcCompDomain, 0, sizeof( SW2ProfileData.pwcCompDomain ) );

			memset( pwcBuffer, 0, sizeof( pwcBuffer ) );
			ccBuffer = sizeof( pwcBuffer );

			//
			// ServerCertificateOnLocalComputer	 
			//
			if( SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"ServerCertificateOnLocalComputer",
								pwcBuffer,
								sizeof( pwcBuffer ),
								&ccBuffer ) )
			{
				if( wcscmp( _wcsupr( pwcBuffer ), L"TRUE" ) == 0 )
					SW2ProfileData.bServerCertificateLocal = TRUE;
				else
					SW2ProfileData.bServerCertificateLocal = FALSE;
			}

			memset( pwcBuffer, 0, sizeof( pwcBuffer ) );
			ccBuffer = sizeof( pwcBuffer );

			//
			// CheckForMicrosoftExtension  
			//
			if( SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"CheckForMicrosoftExtension",
								pwcBuffer,
								sizeof( pwcBuffer ),
								&ccBuffer ) )
			{
				if( wcscmp( _wcsupr( pwcBuffer ), L"TRUE" ) == 0 )
					SW2ProfileData.bVerifyMSExtension = TRUE;
				else
					SW2ProfileData.bVerifyMSExtension = FALSE;
			}

			memset( pwcBuffer, 0, sizeof( pwcBuffer ) );
			ccBuffer = sizeof( pwcBuffer );

			//
			// AllowNewConnections   
			//
			if( SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"AllowNewConnections",
								pwcBuffer,
								sizeof( pwcBuffer ),
								&ccBuffer ) )
			{
				if( wcscmp( _wcsupr( pwcBuffer ), L"TRUE" ) == 0 )
					SW2ProfileData.bAllowNewConnection = TRUE;
				else
					SW2ProfileData.bAllowNewConnection = FALSE;
			}

			memset( pwcBuffer, 0, sizeof( pwcBuffer ) );
			ccBuffer = sizeof( pwcBuffer );

			//
			// RenewIPAddress    
			//
			if( SetupGetLineText( NULL,
								hInf,
								pwcProfile,
								L"RenewIPAddress",
								pwcBuffer,
								sizeof( pwcBuffer ),
								&ccBuffer ) )
			{
				if( wcscmp( _wcsupr( pwcBuffer ), L"TRUE" ) == 0 )
					SW2ProfileData.bRenewIP = TRUE;
				else
					SW2ProfileData.bRenewIP = FALSE;
			}

			AA_WriteProfile( SW2ProfileData.pwcCurrentProfileId, NULL, SW2ProfileData );
		}
	}
	else
		dwRet = ERROR_NO_DATA;

	return dwRet;
}

DWORD
AA_ReadSSIDConfig( HINF hInf, WCHAR *pwcSSIDProfile )
{
	WCHAR					pwcSSID[32];
	WCHAR					pwcProfile[UNLEN];
	DWORD					ccBuffer;
	PAA_WZC_LIB_CONTEXT		pWZCContext;
	AA_WZC_LIB_ADAPTERS		Adapters;
	int						i;
	DWORD					dwRet;
#ifndef AA_WZC_LIB_XP_SP2
	WZC_WLAN_CONFIG			WZCCfg;
#else
	HKEY					hKey1;
	HKEY					hKey2;
	CHAR					pcSSID[UNLEN];
	DWORD					ccSSID;
	CHAR					pcRegSSID[32];
	BYTE					pb8021X[] = {
										0x5,0x0,0x0,0x0,
										0x0,0x0,0x0,0x0,
										0x0,0x0,0x0,0xc0, // IEEE802.1x: 0x40=disable IEEE802.1x, 0x80=disable the two lower checkboxes
										0x15,0x0,0x0,0x0,// AUTH SELECTION: 0x15=SecureW2,0xd=standard smartcard stuff
										};
	BYTE					pbUnknown1[] = 	{ 
									0x0D,0x0,0x0,0x0,// End of SSID?
									0x28,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x28,0x0,0x0,0x0,
									0x5,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x0,0x0,0x0,0x0,
									0x15,0x0,0x0,0x0,
									0x8,0x2,0x0,0x0,
									0x0,0x0,0x0,0x0,  // these 4 bytes differ from machine to machine, but appear not to be relevant
									0x0,0x0,0x0,0x0 
									};
	BYTE					pbConnectionData[516];
	PBYTE					pbReg;
	DWORD					cbReg;
	ULONG					ulStatus = 0;
	GUID					guid;
	HRESULT					hrInit = S_OK;
	HRESULT					hr = S_OK;
	IProvisioningProfileWireless *pIProvisioningProfileWireless;
	WCHAR					*pwcXMLTemplate;
	DWORD					ccXMLTemplate;
	DWORD					dwLen = 0;
	WCHAR					pwcEapEntryName[UNLEN];
	BYTE					pbEapEntryValue[1024];
	DWORD					cbEapEntryValue;
	DWORD					dwEapEntryType;
	int						j;
	DWORD					dwSSIDLength;
	CHAR					pcSSIDValue[32];
#endif // AA_WZC_LIB_XP_SP2

	dwRet = NO_ERROR;

	if( SetupGetLineText( NULL,
							hInf,
							pwcSSIDProfile,
							L"Name",
							pwcSSID,
							sizeof( pwcSSID ),
							&ccBuffer ) )
	{
		if( SetupGetLineText( NULL,
								hInf,
								pwcSSIDProfile,
								L"Profile",
								pwcProfile,
								sizeof( pwcProfile ),
								&ccBuffer ) )
		{
			if( ( dwRet = WZCInit( &pWZCContext ) ) == NO_ERROR )
			{
				if( ( dwRet = WZCEnumAdapters( pWZCContext, &Adapters ) ) == NO_ERROR )
				{
#ifdef AA_WZC_LIB_XP_SP2
					ccXMLTemplate = ( ( DWORD ) wcslen( L"<?xml version=\"1.0\"?><wp:WirelessProfile xmlns=\"http://www.microsoft.com/provisioning/WirelessProfile\" xmlns:wp=\"http://www.microsoft.com/provisioning/WirelessProfile\"><wp:version>1</wp:version><wp:ssid></wp:ssid><wp:connectionType>ESS</wp:connectionType><wp:authentication>Open</wp:authentication><wp:encryption>WEP</wp:encryption><wp:keyProvidedAutomatically>true</wp:keyProvidedAutomatically><wp:IEEE802.1XEnabled>true</wp:IEEE802.1XEnabled><wp:EAPMethod>PEAP</wp:EAPMethod></wp:WirelessProfile>" )
										+ ( ( DWORD ) wcslen( pwcSSID ) + 1 ) ) * sizeof( WCHAR );

					AA_TRACE( ( TEXT( "allocating %ld bytes for pwcXMLTemplate" ), ccXMLTemplate ) );

					if( ( pwcXMLTemplate = ( WCHAR* ) malloc( ccXMLTemplate ) ) )
					{
						AA_TRACE( ( TEXT( "allocated" ) ) );

						memset( pcRegSSID, 0, sizeof( pcRegSSID ) );

						if( ( WideCharToMultiByte( CP_ACP, 0, pwcSSID, -1, pcSSID, sizeof( pcSSID ), NULL, NULL ) ) > 0 )
						{
							memcpy( pcRegSSID, pcSSID, strlen( pcSSID ) );

							ccSSID = ( DWORD ) strlen( pcSSID );

							memset( pbConnectionData, 0, sizeof( pbConnectionData ) );
							memcpy( pbConnectionData, pwcProfile, ( wcslen( pwcProfile ) * sizeof( WCHAR ) ) );

							// length = 802.1X + SSIDLength + SSID + Unknown1
							cbReg = sizeof( pb8021X ) +sizeof( DWORD )+ sizeof( pcRegSSID ) + sizeof( pbUnknown1 ) + sizeof( pbConnectionData );

							if( ( pbReg = ( PBYTE ) malloc( cbReg ) ) )
							{
								memset( pbReg, 0, cbReg );

								memcpy( pbReg, pb8021X, sizeof( pb8021X ) );
								memcpy( pbReg + sizeof( pb8021X ), &ccSSID, sizeof( DWORD ) );
								memcpy( pbReg + sizeof( pb8021X ) + sizeof( DWORD ), pcRegSSID, sizeof( pcRegSSID ) );
								memcpy( pbReg + sizeof( pb8021X ) + sizeof( DWORD ) + sizeof( pcRegSSID ), pbUnknown1, sizeof( pbUnknown1 ) );
								memcpy( pbReg + sizeof( pb8021X ) + sizeof( DWORD ) + sizeof( pcRegSSID ) + sizeof( pbUnknown1 ), 
									pbConnectionData, sizeof( pbConnectionData ) );

								AA_TRACE( ( TEXT( "pbReg (%ld): %s" ), cbReg, AA_ByteToHex( pbReg, cbReg ) ) );

								//
								// Create SSID
								//
								memset( &guid, 0, sizeof( GUID ) );

								swprintf( pwcXMLTemplate, L"<?xml version=\"1.0\"?><wp:WirelessProfile xmlns=\"http://www.microsoft.com/provisioning/WirelessProfile\" xmlns:wp=\"http://www.microsoft.com/provisioning/WirelessProfile\"><wp:version>1</wp:version><wp:ssid>%s</wp:ssid><wp:connectionType>ESS</wp:connectionType><wp:authentication>Open</wp:authentication><wp:encryption>WEP</wp:encryption><wp:keyProvidedAutomatically>true</wp:keyProvidedAutomatically><wp:IEEE802.1XEnabled>true</wp:IEEE802.1XEnabled><wp:EAPMethod>PEAP</wp:EAPMethod></wp:WirelessProfile>", 
									pwcSSID );

								AA_TRACE( ( TEXT( "pwcXMLTemplate: %s" ), pwcXMLTemplate ) );

								//
								// Add to all adapters in list
								//
								for( i=0; ( DWORD ) i < Adapters.dwNumGUID; i++ )
								{
									if( pWZCContext->dwWZCSDllVersion >= WZCS_DLL_VERSION_5_1_2600_2149 )
									{
										hrInit = CoInitialize(NULL);

										if( hrInit == S_OK || hrInit == S_FALSE )
										{
											AA_TRACE( ( TEXT( "CoInitialize Succeeded" ) ) );

											if ( ( hr = CoCreateInstance(	&CLSID_NetProvisioning, 
																			NULL,
																			CLSCTX_ALL, 
																			&IID_IProvisioningProfileWireless, 
																			(void **)&pIProvisioningProfileWireless)) == S_OK  )
											{
												AA_TRACE( ( TEXT( "CoCreateInstance Succeeded" ) ) );

												CLSIDFromString( Adapters.pwcGUID[i],
																&guid );

												if( ( hr = pIProvisioningProfileWireless->lpVtbl->CreateProfile( pIProvisioningProfileWireless,
																												pwcXMLTemplate,
																												NULL,
																												&guid,
																												&ulStatus ) ) == S_OK )
												{
													AA_TRACE( ( TEXT( "CreateProfile succesfull" ) ) );
												}
												else
												{
													AA_TRACE( ( TEXT( "CreateProfile failed: %ld, status: %ld, %ld" ), hr, ulStatus, GetLastError() ) );

													// ignore error for time being
													// dwRet = ERROR_INVALID_DATA;
												}
											}

											if( hrInit == S_OK )
												CoUninitialize();
										}
										else
										{
											AA_TRACE( ( TEXT( "CoInitialize FAILED %ld, %ld" ), hr, GetLastError() ) );

											dwRet = ERROR_OPEN_FAILED;
										}

										if( dwRet == NO_ERROR )
										{
											AA_TRACE( ( TEXT( "adding EAP Entry" ) ) );

											if( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
															L"SOFTWARE\\Microsoft\\EAPOL\\Parameters\\Interfaces",
															0,
															KEY_ALL_ACCESS,
															&hKey1 ) == ERROR_SUCCESS )
											{
												AA_TRACE( ( TEXT( "Opened Interfaces entry" ) ) );

												if( RegOpenKeyEx( hKey1,
														Adapters.pwcGUID[i],
														0,
														KEY_QUERY_VALUE | KEY_SET_VALUE,
														&hKey2 ) == ERROR_SUCCESS )
												{
													AA_TRACE( ( TEXT( "Opened guid key: %s" ), Adapters.pwcGUID[i] ) );

													//
													// Loop through Eap Entry till we find an
													// entry with the same SSID or no more entries 
													// are found
													//
													j = 1;
													memset( pwcEapEntryName, 0, sizeof( pwcEapEntryName ) );
													wsprintf( pwcEapEntryName, L"%ld", j );
													cbEapEntryValue = sizeof( pbEapEntryValue );

													while( RegQueryValueEx( hKey2,
																			pwcEapEntryName,
																			NULL,
																			&dwEapEntryType,
																			pbEapEntryValue,
																			&cbEapEntryValue ) == ERROR_SUCCESS )
													{
														AA_TRACE( ( TEXT( "opened eap entry: %s, value: %ld" ), 
																						pwcEapEntryName, cbEapEntryValue ) );

														// Retreive SSID Length
														//
														memcpy( &dwSSIDLength, &( pbEapEntryValue[16] ), sizeof( dwSSIDLength ) );

														AA_TRACE( ( TEXT( "Retrieved dwSSIDLength: %ld" ), dwSSIDLength ) );

														memset( pcSSIDValue, 0, sizeof( pcSSIDValue ) );

														if( dwSSIDLength == ccSSID )
														{
															memcpy( pcSSIDValue, &( pbEapEntryValue[16 + sizeof( dwSSIDLength )] ), dwSSIDLength );

															if( strcmp( pcSSIDValue, pcRegSSID ) == 0 )
															{
																// found correct SSID
																AA_TRACE( ( TEXT( "SSID Value Match" ) ) );

																break;
															}
															else
															{
																AA_TRACE( ( TEXT( "SSID Value Mismatch" ) ) );
															}
														}
														else
															AA_TRACE( ( TEXT( "SSID Length MisMatch" ) ) );
				
														j++;
														memset( pwcEapEntryName, 0, sizeof( pwcEapEntryName ) );
														wsprintf( pwcEapEntryName, L"%ld", j );
														memset( pbEapEntryValue, 0, sizeof( pbEapEntryValue ) );
														cbEapEntryValue = sizeof( pbEapEntryValue );
													} // while

													AA_TRACE( ( TEXT( "setting entry %s" ), pwcEapEntryName ) );

													//
													// Write entry
													//
													if( RegSetValueEx( hKey2,
																	pwcEapEntryName,
																	0,
																	REG_BINARY,
																	pbReg,
																	cbReg ) != ERROR_SUCCESS )
													{
														AA_TRACE( ( TEXT( "Failed to set value: %ld" ), GetLastError() ));
													}

													RegCloseKey(hKey2);
												}
												else
													AA_TRACE( ( TEXT( "failed to open guid key: %ld" ), GetLastError() ) );

												RegCloseKey(hKey1);
											}
											else
											{
												AA_TRACE( ( TEXT( "failed to open interfaces key: %ld" ), GetLastError() ) );

												dwRet = ERROR_OPEN_FAILED;
											}
										}
										else
										{
											AA_TRACE( ( TEXT( "failed to open interfaces key: %ld" ), GetLastError() ) );
											
											dwRet = ERROR_OPEN_FAILED;
										}
									}
									else
										dwRet = ERROR_NOT_SUPPORTED;
								} // for

								free( pbReg );
							}
							else
								dwRet = ERROR_NOT_ENOUGH_MEMORY;
						}
						else
							dwRet = ERROR_NOT_ENOUGH_MEMORY;

						free( pwcXMLTemplate );
					}
					else
						dwRet = ERROR_NOT_ENOUGH_MEMORY;
#else
					if( ( dwRet = WZCInitConfig( pWZCContext, 
												&WZCCfg, 
												pwcSSID, 
												Ndis802_11Infrastructure ) ) == NO_ERROR )
					{
						//
						// Add to all adapters in list
						//
						for( i=0; ( DWORD ) i < Adapters.dwNumGUID; i++ )
						{
							if( ( dwRet = WZCAddPreferedConfig( pWZCContext, 
																Adapters.pwcGUID[i], 
																WZCCfg, 
																AA_WZC_LIB_CONFIG_PREF | AA_WZC_LIB_CONFIG_WEP,
																TRUE,
																FALSE ) ) == NO_ERROR )
							{
								SW2_CONFIG_DATA SW2ConfigData;

								memset( &SW2ConfigData, 0, sizeof( SW2ConfigData ) );

								memcpy( SW2ConfigData.pwcProfileId, pwcProfile, sizeof( pwcProfile ) );

								AA_TRACE( ( TEXT( "pwcProfile: %s" ), SW2ConfigData.pwcProfileId ) );

								dwRet = WZCSetConfigEapData( pWZCContext, 
															Adapters.pwcGUID[i], 
															pwcSSID, 
															21, 
															( PBYTE ) &SW2ConfigData, 
															sizeof( SW2ConfigData ) );
							}
						} // for
					}
#endif // AA_WZC_LIB_XP_SP2
				}

				WZCEnd( pWZCContext );
			}
		}
		else
			dwRet = ERROR_INVALID_DATA;
	}
	else
		dwRet = ERROR_NO_DATA;

	AA_TRACE( ( TEXT( "AA_ReadSSIDConfig returning: %ld" ), dwRet ) );

	return dwRet;
}

DWORD
AA_InstallGina( HINF hInf )
{
	WCHAR					pwcBuffer[1024];
	SW2_GINA_CONFIG_DATA	GinaConfigData;
	DWORD					ccBuffer;
	DWORD					dwRet;
	TCHAR					*pwcToken;
	int						i;

	dwRet = NO_ERROR;

	AA_InitDefaultGinaConfig( &GinaConfigData );

	memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

	if( SetupGetLineText( NULL,
							hInf,
							L"Gina",
							L"UseSecureW2Gina",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&ccBuffer ) )
	{
		if( wcscmp( _wcsupr( pwcBuffer ), L"TRUE" ) == 0 )
			GinaConfigData.bUseSW2Gina = TRUE;
		else
			GinaConfigData.bUseSW2Gina = FALSE;
	}

	if( GinaConfigData.bUseSW2Gina )
	{
		SetupGetLineText( NULL,
						hInf,
						L"Gina",
						L"GinaDomainName",
						GinaConfigData.pwcGinaDomainName,
						sizeof( GinaConfigData.pwcGinaDomainName ),
						&ccBuffer );

		AA_TRACE( ( TEXT( "AA_InstallGina::GinaDomainName: %s" ), GinaConfigData.pwcGinaDomainName ) );

		SetupGetLineText( NULL,
						hInf,
						L"Gina",
						L"GinaType",
						GinaConfigData.pwcGinaType,
						sizeof( GinaConfigData.pwcGinaType ),
						&ccBuffer );

		AA_TRACE( ( TEXT( "AA_InstallGina::GinaType: %s" ), GinaConfigData.pwcGinaType ) );

		memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

		if( SetupGetLineText( NULL,
					hInf,
					L"Gina",
					L"UseGinaVLAN",
					pwcBuffer,
					sizeof( pwcBuffer ),
					&ccBuffer ) )
		{
			if( wcscmp( _wcsupr( pwcBuffer ), L"TRUE" ) == 0 )
				GinaConfigData.bUseGinaVLAN = TRUE;
			else
				GinaConfigData.bUseGinaVLAN = FALSE;
		}

		if( GinaConfigData.bUseGinaVLAN )
		{
			memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

			if( SetupGetLineText( NULL,
								hInf,
								L"Gina",
								L"GinaVLANIPAddress",
								pwcBuffer,
								sizeof( pwcBuffer ),
								&ccBuffer ) )
			{
				AA_TRACE( ( TEXT( "AA_InstallGina: pwcBuffer: %s" ), pwcBuffer ) );

				pwcToken = _tcstok( pwcBuffer, TEXT( "." ) );

				i = 3;

				while( ( pwcToken != NULL )
					&& ( i > 0 ) )
				{
					AA_TRACE( ( TEXT( "AA_InstallGina: pwcToken : %s" ), pwcToken ) );

					( ( PBYTE ) &( GinaConfigData.dwGinaVLANIPAddress ) )[i] = _ttoi(pwcToken);

					pwcToken = _tcstok( NULL, TEXT( "." ) );

					i--;
				}

				AA_TRACE( ( TEXT( "AA_InstallGina: GinaConfigData.dwGinaVLANIPAddress: %ld" ), GinaConfigData.dwGinaVLANIPAddress ) );
			}

			memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

			if( SetupGetLineText( NULL,
								hInf,
								L"Gina",
								L"GinaVLANSubnetMask",
								pwcBuffer,
								sizeof( pwcBuffer ),
								&ccBuffer ) )
			{
				AA_TRACE( ( TEXT( "AA_InstallGina: pwcBuffer: %s" ), pwcBuffer ) );

				pwcToken = _tcstok( pwcBuffer, TEXT( "." ) );

				i = 3;

				while( ( pwcToken != NULL )
					&& ( i > 0 ) )
				{
					AA_TRACE( ( TEXT( "AA_InstallGina: pwcToken : %s" ), pwcToken ) );

					( ( PBYTE ) &( GinaConfigData.dwGinaVLANSubnetMask ) )[i] = _ttoi(pwcToken);

					pwcToken = _tcstok( NULL, TEXT( "." ) );

					i--;
				}

				AA_TRACE( ( TEXT( "AA_InstallGina: GinaConfigData.dwGinaVLANSubnetMask: %ld" ), GinaConfigData.dwGinaVLANSubnetMask ) );
			}
		}

		AA_WriteGinaConfig( &GinaConfigData );
	}

	return dwRet;
}

void 
__declspec ( dllexport )
Run( HWND hwndParent, 
	int string_size, 
	char *variables, 
	stack_t **stacktop )
{
	HINF					hInf;
	WCHAR					pwcBuffer[1024];
	WCHAR					pwcVersion[256];
	WCHAR					pwcTemp[1024];
	DWORD					ccBuffer = 0;
	DWORD					dwError;
	int						i = 0;
	DWORD					dwRet;
	
	dwRet = NO_ERROR;

	EXDLL_INIT();

	if( ( hInf = SetupOpenInfFile( L".\\SecureW2.inf", 
						NULL,
						INF_STYLE_WIN4,
						&dwError ) ) != INVALID_HANDLE_VALUE )
	{
		//
		// Read version and see if we are compatible
		//
		swprintf( pwcVersion, L"%ld", AA_CONFIG_VERSION );

		if( SetupGetLineText( NULL,
							hInf,
							L"Version",
							L"Config",
							pwcBuffer,
							sizeof( pwcBuffer ),
							&ccBuffer ) )
		{
			if( !wcscmp( pwcBuffer, pwcVersion ) )
			{
				//
				// We are compatible
				//
				memset( pwcBuffer, 0, sizeof( pwcBuffer ) );

				//
				// Can we start WZCSVC?
				//
				if( SetupGetLineText( NULL,
									hInf,
									L"WZCSVC",
									L"Enable",
									pwcBuffer,
									sizeof( pwcBuffer ),
									&ccBuffer ) )
				{
					if( wcscmp( _wcsupr( pwcBuffer ), L"TRUE" ) == 0 )
					{
						AA_StartWZCSVC(FALSE);
					}
					else if( wcscmp( _wcsupr( pwcBuffer ), L"AUTO" ) == 0 )
					{
						AA_StartWZCSVC(TRUE);
					}
				}

				//
				// Read and install certificates
				//
				for( i=0; dwRet == NO_ERROR; i++ )
				{
					swprintf( pwcBuffer, L"Certificate.%d", i );

					dwRet = AA_InstallCertificate( hInf, pwcBuffer, i );
				}

				//
				// Did we fail because we don't have any more profiles?
				//
				if( dwRet != NO_ERROR )
				{
					if( dwRet == ERROR_NO_DATA )
						dwRet = NO_ERROR;
					else
					{
						swprintf( pwcTemp, L"Failed to install certificate \"%ws\" (%ld)", pwcBuffer, dwRet );

						MessageBox( hwndParent, pwcTemp, L"SecureW2 Install Error", MB_OK | MB_ICONERROR );
					}
				}

				if( dwRet == NO_ERROR )
				{
					memset( pwcBuffer, 0, sizeof( pwcBuffer ) );
				
					//
					// Profiles
					//
					for( i=1; dwRet == NO_ERROR; i++ )
					{
						swprintf( pwcBuffer, L"Profile.%d", i );

						dwRet = AA_ReadProfileConfig( hwndParent, hInf, pwcBuffer );
					}

					//
					// Did we fail because we don't have any more profiles?
					//
					if( dwRet != NO_ERROR )
					{
						if( dwRet == ERROR_NO_DATA )
							dwRet = NO_ERROR;
						else
						{
							swprintf( pwcTemp, L"Failed reading config profile \"%ws\" (%ld)", pwcBuffer, dwRet );

							MessageBox( hwndParent, pwcTemp, L"SecureW2 Install Error", MB_OK | MB_ICONERROR );
						}
					}

					if( dwRet == NO_ERROR )
					{
						//
						// SSIDs
						//
						for( i=1; dwRet == NO_ERROR; i++ )
						{
							swprintf( pwcBuffer, L"SSID.%d", i );

							dwRet = AA_ReadSSIDConfig( hInf, pwcBuffer );
						}

						if( dwRet == ERROR_NO_DATA )
							dwRet = NO_ERROR;
						else if( dwRet == ERROR_NOT_SUPPORTED )
						{
							dwRet = NO_ERROR;

							swprintf( pwcTemp, L"This installer does not support Service Pack 2. Please configure SecureW2 manually" );

							MessageBox( hwndParent, pwcTemp, L"SecureW2 Install Alert", MB_OK | MB_ICONINFORMATION );
						}
						else
						{
							swprintf( pwcTemp, L"Failed setting SSID configuration (%ld)", dwRet );

							MessageBox( hwndParent, pwcTemp, L"SecureW2 Install Error", MB_OK | MB_ICONERROR );
						}
					}
				}

				if( dwRet == NO_ERROR )
					dwRet = AA_InstallGina( hInf );
			}
			else
			{
				swprintf( pwcTemp, L"Incorrect configuration version: \"%ws\", require version \"%ld\". Please verify your configuration file.", pwcBuffer, AA_CONFIG_VERSION );

				MessageBox( hwndParent, pwcTemp, L"SecureW2 Install Error", MB_OK | MB_ICONERROR );

				dwRet = ERROR_INVALID_DATA;
			}
		}
		else
		{
			MessageBox( hwndParent, L"Could not find required parameter \"Config\" in section \"Version\". Please verify your configuration file.", L"SecureW2 Install Error", MB_OK | MB_ICONERROR );

			dwRet = ERROR_INVALID_DATA;
		}

		SetupCloseInfFile( hInf );
	}

	if( dwRet != NO_ERROR )
		pushstring( "cancel" );
}

BOOL WINAPI
DllMain(	IN HINSTANCE   hInstance,
			IN DWORD       dwReason,
			IN LPVOID		lpVoid )
{
	g_hInstance = hInstance;

	return TRUE;
}