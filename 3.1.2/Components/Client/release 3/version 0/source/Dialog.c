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
// Name: Dialog.c
// Description: Contains the dialog functionality for the module
// Author: Tom Rixom
// Created: 17 December 2002
// Version: 1.0
// Last revision: 23 Januari 2004 
//
// ----------------------------- Revisions -------------------------------
//
// Revision - <Date of revision> <Version of file which has been revised> <Name of author>
// <Description of what has been revised>
//
// Added cert check - 21 Juli 2003 - Tom Rixom 
// Added extra certificate check. The server certificate must be installed
// in the computer "My" Store.
//
// Added "Install CA certificates" - 16 April 2003 - Tom Rixom
// All ca certifcates are installed in one go
//
// Added cert check - 21 Juli 2003 - Tom Rixom 
// Added extra certificate check. The server certificate must be installed
// in the computer "My" Store.
//
// FIX - 13 November 2003 - Tom Rixom
// Removed functionality that when updatecertificateview returned with error dialog was 
// cancelled
//
// Removed License from SecureW2 2 XP - 23 Januari 2004 - Tom Rixom
// SecureW2 PPC still needs a license
//
// Added Advanced button in user configuration - 23 Januari 2004 - Tom Rixom
//
// Added Profiles - 10 Februari 2004 - Tom Rixom
//
// Change look of SecureW2 - 21 April 2004 - Tom Rixom
// More advanced features are now in accessible through advanced button
// Moved advanced button to outer dialog
//
// User can now configure domain in which server certificate must reside - 21 April 2004 - Tom Rixom
//
// Removed button - 22 April 2004 - Tom Rixom
// "Allow non-admin to setup new connections" and replaced it with "Allow users..."
// Most users are admin of laptop making the previous option non-usable
//
// Addedd extra button - 22 April 2004 - Tom Rixom
// SecureW2 can now optionally check for localy installed server certificate 
//
// Removed temporary trust - 07 May 2004 - Tom Rixom
// SecureW2 can not be setup for "temporary connections" any more, to test connection user
// must disable "Verify Server Certificate"
//
// Wired and wireless removed - 07 May 2004 - Tom Rixom
// Done automaticly
//
// Added trusted Root CA  07 May 2004 - Tom Rixom
// Can only connect to a CA that is trusted
//

#include "Main.h"
#include <commctrl.h>
#include <Commdlg.h>
#ifdef _WIN32_WCE
#include <aygshell.h>
#endif // _WIN32_WCE

#ifdef _WIN32_WCE
//
// Name: AA_CreateCommandBar
// Description: In Windows CE this function makes the window 
//				work with the Windows CE interface
// Author: Tom Rixom
// Created: 12 May 2004
//
HWND AA_CreateCommandBar( HWND hWnd )
{
	SHMENUBARINFO mbi;

	memset( &mbi, 0, sizeof( SHMENUBARINFO ) );
	mbi.cbSize     = sizeof( SHMENUBARINFO );
	mbi.hwndParent = hWnd;
	mbi.hInstRes   = ghInstance;
	mbi.nBmpId     = 0;
	mbi.cBmpImages = 0;
	mbi.dwFlags = SHCMBF_EMPTYBAR;
	//mbi.nToolBarId = IDM_MENU;

	if( !SHCreateMenuBar( &mbi ) ) 
		return NULL;

	return mbi.hwndMB;
}
#endif // _WIN32_WCE

//
// Name: CredentialsDlgProc
// Description: Dialog Function for the Credentials Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
CredentialsDlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
   PSW2_USER_DATA	pUserData;
   WCHAR			pwcTemp[UNLEN];
#ifdef _WIN32_WCE
	SHINITDLGINFO	shidi;
#endif //  _WIN32_WCE

    switch( unMsg )
    {

		case WM_INITDIALOG:
        
			AA_TRACE( ( TEXT( "CredentialsDlgProc:: WM_INITDIALOG" ) ) );

			pUserData = ( PSW2_USER_DATA ) lParam;

			if( wcslen( pUserData->pwcUsername ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_CRED_USERNAME ), pUserData->pwcUsername );

			if( wcslen( pUserData->pwcDomain ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_CRED_DOMAIN ), pUserData->pwcDomain );

#ifdef _WIN32_WCE
			// Create a Done button and size it.  
			shidi.dwMask = SHIDIM_FLAGS;
			shidi.dwFlags = SHIDIF_DONEBUTTON | SHIDIF_SIPDOWN |SHIDIF_SIZEDLGFULLSCREEN;
			shidi.hDlg = hWnd;

			SHInitDialog( &shidi );

			AA_CreateCommandBar( hWnd );

			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pUserData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pUserData );
#endif // _WIN32_WCE

			SetFocus( GetDlgItem( hWnd, IDC_CRED_USERNAME ) );

			AA_TRACE( ( TEXT( "CredentialsDlgProc:: WM_INITDIALOG:: returning" ) ) );

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_CRED_USERNAME:

					if( HIWORD( wParam ) == EN_CHANGE )
					{
						if( GetWindowText( GetDlgItem( hWnd, IDC_CRED_USERNAME ), pwcTemp, UNLEN ) > 0 )
						{
							if( wcschr( pwcTemp, '@' ) )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CRED_DOMAIN_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CRED_DOMAIN ), FALSE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CRED_DOMAIN_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CRED_DOMAIN ), TRUE );
							}
						}
					}

					return FALSE;

				break;

				case IDOK:

					AA_TRACE( ( TEXT( "CredentialsDlgProc::IDOK" ) ) );

#ifdef _WIN32_WCE
					pUserData = ( PSW2_USER_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pUserData = ( PSW2_USER_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE
					//
					// Both the username and password must be filled in, domain is optional
					//
					//
					// Username
					//
					if( GetWindowTextLength( GetDlgItem( hWnd, IDC_CRED_USERNAME ) ) > 0 )
					{
						memset( pUserData->pwcUsername, 0, UNLEN );

						GetWindowText( GetDlgItem( hWnd, IDC_CRED_USERNAME ), pUserData->pwcUsername, UNLEN );

						//
						// Password
						//
						if( GetWindowTextLength( GetDlgItem( hWnd, IDC_CRED_PASSWORD ) ) > 0 )
						{
							memset( pUserData->pwcPassword, 0, PWLEN );

							GetWindowText( GetDlgItem( hWnd, IDC_CRED_PASSWORD ), pUserData->pwcPassword, PWLEN );

							//
							// Domain
							//
							memset( pUserData->pwcDomain, 0, UNLEN );

							GetWindowText( GetDlgItem( hWnd, IDC_CRED_DOMAIN ), pUserData->pwcDomain, UNLEN );
						}

						pUserData->bSaveUserCredentials = FALSE;

						if( SendMessage( GetDlgItem( hWnd, IDC_CRED_SAVECREDENTIALS ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						{
							pUserData->bSaveUserCredentials = TRUE;
						}

						EndDialog( hWnd, TRUE );
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

//
// Name: ConfigAdvancedDlgProc
// Description: Dialog Function for the Advanced Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigAdvancedDlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
    PSW2_PROFILE_DATA		pProfileData;
#ifndef _WIN32_WCE
	WCHAR					pwcTemp[UNLEN];
#endif // _WIN32_WCE
	static BOOL				bPasswordChanged;
#ifdef _WIN32_WCE
	SHINITDLGINFO			shidi;
#endif //  _WIN32_WCE
	DWORD					dwErr = NO_ERROR;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			AA_TRACE( ( TEXT( "ConfigAdvancedDlgProc:: WM_INITDIALOG" ) ) );

			//
			// Only administrators can access this dialog
			//
			if( !AA_IsAdmin() )
				EndDialog( hWnd, FALSE );

			pProfileData = ( PSW2_PROFILE_DATA ) lParam;

#ifdef _WIN32_WCE
			// Create a Done button and size it.  
			shidi.dwMask = SHIDIM_FLAGS;
			shidi.dwFlags = SHIDIF_DONEBUTTON | SHIDIF_SIPDOWN |SHIDIF_SIZEDLGFULLSCREEN;
			shidi.hDlg = hWnd;

			SHInitDialog( &shidi );

			AA_CreateCommandBar( hWnd );
#endif // _WIN32_WCE

#ifndef _WIN32_WCE
			if( pProfileData->bUseAlternateComputerCred )
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_COMPUTER_CRED ), BM_SETCHECK, BST_CHECKED, 0 );

			SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME ), pProfileData->pwcCompName );

			if( wcslen( pProfileData->pwcCompPassword ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD ), L"This is not my password" );

			SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), pProfileData->pwcCompDomain );

			bPasswordChanged = FALSE;

			if( pProfileData->bUseAlternateComputerCred )
			{
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME_LABEL ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME ), TRUE );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD_LABEL ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD ), TRUE );

				if( ( wcslen( pProfileData->pwcCompName ) > 0 ) && 
					( wcschr( pProfileData->pwcCompName, '@' ) == NULL ) )
				{
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN_LABEL ), TRUE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), TRUE );
				}
			}
			else
			{
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME_LABEL ), FALSE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME ), FALSE );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD_LABEL ), FALSE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD ), FALSE );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN_LABEL ), FALSE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), FALSE );
			}
#endif // _WIN32_WCE
			
			if( pProfileData->bServerCertificateLocal )
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_SERVER_CERT_LOCAL ), BM_SETCHECK, BST_CHECKED, 0 );

			if( pProfileData->bVerifyMSExtension )
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_MS_EXTENSION ), BM_SETCHECK, BST_CHECKED, 0 );

			if( pProfileData->bAllowNewConnection )
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_ALLOW_NEW_CONNECTION ), BM_SETCHECK, BST_CHECKED, 0 );
			
#ifndef _WIN32_WCE
			if( pProfileData->bRenewIP )
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_RENEW_IP ), BM_SETCHECK, BST_CHECKED, 0 );
#endif // _WIN32_WCE

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pProfileData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pProfileData );
#endif // _WIN32_WCE

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_CONFIG_COMP_PASSWORD:

					if( HIWORD( wParam ) == EN_CHANGE )
						bPasswordChanged = TRUE;

					return FALSE;

				break;

#ifndef _WIN32_WCE
				case IDC_CONFIG_USE_COMPUTER_CRED:

					AA_TRACE( ( TEXT( "ConfigAdvancedDlgProc::IDC_CONFIG_USE_COMPUTER_CRED: %d" ), HIWORD( wParam ) ) );

					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );

					switch( HIWORD( wParam ) )
					{
						case BN_CLICKED:

							if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_COMPUTER_CRED ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME ), TRUE );

								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD ), TRUE );

								if( ( wcslen( pProfileData->pwcCompName ) > 0 ) && 
									( wcschr( pProfileData->pwcCompName, '@' ) == NULL ) )
								{
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN_LABEL ), TRUE );
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), TRUE );
								}
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME ), FALSE );

								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD ), FALSE );

								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), FALSE );
							}

						break;
					}

					return FALSE;

				break;
#endif // _WIN32_WCE
				case IDOK:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

#ifndef _WIN32_WCE
					pProfileData->bUseAlternateComputerCred = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_COMPUTER_CRED ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bUseAlternateComputerCred = TRUE;

					memset( pProfileData->pwcCompName,
							0, 
							sizeof( pProfileData->pwcCompName ) );

					GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME ), 
									pProfileData->pwcCompName, 
									UNLEN );

					if( bPasswordChanged )
					{
						memset( pProfileData->pwcCompPassword, 
								0, 
								sizeof( pProfileData->pwcCompPassword ) );

						GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_COMP_PASSWORD ), pProfileData->pwcCompPassword, PWLEN );
					}

					memset( pProfileData->pwcCompDomain, 0, sizeof( pProfileData->pwcCompDomain ) );

					GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), pProfileData->pwcCompDomain, UNLEN );
#endif // _WIN32_WCE
					pProfileData->bServerCertificateLocal = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_SERVER_CERT_LOCAL ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bServerCertificateLocal = TRUE;

					pProfileData->bVerifyMSExtension = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_MS_EXTENSION ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bVerifyMSExtension = TRUE;

					pProfileData->bAllowNewConnection = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_ALLOW_NEW_CONNECTION ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bAllowNewConnection = TRUE;
					
#ifndef _WIN32_WCE
					pProfileData->bRenewIP = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_RENEW_IP ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bRenewIP = TRUE;
#endif // _WIN32_WCE

					EndDialog( hWnd, TRUE );

					return TRUE;

				break;

				case IDCANCEL:

					EndDialog( hWnd, FALSE );

				break;

#ifndef _WIN32_WCE
				case IDC_CONFIG_COMP_USERNAME:

					if( HIWORD( wParam ) == EN_CHANGE )
					{
						if( GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_COMP_USERNAME ), pwcTemp, UNLEN ) > 0 )
						{
							if( wcschr( pwcTemp, '@' ) )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), FALSE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), TRUE );
							}
						}
						else
						{
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN_LABEL ), TRUE );
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_COMP_DOMAIN ), TRUE );
						}
					}

					return FALSE;

				break;

#endif // _WIN32_WCE
				
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

#ifndef _WIN32_WCE
//
// Name: ConfigGinaDlgProc
// Description: Dialog Function for the Gina Dialog
// Author: Tom Rixom
// Created: 10 May 2005
//
INT_PTR
CALLBACK
ConfigGinaDlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
    PSW2_GINA_CONFIG_DATA	pGinaConfigData = NULL;
	DWORD					dwSelected;
	DWORD					dwGinaTypeSize;
	DWORD					dwErr = NO_ERROR;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			AA_TRACE( ( TEXT( "ConfigGinaDlgProc:: WM_INITDIALOG" ) ) )

			if( ( pGinaConfigData = ( PSW2_GINA_CONFIG_DATA ) malloc( sizeof( SW2_GINA_CONFIG_DATA ) ) ) )
			{
				//
				// Read in GINA Config
				//
				AA_ReadGinaConfig( pGinaConfigData );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_SW2_GINA ), TRUE );

				if( wcslen( pGinaConfigData->pwcGinaDomainName ) > 0 )
					SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_GINA_DOMAIN ), pGinaConfigData->pwcGinaDomainName );

				//SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE ), CB_ADDSTRING, 0, ( LPARAM ) L"Microsoft" );
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE ), CB_ADDSTRING, 0, ( LPARAM ) L"Novell" );

				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE ), CB_SELECTSTRING, -1, 
																( LPARAM ) pGinaConfigData->pwcGinaType );

				AA_TRACE( ( TEXT( "ConfigGinaDlgProc:: selected GinaType: %s" ), pGinaConfigData->pwcGinaType ) )

				if( pGinaConfigData->bUseSW2Gina )
				{
					SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_SW2_GINA ), BM_SETCHECK, BST_CHECKED, 0 );

					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_DOMAIN_LABEL ), TRUE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_DOMAIN ), TRUE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE_LABEL), TRUE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE), TRUE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_VLAN ), TRUE );

					if( pGinaConfigData->bUseGinaVLAN )
					{
						SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_VLAN ), BM_SETCHECK, BST_CHECKED, 0 );

						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP), TRUE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP_LABEL), TRUE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB), TRUE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB_LABEL ), TRUE );
					}
					else
					{
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP), FALSE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP_LABEL), FALSE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB), FALSE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB_LABEL ), FALSE );
					}
				}
				else
				{
					SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_SW2_GINA ), BM_SETCHECK, BST_UNCHECKED, 0 );

					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_DOMAIN_LABEL ), FALSE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_DOMAIN ), FALSE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE_LABEL), FALSE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE), FALSE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_VLAN ), FALSE );

					if( pGinaConfigData->bUseGinaVLAN )
					{
						SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_VLAN ), BM_SETCHECK, BST_CHECKED, 0 );
					}

					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP), FALSE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP_LABEL), FALSE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB), FALSE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB_LABEL ), FALSE );
				}

				if( pGinaConfigData->dwGinaVLANIPAddress > 0 )
					SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP), 
												IPM_SETADDRESS, 0, pGinaConfigData->dwGinaVLANIPAddress );

				if( pGinaConfigData->dwGinaVLANSubnetMask > 0 )
					SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB), 
												IPM_SETADDRESS, 0, pGinaConfigData->dwGinaVLANSubnetMask );
				
				SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pGinaConfigData );
			}
			else
			{
				EndDialog( hWnd, FALSE );
			}

			return FALSE;

		break;

		case WM_SHOWWINDOW:

			switch( LOWORD( wParam ) )
			{
				case TRUE:

					AA_TRACE( ( TEXT( "ConfigGinaDlgProc:: WM_SHOWWINDOW" ) ) );

					pGinaConfigData = ( PSW2_GINA_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );

					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_SW2_GINA ), TRUE );

					SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_GINA_DOMAIN ), pGinaConfigData->pwcGinaDomainName );

					if( pGinaConfigData->bUseSW2Gina )
					{
						SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_SW2_GINA ), BM_SETCHECK, BST_CHECKED, 0 );

						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_DOMAIN_LABEL ), TRUE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_DOMAIN ), TRUE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE_LABEL ), TRUE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE ), TRUE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_VLAN ), TRUE );

						if( pGinaConfigData->bUseGinaVLAN )
						{
							SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_VLAN ), BM_SETCHECK, BST_CHECKED, 0 );

							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP), TRUE );
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP_LABEL), TRUE );
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB), TRUE );
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB_LABEL ), TRUE );
						}
						else
						{
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP), FALSE );
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP_LABEL), FALSE );
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB), FALSE );
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB_LABEL ), FALSE );
						}
					}
					else
					{
						SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_SW2_GINA ), BM_SETCHECK, BST_UNCHECKED, 0 );

						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_DOMAIN_LABEL ), FALSE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_DOMAIN ), FALSE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE_LABEL ), FALSE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE ), FALSE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_VLAN ), FALSE );

						if( pGinaConfigData->bUseGinaVLAN )
						{
							SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_VLAN ), BM_SETCHECK, BST_CHECKED, 0 );
						}

						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP), FALSE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP_LABEL), FALSE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB), FALSE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB_LABEL ), FALSE );
					}					

				break;

				default:

				break;
			}

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDOK:

					AA_TRACE( ( TEXT( "ConfigGinaDlgProc:: IDOK" ) ) );

					pGinaConfigData = ( PSW2_GINA_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );

					pGinaConfigData->bUseSW2Gina = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_SW2_GINA), 
																	BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pGinaConfigData->bUseSW2Gina = TRUE;

					memset( pGinaConfigData->pwcGinaDomainName, 
							0, 
							sizeof( pGinaConfigData->pwcGinaDomainName ) );

					GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_GINA_DOMAIN), 
																	pGinaConfigData->pwcGinaDomainName, UNLEN );

					if( ( dwSelected = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE ), CB_GETCURSEL, 0, 0 ) ) != CB_ERR )
					{
						AA_TRACE( ( TEXT( "ConfigGinaDlgProc::dwSelected: %d" ), dwSelected ) );

						if( ( dwGinaTypeSize = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE ), CB_GETLBTEXTLEN, dwSelected, 0 ) ) != CB_ERR )
						{
							AA_TRACE( ( TEXT( "ConfigGinaDlgProc::CB_GETLBTEXTLEN: %d" ), dwSelected ) );

							if( ( dwGinaTypeSize > 0 ) && ( dwGinaTypeSize <= sizeof( pGinaConfigData->pwcGinaType ) ) )
							{
								AA_TRACE( ( TEXT( "ConfigGinaDlgProc::copying GinaType: %ld" ), dwGinaTypeSize ) );

								memset( pGinaConfigData->pwcGinaType, 0, sizeof( pGinaConfigData->pwcGinaType ) );
								
								dwErr = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE ), CB_GETLBTEXT, dwSelected, ( LPARAM ) pGinaConfigData->pwcGinaType );

								AA_TRACE( ( TEXT( "ConfigGinaDlgProc:: pwcGinaType: %s" ), pGinaConfigData->pwcGinaType ) );
							}
							else
							{
								AA_TRACE( ( TEXT( "ConfigGinaDlgProc::dwSelected: %d, too big" ), dwSelected ) );

								dwErr = CB_ERR;
							}
						}
						else
						{
							AA_TRACE( ( TEXT( "ConfigGinaDlgProc::SendMessage( CB_GETLBTEXTLEN ) Failed: %d" ), GetLastError() ) );

							dwErr = CB_ERR;
						}
					}
					else
					{
						AA_TRACE( ( TEXT( "ConfigGinaDlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() ) );

						dwErr = CB_ERR;
					}
                    
					pGinaConfigData->bUseGinaVLAN = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_VLAN), 
																	BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pGinaConfigData->bUseGinaVLAN = TRUE;

					pGinaConfigData->dwGinaVLANIPAddress = 0;

					SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP), 
										IPM_GETADDRESS, 0, (LPARAM) &( pGinaConfigData->dwGinaVLANIPAddress ) );

					pGinaConfigData->dwGinaVLANSubnetMask = 0;

					SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB), 
										IPM_GETADDRESS, 0, (LPARAM) &( pGinaConfigData->dwGinaVLANSubnetMask) );

					AA_WriteGinaConfig( pGinaConfigData );

					return TRUE;

				break;
				
				case IDC_CONFIG_GINA_USE_SW2_GINA:

					AA_TRACE( ( TEXT( "ConfigGinaDlgProc::IDC_CONFIG_GINA_USE_SW2_GINA: %d" ), HIWORD( wParam ) ) );

					switch( HIWORD( wParam ) )
					{
						case BN_CLICKED:

							if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_SW2_GINA ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_DOMAIN_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_DOMAIN ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_VLAN ), TRUE );

								if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_VLAN ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
								{
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP), TRUE );
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP_LABEL), TRUE );
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB), TRUE );
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB_LABEL ), TRUE );
								}
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_DOMAIN_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_DOMAIN ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_TYPE ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_VLAN ), FALSE );

								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP_LABEL), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB_LABEL ), FALSE );
							}
						break;
					}

				break;

				case IDC_CONFIG_GINA_USE_VLAN:

					AA_TRACE( ( TEXT( "ConfigGinaDlgProc::IDC_CONFIG_GINA_USE_VLAN: %d" ), HIWORD( wParam ) ) );

					switch( HIWORD( wParam ) )
					{
						case BN_CLICKED:

							if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_GINA_USE_VLAN ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP_LABEL), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB_LABEL ), TRUE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_IP_LABEL), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_GINA_VLAN_SUB_LABEL ), FALSE );
							}

						break;
					}

				break;

				default:
				
					return FALSE;

				break;
			}

		break;

		case WM_DESTROY:

			AA_TRACE( ( TEXT( "ConfigGinaDlgProc::WM_DESTROY" ) ) );

			if( pGinaConfigData )
				free( pGinaConfigData );

		break;

		default:

			return FALSE;

		break;

    }

    return FALSE;
}
#endif // _WIN32_WCE

//
// Name: ConfigUserDlgProc
// Description: Dialog Function for the User Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigUserDlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
    PSW2_PROFILE_DATA		pProfileData;
	WCHAR					pwcTemp[UNLEN];
	static BOOL				bPasswordChanged;
	DWORD					dwErr = NO_ERROR;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			AA_TRACE( ( TEXT( "ConfigUserDlgProc:: WM_INITDIALOG" ) ) )

			pProfileData = ( PSW2_PROFILE_DATA ) lParam;

			SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), pProfileData->pwcUserName );

			if( wcslen( pProfileData->pwcUserPassword ) > 0 )
				SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD ), L"This is not my password" );

			SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), pProfileData->pwcUserDomain );

			bPasswordChanged = FALSE;

			if( pProfileData->bPromptUser )
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), BM_SETCHECK, BST_CHECKED, 0 );

#ifndef _WIN32_WCE
			if( pProfileData->bUseCredentialsForComputer)
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), BM_SETCHECK, BST_CHECKED, 0 );
#endif // _WIN32_WCE

			//
			// Only Administrator can decide whether user credentials are used
			// for everyone
			//
#ifndef _WIN32_WCE
			if( !AA_IsAdmin() )
			{
				ShowWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), SW_HIDE  );
			}
#endif // _WIN32_WCE
			if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
			{
				//
				// If we are to prompt user then disable all except control option
				//
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), TRUE );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME_LABEL ), FALSE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), FALSE );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD_LABEL ), FALSE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD ), FALSE );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), FALSE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), FALSE );
#ifndef _WIN32_WCE
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), FALSE );
#endif // _WIN32_WCE
			}
			else
			{
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), TRUE );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME_LABEL ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), TRUE );

				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD_LABEL ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD ), TRUE );

				if( ( wcslen( pProfileData->pwcUserName ) > 0 ) && 
					( wcschr( pProfileData->pwcUserName, '@' ) == NULL ) )
				{
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), TRUE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), TRUE );
				}
				else
				{
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), FALSE );
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), FALSE );
				}
#ifndef _WIN32_WCE
				if( pProfileData->bUseAlternateComputerCred )
				{
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), FALSE );
				}
				else
				{
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), TRUE );
				}
#endif // _WIN32_WCE
			}
			
#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pProfileData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pProfileData );
#endif // _WIN32_WCE

			return FALSE;

		break;

		case WM_SHOWWINDOW:

			switch( LOWORD( wParam ) )
			{
				case TRUE:

					AA_TRACE( ( TEXT( "ConfigUserDlgProc:: WM_SHOWWINDOW" ) ) );

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
					{
						//
						// If we are to prompt user then disable all except control option
						//
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), TRUE );

						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME_LABEL ), FALSE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), FALSE );

						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD_LABEL ), FALSE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD ), FALSE );

						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), FALSE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), FALSE );

#ifndef _WIN32_WCE
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), FALSE );
#endif // _WIN32_WCE
					}
					else
					{
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), TRUE );

						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME_LABEL ), TRUE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), TRUE );

						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD_LABEL ), TRUE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD ), TRUE );

						if( ( wcslen( pProfileData->pwcUserName ) > 0 ) && 
							( wcschr( pProfileData->pwcUserName, '@' ) == NULL ) )
						{
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), TRUE );
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), TRUE );
						}
						else
						{
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), FALSE );
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), FALSE );
						}
#ifndef _WIN32_WCE
						if( pProfileData->bUseAlternateComputerCred )
						{
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), FALSE );
						}
						else
						{
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), TRUE );
						}
#endif // _WIN32_WCE
					}

				break;

				default:

				break;
			}

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_CONFIG_USER_PASSWORD:

					if( HIWORD( wParam ) == EN_CHANGE )
						bPasswordChanged = TRUE;

					return FALSE;

				break;

				case IDOK:

					AA_TRACE( ( TEXT( "ConfigUserDlgProc:: IDOK" ) ) );

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					pProfileData->bPromptUser = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), 
																	BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bPromptUser = TRUE;

					memset( pProfileData->pwcUserName, 
							0, 
							sizeof( pProfileData->pwcUserName ) );

					GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), 
																	pProfileData->pwcUserName, UNLEN );

					if( bPasswordChanged )
					{
						memset( pProfileData->pwcUserPassword, 
								0, 
								sizeof( pProfileData->pwcUserPassword ) );

						GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD ), 
																pProfileData->pwcUserPassword, PWLEN );
					}

					memset( pProfileData->pwcUserDomain, 0, sizeof( pProfileData->pwcUserDomain ) );

					GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), 
																	pProfileData->pwcUserDomain, UNLEN );

#ifndef _WIN32_WCE
					pProfileData->bUseCredentialsForComputer = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), 
																	BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bUseCredentialsForComputer = TRUE;

					AA_TRACE( ( TEXT( "ConfigUserDlgProc:: pProfileData->bUseCredentialsForComputer: %ld" ), pProfileData->bUseCredentialsForComputer ) );
					AA_TRACE( ( TEXT( "ConfigUserDlgProc:: pProfileData->bUseAlternateComputerCred: %ld" ), pProfileData->bUseAlternateComputerCred ) );

					if( pProfileData->bUseCredentialsForComputer && 
						!pProfileData->bUseAlternateComputerCred )
					{
						memset( pProfileData->pwcCompName, 0, sizeof( pProfileData->pwcCompName ) );
						memcpy( pProfileData->pwcCompName, pProfileData->pwcUserName, sizeof( pProfileData->pwcCompName ) );
						memset( pProfileData->pwcCompPassword, 0, sizeof( pProfileData->pwcCompPassword ) );
						memcpy( pProfileData->pwcCompPassword, pProfileData->pwcUserPassword, sizeof( pProfileData->pwcCompPassword ) );
						memset( pProfileData->pwcCompDomain, 0, sizeof( pProfileData->pwcCompDomain ) );
						memcpy( pProfileData->pwcCompDomain, pProfileData->pwcUserDomain, sizeof( pProfileData->pwcCompDomain ) );

					}
#endif // _WIN32_WCE

					return TRUE;

				break;

				case IDC_CONFIG_USER_USERNAME:

					if( HIWORD( wParam ) == EN_CHANGE )
					{
						if( GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), pwcTemp, UNLEN ) > 0 )
						{
							if( wcschr( pwcTemp, '@' ) )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), FALSE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), TRUE );
							}
						}
						else
						{
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), TRUE );
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), TRUE );
						}
					}
	
					return FALSE;

				break;
				
				case IDC_CONFIG_PROMPT_USER:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					AA_TRACE( ( TEXT( "ConfigUserDlgProc::IDC_CONFIG_PROMPT_USER: %d" ), HIWORD( wParam ) ) );

					switch( HIWORD( wParam ) )
					{
						case BN_CLICKED:

							if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROMPT_USER ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), FALSE );

#ifndef _WIN32_WCE
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), FALSE );
#endif // _WIN32_WCE
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), TRUE );

								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_PASSWORD_LABEL ), TRUE );

								if( GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_USER_USERNAME ), pwcTemp, UNLEN ) > 0 )
								{
									if( !wcschr( pwcTemp, '@' ) )
									{
										EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), TRUE );
										EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), TRUE );
									}
								}
								else
								{
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN_LABEL ), TRUE );
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_DOMAIN ), TRUE );
								}
#ifndef _WIN32_WCE
								if( pProfileData->bUseAlternateComputerCred )
								{
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), FALSE );
								}
								else
								{
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_COMPUTER ), TRUE );
								}
#endif // _WIN32_WCE
							}

						break;
					}

				break;

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

//
// Name: ConfigAuthDlgProc
// Description: Dialog Function for the Authentication Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigAuthDlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
	PSW2_PROFILE_DATA			pProfileData;
	HKEY						hKey;
	HKEY						hEapMethodKey;
	WCHAR						pwcKey[MAX_PATH];
	DWORD						ccKey;
//	WCHAR						*pwcFriendlyName;
//	DWORD						cwcFriendlyName;
	FILETIME					ftLastWriteTime;
	DWORD						dwType;
	SW2_INNER_EAP_CONFIG_DATA	InnerEapConfigData;
	PINNEREAPINVOKECONFIGUI		pInnerEapInvokeConfigUI;
	PINNEREAPFREEMEMORY			pInnerEapFreeMemory;
	HINSTANCE					hEapInstance;
	PBYTE						pbInnerEapConnectionData;
	DWORD						cbInnerEapConnectionData;
	DWORD						dwErr;
	int							i;
	DWORD						dwInnerAuthSize;
	WCHAR						pwcInnerAuth[UNLEN];
	DWORD						dwSelected;
	DWORD						dwSelectedInnerEapType = 0;
	DWORD						dwRet = NO_ERROR;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			AA_TRACE( ( TEXT( "ConfigAuthDlgProc:: WM_INITDIALOG" ) ) );

			pProfileData = ( PSW2_PROFILE_DATA ) lParam;

			//
			// Add Inner Auths
			//
			SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), CB_ADDSTRING, 0, ( LPARAM ) L"PAP" );
			SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), CB_ADDSTRING, 0, ( LPARAM ) L"EAP" );

			AA_TRACE( ( TEXT( "ConfigAuthDlgProc:: pProfileData->pwcInnerAuth: %s" ), pProfileData->pwcInnerAuth ) );

			SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), CB_SELECTSTRING, -1, 
																( LPARAM ) pProfileData->pwcInnerAuth );

			//
			// Add EAP Inner Auth Friendly Names
			//
			if( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
								EAP_EAP_METHOD_LOCATION,
								0,
								KEY_READ,
								&hKey ) == ERROR_SUCCESS )
			{
				dwErr = ERROR_SUCCESS;

				//
				// Loop through all the keys in this registry entry
				// Ignore errors except of course RegEnumKeyEx
				//
				for( i = 0; dwErr == ERROR_SUCCESS; i++) 
				{ 
					ccKey = sizeof( pwcKey );

					if ( ( dwErr = RegEnumKeyEx( hKey, 
												i, 
												pwcKey,
												&ccKey, 
												NULL, 
												NULL, 
												NULL, 
												&ftLastWriteTime ) )  == ERROR_SUCCESS )
					{
						AA_TRACE( ( TEXT( "ConfigAuthDlgProc::RegEnumKeyEx::pwcKey: %s" ), pwcKey ) );

						//
						// Skip EAP-TTLS through EAP-TTLS for now ;)
						//
						if( wcscmp( pwcKey, L"21" ) != 0 )
						{
							if( ( RegOpenKeyEx( hKey,
												pwcKey,
												0,
												KEY_READ,
												&hEapMethodKey ) == ERROR_SUCCESS ) )
							{
								dwType = 0;

								if( ( dwRet = AA_ReadInnerEapMethod( _wtol( pwcKey ), 
																	pProfileData->pwcCurrentProfileId,
																	&InnerEapConfigData ) ) == NO_ERROR )
								{
									AA_TRACE( ( TEXT( "ConfigAuthDlgProc::pwcFriendlyName: %s" ), InnerEapConfigData.pwcEapFriendlyName ) );

									dwSelected = ( DWORD ) SendMessage( 
															GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), 
															CB_ADDSTRING, 
															0, 
															( LPARAM ) InnerEapConfigData.pwcEapFriendlyName );

									AA_TRACE( ( TEXT( "ConfigAuthDlgProc::InnerEapConfigData.dwEapType: %ld" ), InnerEapConfigData.dwEapType ) );

									SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), 
												CB_SETITEMDATA, 
												dwSelected, 
												( LPARAM ) InnerEapConfigData.dwEapType );
								}

								RegCloseKey( hEapMethodKey );
							}
						}
					}
				} // for

				RegCloseKey( hKey );
			}

			if( wcscmp( pProfileData->pwcInnerAuth, L"EAP" ) == 0 )
			{
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_LABEL ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), TRUE );

				AA_TRACE( ( TEXT( "ConfigAuthDlgProc::dwCurrentInnerEapMethod: %ld" ), pProfileData->dwCurrentInnerEapMethod ) );

				if( pProfileData->dwCurrentInnerEapMethod > 0 )
				{
					if( ( dwRet = AA_ReadInnerEapMethod( pProfileData->dwCurrentInnerEapMethod, 
															pProfileData->pwcCurrentProfileId,
															&InnerEapConfigData ) ) == NO_ERROR )
					{
						//
						// Select current EAP method
						//
						SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), 
										CB_SELECTSTRING, 
										-1, 
										( LPARAM ) InnerEapConfigData.pwcEapFriendlyName );

						//
						// If the EAP method has a ConfigUI then enable configure button
						//
						if( wcslen( InnerEapConfigData.pwcEapConfigUiPath ) > 0 )
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_CONFIG ), TRUE );
					}
				}
			}

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pProfileData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pProfileData );
#endif // _WIN32_WCE

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_CONFIG_INNER_AUTH:

					if( HIWORD( wParam ) == LBN_SELCHANGE )
					{
#ifdef _WIN32_WCE
						pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
						pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

						if( ( dwSelected = ( DWORD ) SendMessage( 
							GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), CB_GETCURSEL, 0, 0 ) ) != CB_ERR )
						{
							AA_TRACE( ( TEXT( "ConfigAuthDlgProc::dwSelected: %d" ), dwSelected ) );

							if( ( dwInnerAuthSize = 
								( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), 
															CB_GETLBTEXTLEN, dwSelected, 0 ) ) != CB_ERR )
							{
								AA_TRACE( ( TEXT( "ConfigAuthDlgProc::CB_GETLBTEXTLEN: %d" ), dwSelected ) );

								if( ( dwInnerAuthSize > 0 ) && ( dwInnerAuthSize <= sizeof( pwcInnerAuth ) ) )
								{
									AA_TRACE( ( TEXT( "ConfigAuthDlgProc::copying InnerAuth: %d" ), dwInnerAuthSize ) );

									memset( pwcInnerAuth, 0, sizeof( pwcInnerAuth ) );
									
									dwErr = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), CB_GETLBTEXT, dwSelected, ( LPARAM ) pwcInnerAuth );
								}
								else
								{
									AA_TRACE( ( TEXT( "ConfigAuthDlgProc::dwSelected: %d, too big" ), dwSelected ) );

									dwErr = CB_ERR;
								}
							}
							else
							{
								AA_TRACE( ( TEXT( "ConfigAuthDlgProc::SendMessage( CB_GETLBTEXTLEN ) Failed: %d" ), GetLastError() ) );

								dwErr = CB_ERR;
							}
						}
						else
						{
							AA_TRACE( ( TEXT( "ConfigAuthDlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() ) );

							dwErr = CB_ERR;
						}

						if( dwErr != CB_ERR )
						{
							AA_TRACE( ( TEXT( "ConfigAuthDlgProc::pwcInnerAuth: %ws" ), pwcInnerAuth ) );

							if( wcscmp( pwcInnerAuth, L"EAP" ) == 0 )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_LABEL ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), TRUE );

								if( pProfileData->dwCurrentInnerEapMethod > 0 )
								{
									if( ( dwRet = AA_ReadInnerEapMethod( pProfileData->dwCurrentInnerEapMethod, 
																		pProfileData->pwcCurrentProfileId,
																		&InnerEapConfigData ) ) == NO_ERROR )
									{
										//
										// Select current EAP method
										//
										SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), 
														CB_SELECTSTRING, 
														-1, 
														( LPARAM ) InnerEapConfigData.pwcEapFriendlyName );

										//
										// If the EAP method has a ConfigUI then enable configure button
										//
										if( wcslen( InnerEapConfigData.pwcEapConfigUiPath ) > 0 )
											EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_CONFIG ), TRUE );
									}
								}
							}
							else
							{
								AA_TRACE( ( TEXT( "ConfigAuthDlgProc::IDC_CONFIG_INNER_AUTH::disableing EAP window" ) ) );

								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_LABEL ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_CONFIG ), FALSE );
							}
						}
					}

					AA_TRACE( ( TEXT( "ConfigAuthDlgProc::IDC_CONFIG_INNER_AUTH:: returning" ) ) );

					return FALSE;

				break;

				case IDC_CONFIG_INNER_EAP:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( HIWORD( wParam ) == LBN_SELCHANGE )
					{
						if( ( dwSelected = ( DWORD ) SendMessage( 
											GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), 
											CB_GETCURSEL, 
											0, 
											0 ) ) != CB_ERR )
						{
							AA_TRACE( ( TEXT( "ConfigAuthDlgProc::IDC_CONFIG_INNER_EAP::dwSelected: %ld" ), dwSelected ) );

							if( ( dwSelectedInnerEapType = 
									( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP), 
															CB_GETITEMDATA, 
															dwSelected, 
															0 ) ) != CB_ERR )
							{
								AA_TRACE( ( TEXT( "ConfigAuthDlgProc::IDC_CONFIG_INNER_EAP::dwSelectedInnerEapType: %ld" ), dwSelectedInnerEapType ) );

								if( ( dwRet = AA_ReadInnerEapMethod( dwSelectedInnerEapType, 
																	pProfileData->pwcCurrentProfileId,
																	&InnerEapConfigData ) ) == NO_ERROR )
								{
									if( wcslen( InnerEapConfigData.pwcEapConfigUiPath ) > 0 )
										EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_CONFIG ), 
																							TRUE );
									else
										EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_CONFIG ), 
																						FALSE );
								}
							}
						}
					}

					return FALSE;

				break;

				case IDC_CONFIG_INNER_EAP_CONFIG:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE


					if( ( dwSelected = ( DWORD ) SendMessage( 
										GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), 
										CB_GETCURSEL, 
										0, 
										0 ) ) != CB_ERR )
					{
						if( ( dwSelectedInnerEapType = 
								( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP), 
														CB_GETITEMDATA, 
														dwSelected, 
														0 ) ) != CB_ERR )
						{
							dwRet = AA_ReadInnerEapMethod( dwSelectedInnerEapType, 
															pProfileData->pwcCurrentProfileId,
															&InnerEapConfigData );
						}
					}

					if( dwRet == NO_ERROR )
					{
						//
						// Connect to EAP DLL
						//
						if( ( hEapInstance = LoadLibrary( InnerEapConfigData.pwcEapConfigUiPath ) ) )
						{
#ifndef _WIN32_WCE
							if( ( pInnerEapInvokeConfigUI = 
								( PINNEREAPINVOKECONFIGUI ) GetProcAddress( hEapInstance, 
																			"RasEapInvokeConfigUI" ) ) )
#else
							if( ( pInnerEapInvokeConfigUI = 
								( PINNEREAPINVOKECONFIGUI ) GetProcAddress( hEapInstance, 
																			L"RasEapInvokeConfigUI" ) ) )
#endif // _WIN32_WCE
							{
								AA_TRACE( ( TEXT( "ConfigAuthDlgProc::invoking config ui with dwInnerEapType: %ld" ), InnerEapConfigData.dwEapType ) );

								if( ( pInnerEapInvokeConfigUI( InnerEapConfigData.dwEapType,
																hWnd,
																0,
																InnerEapConfigData.pbConnectionData,
																InnerEapConfigData.cbConnectionData,
																&pbInnerEapConnectionData,
																&cbInnerEapConnectionData ) ) == NO_ERROR )
								{
									AA_TRACE( ( TEXT( "ConfigAuthDlgProc::dwConnectionDataOut: %ld" ), cbInnerEapConnectionData ) );
#ifndef _WIN32_WCE
									if( ( pInnerEapFreeMemory = ( PINNEREAPFREEMEMORY ) 
										GetProcAddress( hEapInstance, "RasEapFreeMemory" ) ) )
#else
									if( ( pInnerEapFreeMemory = ( PINNEREAPFREEMEMORY ) 
										GetProcAddress( hEapInstance, L"RasEapFreeMemory" ) ) )
#endif // _WIN32_WCE
									{
										if( cbInnerEapConnectionData <= EAP_MAX_INNER_DATA )
										{
											InnerEapConfigData.cbConnectionData = cbInnerEapConnectionData;

											memcpy( InnerEapConfigData.pbConnectionData, 
													pbInnerEapConnectionData, 
													InnerEapConfigData.cbConnectionData );

											dwRet = AA_WriteInnerEapMethod(	dwSelectedInnerEapType, 
																			pProfileData->pwcCurrentProfileId,
																			InnerEapConfigData );

											AA_TRACE( ( TEXT( "ConfigAuthDlgProc::dwConnectionDataOut: copied config memory" )  ) );
										}
										else
										{
											dwRet = ERROR_NOT_ENOUGH_MEMORY;
										}

										//
										// Free up Inner EAP module memory
										//
										pInnerEapFreeMemory( pbInnerEapConnectionData );
									}
									else
									{
										dwRet = ERROR_DLL_INIT_FAILED;
									}
								}
							}
							else
							{
								AA_TRACE( ( TEXT( "ConfigAuthDlgProc::GetProcAddress FAILED" ) ) );

								dwRet = ERROR_DLL_INIT_FAILED;
							}

							FreeLibrary( hEapInstance );
						}
						else
						{
							AA_TRACE( ( TEXT( "ConfigAuthDlgProc:: LoadLibrary FAILED" ) ) );

							dwRet = ERROR_DLL_INIT_FAILED;
						}
					}
						
				break;

				case IDOK:

					AA_TRACE( ( TEXT( "ConfigAuthDlgProc::IDOK" ) ) );

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( dwSelected = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), CB_GETCURSEL, 0, 0 ) ) != CB_ERR )
					{
						AA_TRACE( ( TEXT( "ConfigAuthDlgProc::dwSelected: %d" ), dwSelected ) );

						if( ( dwInnerAuthSize = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), CB_GETLBTEXTLEN, dwSelected, 0 ) ) != CB_ERR )
						{
							AA_TRACE( ( TEXT( "ConfigAuthDlgProc::CB_GETLBTEXTLEN: %d" ), dwSelected ) );

							if( ( dwInnerAuthSize > 0 ) && ( dwInnerAuthSize <= sizeof( pProfileData->pwcInnerAuth ) ) )
							{
								AA_TRACE( ( TEXT( "ConfigAuthDlgProc::copying InnerAuth: %d" ), dwInnerAuthSize ) );

								memset( pProfileData->pwcInnerAuth, 0, sizeof( pProfileData->pwcInnerAuth ) );
								
								dwErr = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_AUTH ), CB_GETLBTEXT, dwSelected, ( LPARAM ) pProfileData->pwcInnerAuth );

								AA_TRACE( ( TEXT( "ConfigAuthDlgProc:: pProfileData->pwcInnerAuth: %s" ), pProfileData->pwcInnerAuth ) );
							}
							else
							{
								AA_TRACE( ( TEXT( "ConfigAuthDlgProc::dwSelected: %d, too big" ), dwSelected ) );

								dwErr = CB_ERR;
							}
						}
						else
						{
							AA_TRACE( ( TEXT( "ConfigAuthDlgProc::SendMessage( CB_GETLBTEXTLEN ) Failed: %d" ), GetLastError() ) );

							dwErr = CB_ERR;
						}
					}
					else
					{
						AA_TRACE( ( TEXT( "ConfigAuthDlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() ) );

						dwErr = CB_ERR;
					}

					if( ( dwSelected = ( DWORD ) SendMessage( 
										GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP ), 
										CB_GETCURSEL, 
										0, 
										0 ) ) != CB_ERR )
					{
						AA_TRACE( ( TEXT( "ConfigAuthDlgProc::IDC_CONFIG_INNER_EAP::dwSelected: %ld" ), dwSelected ) );

						if( ( dwSelectedInnerEapType = 
								( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP), 
														CB_GETITEMDATA, 
														dwSelected, 
														0 ) ) != CB_ERR )
						{
							AA_TRACE( ( TEXT( "ConfigAuthDlgProc::IDC_CONFIG_INNER_EAP::dwSelectedInnerEapType: %ld" ), dwSelectedInnerEapType ) );

							if( ( dwRet = AA_ReadInnerEapMethod( dwSelectedInnerEapType, 
																pProfileData->pwcCurrentProfileId,
																&InnerEapConfigData ) ) == NO_ERROR )
							{
								if( wcslen( InnerEapConfigData.pwcEapConfigUiPath ) > 0 )
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_CONFIG ), 
																						TRUE );
								else
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_INNER_EAP_CONFIG ), 
																					FALSE );
							}
						}
					}

					pProfileData->dwCurrentInnerEapMethod = dwSelectedInnerEapType;

					if( dwErr == CB_ERR )
					{
						AA_TRACE( ( TEXT( "ConfigAuthDlgProc::retreiving InnerAuth Failed" ) ) );

						wcscpy( pProfileData->pwcInnerAuth, L"PAP" );
					}

					return TRUE;

				break;

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

//
// Name: ConfigCADlgProc
// Description: Dialog Function for the CA certificate dialog allowing the user
//				to choose a trusted CA
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigCADlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
#ifdef _WIN32_WCE
	SHINITDLGINFO			shidi;
#endif //  _WIN32_WCE

	PSW2_PROFILE_DATA	pProfileData;
	DWORD				dwSelected;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			AA_TRACE( ( TEXT( "ConfigCADlgProc:: WM_INITDIALOG" ) ) );

#ifdef _WIN32_WCE
			shidi.dwMask = SHIDIM_FLAGS;
			shidi.dwFlags = SHIDIF_DONEBUTTON | SHIDIF_SIPDOWN |SHIDIF_SIZEDLGFULLSCREEN;
			shidi.hDlg = hWnd;

			SHInitDialog( &shidi );

			AA_CreateCommandBar( hWnd );

#endif // _WIN32_WCE

			pProfileData = ( PSW2_PROFILE_DATA ) lParam;


			AA_CertGetRootCAList( GetDlgItem( hWnd, IDC_CONFIG_ROOTCA ),
									pProfileData->pbTrustedRootCAList,
									pProfileData->dwNrOfTrustedRootCAInList);

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pProfileData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pProfileData );
#endif // _WIN32_WCE

			return FALSE;

		break;

		case WM_SHOWWINDOW:

			switch( LOWORD( wParam ) )
			{
				case TRUE:
#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					AA_TRACE( ( TEXT( "ConfigCADlgProc:: WM_SHOWWINDOW" ) ) );

					AA_CertGetRootCAList( GetDlgItem( hWnd, IDC_CONFIG_ROOTCA ),
											pProfileData->pbTrustedRootCAList,
											pProfileData->dwNrOfTrustedRootCAInList);

				break;

				default:

				break;
			}

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_CONFIG_ADDCERT_ADD:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( dwSelected = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_ROOTCA ), LB_GETCURSEL, 0, 0 ) ) != CB_ERR )
					{
						if( ( dwSelected = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_ROOTCA ), LB_GETITEMDATA, dwSelected, 0 ) ) != CB_ERR )
						{
							AA_TRACE( ( TEXT( "ConfigCADlgProc::LB_GETITEMDATA: %ld" ), dwSelected ) );

							AA_CertAddTrustedRootCA( dwSelected,  
													pProfileData->pbTrustedRootCAList, 
													&pProfileData->dwNrOfTrustedRootCAInList );
						}
						else
						{
							AA_TRACE( ( TEXT( "ConfigCADlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() ) );
						}
					}

					EndDialog( hWnd, TRUE );

					return FALSE;

				break;

				case IDCANCEL:

					EndDialog( hWnd, FALSE );

				break;

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

//
// Name: ConfigCertDlgProc
// Description: Dialog Function for the Certificate Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigCertDlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
	PSW2_PROFILE_DATA		pProfileData;
	DWORD					dwSelected;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			AA_TRACE( ( TEXT( "ConfigCertDlgProc:: WM_INITDIALOG" ) ) );

			pProfileData = ( PSW2_PROFILE_DATA ) lParam;

			//
			// Verify server certificate
			//
			if( pProfileData->bVerifyServer )
			{
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER ), BM_SETCHECK, BST_CHECKED, 0 );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_TRUSTEDROOTCA ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_NAME ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_CERT_ADD ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_CERT_REMOVE ), TRUE );
			}

			//
			// Verify server domain
			//
			if( pProfileData->bVerifyServerName )
			{
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_NAME ), BM_SETCHECK, BST_CHECKED, 0 );

				if( pProfileData->bVerifyServer )
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_SERVER_NAME ), TRUE );
			}

			//
			// server domain
			//
			SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_SERVER_NAME ), pProfileData->pwcServerName );

			//
			// Verify Server name
			//
			if( pProfileData->bVerifyServerName )
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_NAME ), BM_SETCHECK, BST_CHECKED, 0 );

			//
			// Update trusted CAs
			//
			AA_CertGetTrustedRootCAList( GetDlgItem( hWnd, IDC_CONFIG_TRUSTEDROOTCA ), 
										pProfileData->pbTrustedRootCAList, 
										pProfileData->dwNrOfTrustedRootCAInList );
#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pProfileData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pProfileData );
#endif // _WIN32_WCE

			return FALSE;

		break;

		case WM_SHOWWINDOW:

			switch( LOWORD( wParam ) )
			{
				case TRUE:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					//
					// Update trusted CAs
					//
					AA_CertGetTrustedRootCAList( GetDlgItem( hWnd, IDC_CONFIG_TRUSTEDROOTCA ), 
												pProfileData->pbTrustedRootCAList, 
												pProfileData->dwNrOfTrustedRootCAInList );

				break;

				default:

				break;
			}

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_CONFIG_VERIFY_SERVER:

					switch( HIWORD( wParam ) )
					{
						case BN_CLICKED:

							if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_NAME ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_TRUSTEDROOTCA ), TRUE );

								if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_NAME ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
								{
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_SERVER_NAME ), TRUE );
								}
								else
									EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_SERVER_NAME ), FALSE );

								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_CERT_ADD ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_CERT_REMOVE ), TRUE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_NAME ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_TRUSTEDROOTCA ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_SERVER_NAME ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_CERT_ADD ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_CERT_REMOVE ), FALSE );
							}

						break;

						default:
						break;
					}

				break;

				case IDC_CONFIG_CERT_ADD:

					//
					// User wishes to add certificate so show dialog
					//

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( DialogBoxParam( ghInstance,
										MAKEINTRESOURCE(IDD_CONFIG_CA_DLG),
										hWnd,
										ConfigCADlgProc,
										( LPARAM ) pProfileData ) )
					{
						SendMessage( hWnd, WM_SHOWWINDOW, TRUE, 0 );
					}

					return FALSE;

				break;

				case IDC_CONFIG_CERT_REMOVE:

					//
					// User wishes to add certificate so show dialog
					//

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( dwSelected = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_TRUSTEDROOTCA ), LB_GETCURSEL, 0, 0 ) ) != CB_ERR )
					{
						if( ( dwSelected = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_TRUSTEDROOTCA ), LB_GETITEMDATA, dwSelected, 0 ) ) != CB_ERR )
						{
							AA_TRACE( ( TEXT( "ConfigCertDlgProc::LB_GETITEMDATA: %ld" ), dwSelected ) );

							AA_CertRemoveTrustedRootCA( dwSelected,  
														pProfileData->pbTrustedRootCAList, 
														&pProfileData->dwNrOfTrustedRootCAInList );

							SendMessage( hWnd, WM_SHOWWINDOW, TRUE, 0 );
						}
						else
						{
							AA_TRACE( ( TEXT( "ConfigCertDlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() ) );
						}
					}
					
					return FALSE;

				break;

				case IDC_CONFIG_VERIFY_SERVER_NAME:

					switch( HIWORD( wParam ) )
					{
						case BN_CLICKED:

							if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_NAME ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_SERVER_NAME ), TRUE );
							else
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_SERVER_NAME ), FALSE );

						break;

						default:
						break;
					}

				break;

				case IDOK:

					AA_TRACE( ( TEXT( "ConfigCertDlgProc::IDOK" ) ) );

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					//
					// Verify server certificate
					//
					pProfileData->bVerifyServer = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bVerifyServer = TRUE;

					//
					// Verify server domain
					//
					pProfileData->bVerifyServerName = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_VERIFY_SERVER_NAME ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bVerifyServerName = TRUE;

					memset( pProfileData->pwcServerName, 0, UNLEN );

					GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_SERVER_NAME ), pProfileData->pwcServerName, UNLEN );

					return TRUE;

				break;

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

//
// Name: ConfigConnDlgProc
// Description: Dialog Function for the Connection Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigConnDlgProc(	IN  HWND    hWnd,
					IN  UINT    unMsg,
					IN  WPARAM  wParam,
					IN  LPARAM  lParam )
{
	PSW2_PROFILE_DATA		pProfileData;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			AA_TRACE( ( TEXT( "ConfigConnDlgProc:: WM_INITDIALOG" ) ) );

			pProfileData = ( PSW2_PROFILE_DATA ) lParam;

			//
			// Use alternate outer identity
			//
			if( pProfileData->bUseAlternateOuter )
			{
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_OUTER ), BM_SETCHECK, BST_CHECKED, 0 );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_ANONYMOUS ), TRUE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_SPECIFY ), TRUE );
			}

			//
			// Use anonymous outer identity
			//
			if( pProfileData->bUseAlternateAnonymous )
			{
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_ANONYMOUS ), BM_SETCHECK, BST_CHECKED, 0 );
			}
			else
			{
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_SPECIFY ), BM_SETCHECK, BST_CHECKED, 0 );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), TRUE );
			}

			//
			// Alternate identity
			//
			SetWindowText( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), pProfileData->pwcAlternateOuter );

			//
			// Enable session resumption
			//
			if( pProfileData->bUseSessionResumption )
				SendMessage( GetDlgItem( hWnd, IDC_CONFIG_ENABLE_SESSION_RESUMPTION ), BM_SETCHECK, BST_CHECKED, 0 );

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pProfileData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pProfileData );
#endif // _WIN32_WCE

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_CONFIG_USE_ALTERNATE_ANONYMOUS:

					switch( HIWORD( wParam ) )
					{
						case BN_CLICKED:

							if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_ANONYMOUS ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), FALSE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), TRUE );
							}

						break;

						default:
						break;
					}

				break;

				case IDC_CONFIG_USE_ALTERNATE_SPECIFY:

					switch( HIWORD( wParam ) )
					{
						case BN_CLICKED:

							if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_SPECIFY ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), TRUE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), FALSE );
							}

						break;

						default:
						break;
					}

				break;

				case IDC_CONFIG_USE_ALTERNATE_OUTER:

					switch( HIWORD( wParam ) )
					{
						case BN_CLICKED:

							if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_OUTER ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_ANONYMOUS ), TRUE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_SPECIFY ), TRUE );

								if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_SPECIFY ), BM_GETCHECK, 0 , 0 ) == BST_CHECKED )
                                    EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), TRUE );
							}
							else
							{
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_SPECIFY ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), FALSE );
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_ANONYMOUS ), FALSE );
							}

						break;

						default:
						break;
					}

				break;

				case IDOK:

					AA_TRACE( ( TEXT( "ConfigConnDlgProc::IDOK" ) ) );

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					//
					// Use alternate outer identity
					//
					pProfileData->bUseAlternateOuter = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_OUTER ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bUseAlternateOuter = TRUE;

					//
					// Use anonymous outer identity
					//
					pProfileData->bUseAlternateAnonymous = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_USE_ALTERNATE_ANONYMOUS ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bUseAlternateAnonymous = TRUE;
					
					//
					// Specified alternate identity
					//
					GetWindowText( GetDlgItem( hWnd, IDC_CONFIG_ALTERNATE_OUTER ), pProfileData->pwcAlternateOuter, UNLEN );

					//
					// Enable quick connect?
					//
					pProfileData->bUseSessionResumption = FALSE;

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_ENABLE_SESSION_RESUMPTION ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pProfileData->bUseSessionResumption = TRUE;

					return TRUE;

				break;

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

//
// Name: ConfigProfileNewDlgProc
// Description: Dialog Function for the New Profile Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigProfileNewDlgProc(IN  HWND    hWnd,
						IN  UINT    unMsg,
						IN  WPARAM  wParam,
						IN  LPARAM  lParam )
{
    WCHAR					*pwcProfileID;
#ifdef _WIN32_WCE
	SHINITDLGINFO			shidi;
#endif //  _WIN32_WCE

	DWORD					dwErr = NO_ERROR;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			AA_TRACE( ( TEXT( "ProfileNewDlgProc:: WM_INITDIALOG" ) ) );

			pwcProfileID = ( WCHAR* ) lParam;

#ifdef _WIN32_WCE
			shidi.dwMask = SHIDIM_FLAGS;
			shidi.dwFlags = SHIDIF_DONEBUTTON | SHIDIF_SIPDOWN |SHIDIF_SIZEDLGFULLSCREEN;
			shidi.hDlg = hWnd;

			SHInitDialog( &shidi );

			AA_CreateCommandBar( hWnd );

#endif // _WIN32_WCE

			SetFocus( GetDlgItem( hWnd, IDC_PROFILE_ID ) );

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pwcProfileID );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pwcProfileID );
#endif // _WIN32_WCE

			return FALSE;

		break;


	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDOK:

#ifdef _WIN32_WCE
					pwcProfileID = ( WCHAR* ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pwcProfileID = ( WCHAR*) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( GetDlgItemText( hWnd, IDC_PROFILE_ID, pwcProfileID, UNLEN ) > 0 )
					{
						EndDialog( hWnd, TRUE );
					}

					return TRUE;

				break;

				case IDCANCEL:

					EndDialog( hWnd, FALSE );

				break;
			
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

//
// Name: ConfigProfileDlgProc
// Description: Dialog Function for the Profile Configuration Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigProfileDlgProc(	IN  HWND    hWnd,
						IN  UINT    unMsg,
						IN  WPARAM  wParam,
						IN  LPARAM  lParam )
{
	PSW2_CONFIG_DATA	pConfigData;
	SW2_PROFILE_DATA	ProfileData;
	WCHAR				pwcTemp1[UNLEN];
	WCHAR				pwcTemp2[UNLEN];
	WCHAR				pwcProfileID[UNLEN];
	DWORD				dwSelectedInnerEapType = 0;
	HKEY				hKeyLM, hKeyCU, hProfileKeyLM, hProfileKeyCU;
	FILETIME			ftLastWriteTime;
	DWORD				dwErr;
	WCHAR				pwcKey[MAX_PATH*2];
	DWORD				cwcKey;
	int					i;
	DWORD				dwProfileIDSize;
	DWORD				dwSelected;
	DWORD				dwDisposition;
	BOOL				bDefaultProfile;
	BOOL				bIsAdmin;
	DWORD				dwRet = NO_ERROR;
	
    switch( unMsg )
    {	
		case WM_INITDIALOG:
        
			AA_TRACE( ( TEXT( "ConfigProfileDlgProc:: WM_INITDIALOG" ) ) );

			pConfigData = ( PSW2_CONFIG_DATA ) lParam;

			bDefaultProfile = FALSE;

			bIsAdmin = AA_IsAdmin();

			//
			// If we are an administrator create default profile
			//
			if( bIsAdmin )
			{
				//
				// Read in all profiles, if profile key does not exists create it
				//
				dwRet = AA_CreateSecureKey( HKEY_LOCAL_MACHINE,	
											AA_CLIENT_PROFILE_LOCATION, 
											&hKeyLM, 
											&dwDisposition );
			}
			else
			{

				AA_TRACE( ( TEXT( "ConfigProfileDlgProc:: NON Admin" ) ) );
		
				//
				// Only admins can select, create and delete profiles
				//
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_NEW ), FALSE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), FALSE );
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_DELETE ), FALSE );

				//
				// Non admins can only read the registry for profiles
				//
				dwRet = RegOpenKeyEx( HKEY_LOCAL_MACHINE,	
										AA_CLIENT_PROFILE_LOCATION, 
										0, 
										KEY_READ,
										&hKeyLM );

				AA_TRACE( ( TEXT( "ConfigProfileDlgProc:: %ld, %ld" ), dwRet, GetLastError() ) );
			}

			if( dwRet == NO_ERROR )
			{
				AA_TRACE( ( TEXT( "ConfigProfileDlgProc:: opened PROFILES" ) ) );

				//
				// Also create profiles key in user registry
				//
				if( RegCreateKeyEx(	HKEY_CURRENT_USER, 
									AA_CLIENT_PROFILE_LOCATION, 
									0, 
									NULL, 
									0, 
									KEY_READ | KEY_WRITE, 
									NULL,
									&hKeyCU, 
									&dwDisposition ) != ERROR_SUCCESS )
				{
					RegCloseKey( hKeyLM );
					dwRet = ERROR_CANTOPEN;
				}
			}

			if( dwRet == NO_ERROR )
			{
				AA_TRACE( ( TEXT( "ConfigProfileDlgProc:: parsing profiles" ) ) );

				dwErr = ERROR_SUCCESS;

				for( i = 0; dwErr == ERROR_SUCCESS; i++) 
				{ 
					cwcKey = sizeof( pwcKey );

					if ( ( dwErr = RegEnumKeyEx( hKeyLM, 
												i, 
												pwcKey,
												&cwcKey, 
												NULL, 
												NULL, 
												NULL, 
												&ftLastWriteTime ) )  == ERROR_SUCCESS )
					{
						AA_TRACE( ( TEXT( "ConfigProfileDlgProc::RegEnumKeyEx::pwcKey: %s" ), pwcKey ) );

						//
						// Check for DEFAULT profile
						//
						if( wcscmp( TEXT( "DEFAULT" ), pwcKey ) == 0 )
							bDefaultProfile = TRUE;

						dwSelected = ( DWORD ) SendMessage( 
												GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
												CB_ADDSTRING, 
												0, 
												( LPARAM ) pwcKey );
					}
				}
					
				if( !bDefaultProfile )
				{
					AA_TRACE( ( TEXT( "ConfigProfileDlgProc::could not find DEFAULT profile" ) ) );

					if( bIsAdmin )
					{
						//
						// Could not find any profiles so create a DEFAULT one
						//
						dwRet = AA_CreateSecureKey( hKeyLM,	
													TEXT( "DEFAULT" ), 
													&hProfileKeyLM, 
													&dwDisposition );
					}

					if( dwRet == NO_ERROR )
					{
						//
						// Also create a profile in the user registry which will hold the
						// user credentials
						//
						if( RegCreateKeyEx(	hKeyCU, 
											TEXT( "DEFAULT" ), 
											0, 
											NULL, 
											0, 
											KEY_READ | KEY_WRITE, 
											NULL,
											&hProfileKeyCU, 
											&dwDisposition ) != ERROR_SUCCESS )
						{
							AA_TRACE( ( TEXT( "ConfigProfileDlgProc::RegCreateKeyEx FAILED (%ld)" ), GetLastError() ) );

							RegCloseKey( hProfileKeyLM );

							dwRet = ERROR_CANTOPEN;
						}
					}

					if( dwRet == NO_ERROR )
					{
						AA_InitDefaultProfile( &ProfileData );

						AA_WriteProfile( TEXT( "DEFAULT" ), NULL, ProfileData );

						//
						// If this is the only profile we can find then
						// select the DEFAULT profile
						//
						dwSelected = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
															CB_ADDSTRING, 
															0, 
															( LPARAM ) TEXT( "DEFAULT" ) );

						RegCloseKey( hProfileKeyCU );
						RegCloseKey( hProfileKeyLM );
					}
				}

				if( bIsAdmin )
					RegCloseKey( hKeyLM );

				RegCloseKey( hKeyCU );

				//
				// Select the current profile, if it fails try and select DEFAULT profile
				//
				if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), CB_SELECTSTRING, -1, 
														( LPARAM ) pConfigData->pwcProfileId  ) != CB_ERR )
				{
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_CONFIGURE ), TRUE );

					if( wcscmp( pConfigData->pwcProfileId, L"DEFAULT" ) != 0 && bIsAdmin )
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_DELETE ), TRUE );
				}
				else if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), CB_SELECTSTRING, -1, 
														( LPARAM ) TEXT( "DEFAULT" ) ) != CB_ERR )
				{
					EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_CONFIGURE ), TRUE );
				}
			}

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pConfigData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pConfigData );
#endif // _WIN32_WCE

			return FALSE;

		break;

		case WM_SHOWWINDOW:

			switch( LOWORD( wParam ) )
			{
				case TRUE:

					AA_TRACE( ( TEXT( "ConfigProfileDlgProc::WM_SHOWWINDOW" ) ) );

#ifdef _WIN32_WCE
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					dwSelected = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
														CB_RESETCONTENT, 
														0, 
														( LPARAM ) 0 );
					//
					// Read in all profiles
					//
					if( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
										AA_CLIENT_PROFILE_LOCATION,
										0,
										KEY_READ,
										&hKeyLM ) == ERROR_SUCCESS )
					{
						dwErr = ERROR_SUCCESS;

						for( i = 0; dwErr == ERROR_SUCCESS; i++) 
						{ 
							cwcKey = sizeof( pwcKey );

							if ( ( dwErr = RegEnumKeyEx( hKeyLM, 
														i, 
														pwcKey,
														&cwcKey, 
														NULL, 
														NULL, 
														NULL, 
														&ftLastWriteTime ) )  == ERROR_SUCCESS )
							{
								AA_TRACE( ( TEXT( "ConfigProfileDlgProc::RegEnumKeyEx::pwcKey: %s" ), pwcKey ) );

								dwSelected = ( DWORD ) SendMessage( 
														GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
														CB_ADDSTRING, 
														0, 
														( LPARAM ) pwcKey );
							}
						}

						RegCloseKey( hKeyLM );
					}

					if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), CB_SELECTSTRING, -1, 
															( LPARAM ) pConfigData->pwcProfileId  ) != CB_ERR )
					{
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_CONFIGURE ), TRUE );

						if( wcscmp( pConfigData->pwcProfileId, L"DEFAULT" ) != 0 )
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_DELETE ), TRUE );
						else
							EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_DELETE ), FALSE );

					}
					else if( SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), CB_SELECTSTRING, -1, 
															( LPARAM ) TEXT( "DEFAULT" ) ) != CB_ERR )
					{
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_CONFIGURE ), TRUE );
						EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_DELETE ), FALSE );
					}

				break;
	
				default:

				break;
			}

			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDC_CONFIG_PROFILES:

					if( HIWORD( wParam ) == LBN_SELCHANGE )
					{
#ifdef _WIN32_WCE
						pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
						pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

						if( ( dwSelected = ( DWORD ) SendMessage( 
								GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), CB_GETCURSEL, 0, 0 ) ) != CB_ERR )
						{
							AA_TRACE( ( TEXT( "ConfigProfileDlgProc::dwSelected: %d" ), dwSelected ) );

							if( ( dwProfileIDSize = 
								( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
															CB_GETLBTEXTLEN, dwSelected, 0 ) ) != CB_ERR )
							{
								AA_TRACE( ( TEXT( "ConfigProfileDlgProc::CB_GETLBTEXTLEN: %d" ), dwSelected ) );

								if( ( dwProfileIDSize > 0 ) && 
									( dwProfileIDSize <= sizeof( pConfigData->pwcProfileId ) ) )
								{
									AA_TRACE( ( TEXT( "ConfigProfileDlgProc::copying InnerAuth: %d" ), dwProfileIDSize ) );

									memset( pwcProfileID, 
											0, 
											sizeof( pwcProfileID ) );
									
									dwErr = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
																	CB_GETLBTEXT, 
																	dwSelected, 
																	( LPARAM ) pwcProfileID );

									AA_TRACE( ( TEXT( "ConfigProfileDlgProc::dwSelected: %s" ), pwcProfileID ) );
								}
								else
								{
									AA_TRACE( ( TEXT( "ConfigProfileDlgProc::dwSelected: %ld, too big" ), dwSelected ) );

									dwErr = CB_ERR;
								}
							}
							else
							{
								AA_TRACE( ( TEXT( "ConfigProfileDlgProc::SendMessage( CB_GETLBTEXTLEN ) Failed: %d" ), GetLastError() ) );

								dwErr = CB_ERR;
							}
						}
						else
						{
							AA_TRACE( ( TEXT( "ConfigProfileDlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() ) );

							dwErr = CB_ERR;
						}

						if( dwErr != CB_ERR )
						{
							wcscpy( pConfigData->pwcProfileId, pwcProfileID );

							if( wcscmp( pConfigData->pwcProfileId, L"DEFAULT" ) != 0 )
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_DELETE ), TRUE );
							else
								EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_PROFILE_DELETE ), FALSE );
						}

					}

					return FALSE;

				break;

				case IDC_CONFIG_PROFILE_NEW:

					AA_TRACE( ( TEXT( "ConfigProfileDlgProc::IDC_CONFIG_PROFILE_NEW" ) ) );

#ifdef _WIN32_WCE
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( DialogBoxParam( ghInstance,
										MAKEINTRESOURCE(IDD_PROFILE_NEW_DLG),
										hWnd,
										ConfigProfileNewDlgProc,
										( LPARAM ) pwcProfileID ) )
					{
						if( ( dwRet = AA_CreateProfile( pwcProfileID ) ) == NO_ERROR )
						{
							//
							// Load in configuration data
							//
							AA_ReadProfile( pwcProfileID, NULL, &ProfileData );

							if( DialogBoxParam( ghInstance,
											MAKEINTRESOURCE(IDD_PROFILE_DLG),
											hWnd,
											ProfileDlgProc,
											( LPARAM ) &ProfileData ) )
							{
								AA_WriteProfile( pwcProfileID, NULL, ProfileData );

								//
								// Select new Profile
								//
								wcscpy( pConfigData->pwcProfileId, pwcProfileID );

								//
								// Reset screen
								//
								SendMessage( hWnd, WM_SHOWWINDOW, TRUE, 0 );
							}
						}
						else if( dwRet == ERROR_ALREADY_EXISTS )
						{
							memset( pwcTemp1, 0, sizeof( pwcTemp1 ) );
							memset( pwcTemp2, 0, sizeof( pwcTemp2 ) );

							LoadString( ghInstance, IDS_PROFILE_EXISTS, pwcTemp1, sizeof( pwcTemp1 ) );
							LoadString( ghInstance, IDS_SW2_ERROR, pwcTemp2, sizeof( pwcTemp2 ) );

							MessageBox( hWnd, pwcTemp1, pwcTemp2, MB_OK | MB_ICONEXCLAMATION );
						}

						dwRet = NO_ERROR;
					}
					
					return TRUE;

				break;

				case IDC_CONFIG_PROFILE_CONFIGURE:

					AA_TRACE( ( TEXT( "ConfigProfileDlgProc::IDC_CONFIG_PROFILE_CONFIGURE" ) ) );

#ifdef _WIN32_WCE
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( dwSelected = ( DWORD ) SendMessage( 
							GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), CB_GETCURSEL, 0, 0 ) ) != CB_ERR )
					{
						AA_TRACE( ( TEXT( "ConfigProfileDlgProc::dwSelected: %d" ), dwSelected ) );

						if( ( dwProfileIDSize = 
							( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
														CB_GETLBTEXTLEN, dwSelected, 0 ) ) != CB_ERR )
						{
							AA_TRACE( ( TEXT( "ConfigProfileDlgProc::CB_GETLBTEXTLEN: %d" ), dwSelected ) );

							if( ( dwProfileIDSize > 0 ) && 
								( dwProfileIDSize <= sizeof( pConfigData->pwcProfileId ) ) )
							{
								AA_TRACE( ( TEXT( "ConfigProfileDlgProc::copying InnerAuth: %d" ), dwProfileIDSize ) );

								memset( pwcProfileID, 
										0, 
										sizeof( pwcProfileID ) );
								
								dwErr = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
																CB_GETLBTEXT, 
																dwSelected, 
																( LPARAM ) pwcProfileID );

								AA_TRACE( ( TEXT( "ConfigProfileDlgProc::dwSelected: %s" ), pwcProfileID ) );
							}
							else
							{
								AA_TRACE( ( TEXT( "ConfigProfileDlgProc::dwSelected: %ld, too big" ), dwSelected ) );

								dwErr = CB_ERR;
							}
						}
						else
						{
							AA_TRACE( ( TEXT( "ConfigProfileDlgProc::SendMessage( CB_GETLBTEXTLEN ) Failed: %d" ), GetLastError() ) );

							dwErr = CB_ERR;
						}
					}
					else
					{
						AA_TRACE( ( TEXT( "ConfigProfileDlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() ) );

						dwErr = CB_ERR;
					}

					if( dwErr != CB_ERR )
					{
						//
						// Load in configuration data
						//
						AA_ReadProfile( pwcProfileID, NULL, &ProfileData );

						if( DialogBoxParam( ghInstance,
											MAKEINTRESOURCE(IDD_PROFILE_DLG),
											hWnd,
											ProfileDlgProc,
											( LPARAM ) &ProfileData ) )
						{
							AA_WriteProfile( pwcProfileID, NULL, ProfileData );

							//
							// Reset screen
							//
							SendMessage( hWnd, WM_SHOWWINDOW, TRUE, 0 );
						}
					}

					return TRUE;

				break;

				case IDC_CONFIG_PROFILE_DELETE:

					AA_TRACE( ( TEXT( "ConfigProfileDlgProc::IDC_CONFIG_PROFILE_DELETE" ) ) );

#ifdef _WIN32_WCE
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( dwSelected = ( DWORD ) SendMessage( 
							GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), CB_GETCURSEL, 0, 0 ) ) != CB_ERR )
					{
						AA_TRACE( ( TEXT( "ConfigProfileDlgProc::dwSelected: %d" ), dwSelected ) );

						if( ( dwProfileIDSize = 
							( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
														CB_GETLBTEXTLEN, dwSelected, 0 ) ) != CB_ERR )
						{
							AA_TRACE( ( TEXT( "ConfigProfileDlgProc::CB_GETLBTEXTLEN: %d" ), dwSelected ) );

							if( ( dwProfileIDSize > 0 ) && 
								( dwProfileIDSize <= sizeof( pConfigData->pwcProfileId ) ) )
							{
								AA_TRACE( ( TEXT( "ConfigProfileDlgProc::copying InnerAuth: %d" ), dwProfileIDSize ) );

								memset( pwcProfileID, 
										0, 
										sizeof( pwcProfileID ) );
								
								dwErr = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
																CB_GETLBTEXT, 
																dwSelected, 
																( LPARAM ) pwcProfileID );

								AA_TRACE( ( TEXT( "ConfigProfileDlgProc::dwSelected: %s" ), pwcProfileID ) );
							}
							else
							{
								AA_TRACE( ( TEXT( "ConfigProfileDlgProc::dwSelected: %ld, too big" ), dwSelected ) );

								dwErr = CB_ERR;
							}
						}
						else
						{
							AA_TRACE( ( TEXT( "ConfigProfileDlgProc::SendMessage( CB_GETLBTEXTLEN ) Failed: %d" ), GetLastError() ) );

							dwErr = CB_ERR;
						}
					}
					else
					{
						AA_TRACE( ( TEXT( "ConfigProfileDlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() ) );

						dwErr = CB_ERR;
					}

					if( dwErr != CB_ERR )
					{
						if( wcscmp( pwcProfileID, TEXT( "DEFAULT" ) ) != 0 )
						{
							memset( pwcTemp1, 0, sizeof( pwcTemp1 ) );
							memset( pwcTemp2, 0, sizeof( pwcTemp2 ) );

							LoadString( ghInstance, IDS_PROFILE_DELETE, pwcTemp1, sizeof( pwcTemp1 ) );
							LoadString( ghInstance, IDS_SW2_ALERT, pwcTemp2, sizeof( pwcTemp2 ) );

							if( MessageBox( hWnd, pwcTemp1, pwcTemp2, MB_YESNO | MB_ICONQUESTION ) == IDYES )
							{
								AA_DeleteProfile( pwcProfileID );

								//
								// Reset screen
								//
								SendMessage( hWnd, WM_SHOWWINDOW, TRUE, 0 );
							}
						}
						else
						{
							memset( pwcTemp1, 0, sizeof( pwcTemp1 ) );
							memset( pwcTemp2, 0, sizeof( pwcTemp2 ) );

							LoadString( ghInstance, IDS_PROFILE_DELETEDEFAULT, pwcTemp1, sizeof( pwcTemp1 ) );
							LoadString( ghInstance, IDS_SW2_ALERT, pwcTemp2, sizeof( pwcTemp2 ) );

							MessageBox( hWnd, pwcTemp1, pwcTemp2, MB_OK | MB_ICONEXCLAMATION );
						}
					}

					return TRUE;

				break;

				case IDOK:

					AA_TRACE( ( TEXT( "ConfigProfileDlgProc::IDOK" ) ) );

#ifdef _WIN32_WCE
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( dwSelected = ( DWORD ) SendMessage( 
							GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), CB_GETCURSEL, 0, 0 ) ) != CB_ERR )
					{
						AA_TRACE( ( TEXT( "ConfigProfileDlgProc::dwSelected: %d" ), dwSelected ) );

						if( ( dwProfileIDSize = 
							( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
														CB_GETLBTEXTLEN, dwSelected, 0 ) ) != CB_ERR )
						{
							AA_TRACE( ( TEXT( "ConfigProfileDlgProc::CB_GETLBTEXTLEN: %d" ), dwSelected ) );

							if( ( dwProfileIDSize > 0 ) && 
								( dwProfileIDSize <= sizeof( pConfigData->pwcProfileId ) ) )
							{
								AA_TRACE( ( TEXT( "ConfigProfileDlgProc::copying InnerAuth: %d" ), dwProfileIDSize ) );

								memset( pConfigData->pwcProfileId, 
										0, 
										sizeof( pConfigData->pwcProfileId ) );
								
								dwErr = ( DWORD ) SendMessage( GetDlgItem( hWnd, IDC_CONFIG_PROFILES ), 
																CB_GETLBTEXT, 
																dwSelected, 
																( LPARAM ) pConfigData->pwcProfileId );

								AA_TRACE( ( TEXT( "ConfigProfileDlgProc::dwSelected: %s" ), pConfigData->pwcProfileId ) );
							}
							else
							{
								AA_TRACE( ( TEXT( "ConfigProfileDlgProc::dwSelected: %ld, too big" ), dwSelected ) );

								dwErr = CB_ERR;
							}
						}
						else
						{
							AA_TRACE( ( TEXT( "ConfigProfileDlgProc::SendMessage( CB_GETLBTEXTLEN ) Failed: %d" ), GetLastError() ) );

							dwErr = CB_ERR;
						}
					}
					else
					{
						AA_TRACE( ( TEXT( "ConfigProfileDlgProc::SendMessage( CB_GETCURSEL ) Failed: %d" ), GetLastError() ) );

						dwErr = CB_ERR;
					}

					return TRUE;

				break;

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

//
// Name: ProfileDlgProc
// Description: Dialog Function for the Profile Selection Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ProfileDlgProc(	IN  HWND    hWnd,
				IN  UINT    unMsg,
				IN  WPARAM  wParam,
				IN  LPARAM  lParam )
{
    PSW2_PROFILE_DATA		pProfileData;
	WCHAR					pwcTemp[MAX_PATH*2];
#ifdef _WIN32_WCE
	static HWND				hWndCB;
	static SHACTIVATEINFO	hSHActInfo;
	static WCHAR			pwcTempPassword[PWLEN];
	SHINITDLGINFO			shidi;
#endif // _WIN32_WCE
	int						iSel;
	TCITEM					tie; 
	DWORD					dwErr = NO_ERROR;
	NMHDR					*pnmH;
	
    switch( unMsg )
    {
		case WM_INITDIALOG:

			AA_TRACE( ( TEXT( "ProfileDlgProc:: WM_INITDIALOG" ) ) );

			pProfileData = ( PSW2_PROFILE_DATA ) lParam;

			swprintf( pwcTemp, TEXT( "SecureW2 Profile: %s" ), pProfileData->pwcCurrentProfileId );

			SetWindowText( hWnd, pwcTemp );

/*			memset( pcTemp, 0, sizeof( pcTemp ) );

			GetClassName( hWnd, pwcTemp, sizeof( pcTemp ) ); 

			WideCharToMultiByte( CP_ACP, 0, pwcTemp, -1, pcTemp, sizeof( pcTemp ), NULL, NULL );

#ifdef AA_TRACE
			AA_TRACE( ( TEXT( "ProfileDlgProc:: WM_INITDIALOG:: %s", pcTemp );
#endif
*/
#ifdef _WIN32_WCE
			shidi.dwMask = SHIDIM_FLAGS;
			shidi.dwFlags = SHIDIF_DONEBUTTON | SHIDIF_SIPDOWN |SHIDIF_SIZEDLGFULLSCREEN;
			shidi.hDlg = hWnd;

			SHInitDialog( &shidi );

			AA_CreateCommandBar( hWnd );

#endif // _WIN32_WCE

			//
			// Only Administrators can see the full configuration
			//
			if( AA_IsAdmin() )
			{
				tie.mask = TCIF_TEXT | TCIF_IMAGE; 
				tie.iImage = -1; 

				LoadString( ghInstance, IDS_TAB_CONNECTION, pwcTemp, sizeof( pwcTemp ) );

				tie.pszText = pwcTemp; 
 
				TabCtrl_InsertItem( GetDlgItem( hWnd, IDC_PROFILE_TAB ), 0, &tie );

				LoadString( ghInstance, IDS_TAB_CERTIFICATES, pwcTemp, sizeof( pwcTemp ) );

				tie.pszText = pwcTemp; 
	 
				TabCtrl_InsertItem( GetDlgItem( hWnd, IDC_PROFILE_TAB ), 1, &tie );

				LoadString( ghInstance, IDS_TAB_AUTHENTICATION, pwcTemp, sizeof( pwcTemp ) );

				tie.pszText = pwcTemp; 

				TabCtrl_InsertItem( GetDlgItem( hWnd, IDC_PROFILE_TAB ), 2, &tie );

				LoadString( ghInstance, IDS_TAB_USERACCOUNT, pwcTemp, sizeof( pwcTemp ) );

				tie.pszText = pwcTemp; 

				TabCtrl_InsertItem( GetDlgItem( hWnd, IDC_PROFILE_TAB ), 3, &tie );
			
				AA_TRACE( ( TEXT( "ProfileDlgProc:: showing dialog" ) ) );

				pProfileData->hWndTabs[0] = CreateDialogParam( ghInstance, 
															MAKEINTRESOURCE(IDD_CONFIG_CON_DLG),
															hWnd,
															ConfigConnDlgProc,
															( LPARAM ) pProfileData ); 

				pProfileData->hWndTabs[1] = CreateDialogParam( ghInstance, 
															MAKEINTRESOURCE(IDD_CONFIG_CERT_DLG),
															hWnd,
															ConfigCertDlgProc,
															( LPARAM ) pProfileData ); 

				pProfileData->hWndTabs[2] = CreateDialogParam( ghInstance, 
															MAKEINTRESOURCE(IDD_CONFIG_AUTH_DLG),
															hWnd,
															ConfigAuthDlgProc,
															( LPARAM ) pProfileData ); 

				pProfileData->hWndTabs[3] = CreateDialogParam( ghInstance, 
															MAKEINTRESOURCE(IDD_CONFIG_USER_DLG),
															hWnd,
															ConfigUserDlgProc,
															( LPARAM ) pProfileData ); 

				SetWindowPos( pProfileData->hWndTabs[0], HWND_TOP, 0,0,0,0, SWP_SHOWWINDOW | SWP_NOSIZE |SWP_NOMOVE );
				SetWindowPos( pProfileData->hWndTabs[1], HWND_TOP, 0,0,0,0, SWP_HIDEWINDOW | SWP_NOSIZE |SWP_NOMOVE );
				SetWindowPos( pProfileData->hWndTabs[2], HWND_TOP, 0,0,0,0, SWP_HIDEWINDOW | SWP_NOSIZE |SWP_NOMOVE );
				SetWindowPos( pProfileData->hWndTabs[3], HWND_TOP, 0,0,0,0, SWP_HIDEWINDOW | SWP_NOSIZE |SWP_NOMOVE );

			}
			else
			{
				tie.mask = TCIF_TEXT | TCIF_IMAGE; 
				tie.iImage = -1; 
				tie.pszText = L"User account";
	 
				TabCtrl_InsertItem( GetDlgItem( hWnd, IDC_PROFILE_TAB ), 1, &tie );
			
				AA_TRACE( ( TEXT( "ProfileDlgProc:: showing dialog" ) ) );

				pProfileData->hWndTabs[0] = CreateDialogParam( ghInstance, 
															MAKEINTRESOURCE(IDD_CONFIG_USER_DLG),
															hWnd,
															ConfigUserDlgProc,
															( LPARAM ) pProfileData ); 

				SetWindowPos( pProfileData->hWndTabs[0], HWND_TOP, 0,0,0,0, SWP_SHOWWINDOW | SWP_NOSIZE |SWP_NOMOVE );
			}

			//
			// Only admins can see and access the advanced options
			//
			if( !AA_IsAdmin() )
			{
				EnableWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_ADVANCED ), FALSE );

				ShowWindow( GetDlgItem( hWnd, IDC_CONFIG_USER_ADVANCED ), SW_HIDE );
			}

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pProfileData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pProfileData );
#endif // _WIN32_WCE

			return FALSE;

		break;

		case WM_SHOWWINDOW:

			switch( LOWORD( wParam ) )
			{
				case TRUE:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( iSel = TabCtrl_GetCurSel( GetDlgItem( hWnd, IDC_PROFILE_TAB ) ) ) < AA_MAX_CONFIG_TAB )
					{
						ShowWindow( pProfileData->hWndTabs[0], FALSE );

						if( AA_IsAdmin() )
						{
							ShowWindow( pProfileData->hWndTabs[1], FALSE );
							ShowWindow( pProfileData->hWndTabs[2], FALSE );
							ShowWindow( pProfileData->hWndTabs[3], FALSE );
						}

						ShowWindow( pProfileData->hWndTabs[iSel], TRUE );
					}

				break;

				default:

				break;
			}

			return FALSE;

		break;

		case WM_NOTIFY:

			switch( wParam )
			{
				case IDC_PROFILE_TAB:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					pnmH = ( NMHDR * ) lParam;

					switch( pnmH->code )
					{
						case TCN_SELCHANGE:

							AA_TRACE( ( TEXT( "ProfileDlgProc::TCN_SELCHANGE" ) ) );

							if( ( iSel = TabCtrl_GetCurSel( GetDlgItem( hWnd, IDC_PROFILE_TAB ) ) ) < AA_MAX_CONFIG_TAB )
							{
								ShowWindow( pProfileData->hWndTabs[0], FALSE );

								if( AA_IsAdmin() )
								{
									ShowWindow( pProfileData->hWndTabs[1], FALSE );
									ShowWindow( pProfileData->hWndTabs[2], FALSE );
									ShowWindow( pProfileData->hWndTabs[3], FALSE );
								}

								ShowWindow( pProfileData->hWndTabs[iSel], TRUE );
							}

							return FALSE;

						break;
					}

				break;

				default:

						return FALSE;

				break;
			}

		break;

	    case WM_COMMAND:

			AA_TRACE( ( TEXT( "ProfileDlgProc::WM_COMMAND: %ld" ), LOWORD( wParam ) ) );

			switch( LOWORD( wParam ) )
			{
				case IDC_CONFIG_USER_ADVANCED:

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( DialogBoxParam( ghInstance,
										MAKEINTRESOURCE(IDD_CONFIG_ADVANCED_DLG),
										hWnd,
										ConfigAdvancedDlgProc,
										( LPARAM ) pProfileData ) )
					{
						SendMessage( hWnd, WM_SHOWWINDOW, TRUE, 0 );
					}

					return FALSE;

				break;

				case IDOK:

					AA_TRACE( ( TEXT( "ProfileDlgProc::IDOK" ) ) );

#ifdef _WIN32_WCE
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pProfileData = ( PSW2_PROFILE_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					SendMessage( pProfileData->hWndTabs[0], WM_COMMAND, IDOK, 0 );
					
					if( AA_IsAdmin() )
					{
						SendMessage( pProfileData->hWndTabs[1], WM_COMMAND, IDOK, 0 );
						SendMessage( pProfileData->hWndTabs[2], WM_COMMAND, IDOK, 0 );
						SendMessage( pProfileData->hWndTabs[3], WM_COMMAND, IDOK, 0 );
					}

					EndDialog( hWnd, TRUE );

					return FALSE;

				break;

				case IDCANCEL:

					AA_TRACE( ( TEXT( "ProfileDlgProc::IDCANCEL" ) ) );

					EndDialog( hWnd, FALSE );

					return TRUE;

				break;

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


//
// Name: ConfigDlgProc
// Description: Dialog Function for the main SecureW2 Configuration Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
ConfigDlgProc(	IN  HWND    hWnd,
				IN  UINT    unMsg,
				IN  WPARAM  wParam,
				IN  LPARAM  lParam )
{
    PSW2_CONFIG_DATA		pConfigData;
	WCHAR					pwcTemp[MAX_PATH*2];
#ifdef _WIN32_WCE
	static HWND				hWndCB;
	static SHACTIVATEINFO	hSHActInfo;
	static WCHAR			pwcTempPassword[PWLEN];
	SHINITDLGINFO			shidi;
#endif // _WIN32_WCE
	int						iSel;
	TCITEM					tie; 
	DWORD					dwErr = NO_ERROR;
	NMHDR					*pnmH;
	
    switch( unMsg )
    {
		case WM_INITDIALOG:

			AA_TRACE( ( TEXT( "ConfigDlgProc:: WM_INITDIALOG" ) ) );

			pConfigData = ( PSW2_CONFIG_DATA ) lParam;

#ifdef _WIN32_WCE
			shidi.dwMask = SHIDIM_FLAGS;
			shidi.dwFlags = SHIDIF_DONEBUTTON | SHIDIF_SIPDOWN |SHIDIF_SIZEDLGFULLSCREEN;
			shidi.hDlg = hWnd;

			SHInitDialog( &shidi );

			AA_CreateCommandBar( hWnd );

#endif // _WIN32_WCE

			tie.mask = TCIF_TEXT | TCIF_IMAGE; 
			tie.iImage = -1; 
				
			LoadString( ghInstance, IDS_TAB_PROFILE, pwcTemp, sizeof( pwcTemp ) );

			tie.pszText = pwcTemp; 

			TabCtrl_InsertItem( GetDlgItem( hWnd, IDC_CONFIG_TAB ), 0, &tie );

#ifndef _WIN32_WCE

			if( AA_IsAdmin() )
			{
				LoadString( ghInstance, IDS_TAB_GINA, pwcTemp, sizeof( pwcTemp ) );

				tie.pszText = pwcTemp; 

				TabCtrl_InsertItem( GetDlgItem( hWnd, IDC_CONFIG_TAB ), 1, &tie );
			}

#endif // _WIN32_WCE
			
			AA_TRACE( ( TEXT( "ConfigDlgProc:: showing dialog" ) ) );

			pConfigData->hWndTabs[0] = CreateDialogParam( ghInstance, 
														MAKEINTRESOURCE(IDD_CONFIG_PROFILE_DLG),
														hWnd,
														ConfigProfileDlgProc,
														( LPARAM ) pConfigData ); 

#ifndef _WIN32_WCE
			if( AA_IsAdmin() )
			{
				pConfigData->hWndTabs[1] = CreateDialogParam( ghInstance, 
															MAKEINTRESOURCE(IDD_CONFIG_GINA_DLG),
															hWnd,
															ConfigGinaDlgProc,
															( LPARAM ) pConfigData ); 
			}
#endif // _WIN32_WCE

			SetWindowPos( pConfigData->hWndTabs[0], 
							HWND_TOP, 0,0,0,0, 
							SWP_SHOWWINDOW | SWP_NOSIZE |SWP_NOMOVE );

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pConfigData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pConfigData );
#endif // _WIN32_WCE

			return FALSE;

		break;

		case WM_NOTIFY:

			switch( wParam )
			{
				case IDC_CONFIG_TAB:

#ifdef _WIN32_WCE
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					pnmH = ( NMHDR * ) lParam;

					switch( pnmH->code )
					{
						case TCN_SELCHANGE:

							AA_TRACE( ( TEXT( "ConfigDlgProc::TCN_SELCHANGE" ) ) );

							if( ( iSel = TabCtrl_GetCurSel( GetDlgItem( hWnd, IDC_CONFIG_TAB ) ) ) < AA_MAX_CONFIG_TAB )
							{
								ShowWindow( pConfigData->hWndTabs[0], FALSE );
#ifndef _WIN32_WCE
								if( AA_IsAdmin() )
								{
									ShowWindow( pConfigData->hWndTabs[1], FALSE );
								}
#endif // _WIN32_WCE

								ShowWindow( pConfigData->hWndTabs[iSel], TRUE );
							}

							return FALSE;

						break;
					}

				break;

				default:

						return FALSE;

				break;
			}

		break;

	    case WM_COMMAND:

			AA_TRACE( ( TEXT( "ConfigDlgProc::WM_COMMAND: %ld" ), LOWORD( wParam ) ) );

			switch( LOWORD( wParam ) )
			{
				case IDOK:

					AA_TRACE( ( TEXT( "ConfigDlgProc::IDOK" ) ) );

#ifdef _WIN32_WCE
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pConfigData = ( PSW2_CONFIG_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					SendMessage( pConfigData->hWndTabs[0], WM_COMMAND, IDOK, 0 );
#ifndef _WIN32_WCE
					if( AA_IsAdmin() )
					{
						SendMessage( pConfigData->hWndTabs[1], WM_COMMAND, IDOK, 0 );
					}
#endif // _WIN32_WCE

					EndDialog( hWnd, TRUE );

					return FALSE;

				break;

				case IDCANCEL:

					AA_TRACE( ( TEXT( "ConfigDlgProc::IDCANCEL" ) ) );

					EndDialog( hWnd, FALSE );

					return TRUE;

				break;

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

//
// Name: TLSServerTrustDlgProc
// Description: Dialog Function for the "Untrusted Server" Dialog
// Author: Tom Rixom
// Created: 12 May 2004
//
INT_PTR
CALLBACK
TLSServerTrustDlgProc(	IN  HWND    hWnd,
							IN  UINT    unMsg,
							IN  WPARAM  wParam,
							IN  LPARAM  lParam )
{
#ifdef _WIN32_WCE
	SHINITDLGINFO				shidi;
#endif //  _WIN32_WCE
	PSW2_SESSION_DATA			pSessionData;
	PCCERT_CONTEXT				pCertContext;
	SHELLEXECUTEINFO			ExecInfo;
	CHAR						pcTemp[UNLEN];
	WCHAR						pwcTemp[MAX_PATH*2];
	WCHAR						pwcTemp1[UNLEN];
	WCHAR						pwcTemp2[UNLEN];
	HCERTSTORE					hCertStore;
	HIMAGELIST					hImageList;
	HTREEITEM					hSelectedItem;
	TVITEM						tvItem;
	HCRYPTPROV					hCSP;
	PBYTE						pbSHA1;
	DWORD						cbSHA1;
	DWORD						dwErr;
	FILE						*pFile;
	int							i;
	DWORD						dwRet = NO_ERROR;

    switch( unMsg )
    {
		case WM_INITDIALOG:
        
			AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: WM_INITDIALOG" ) ) );

			pSessionData = ( PSW2_SESSION_DATA ) lParam;

#ifdef _WIN32_WCE
			// Create a Done button and size it.  
			shidi.dwMask = SHIDIM_FLAGS;
			shidi.dwFlags = SHIDIF_DONEBUTTON | SHIDIF_SIPDOWN |SHIDIF_SIZEDLGFULLSCREEN;
			shidi.hDlg = hWnd;

			SHInitDialog( &shidi );

			AA_CreateCommandBar( hWnd );

#endif // _WIN32_WCE
			
			//
			// If this is not an administrator then we cannot install certificates
			// can only connect using temp trust
			//
			if( !AA_IsAdmin() )
			{
				//
				// Disable install button
				//
				EnableWindow( GetDlgItem( hWnd, IDINSTALLCERT ), FALSE );
				EnableWindow( GetDlgItem( hWnd, IDINSTALLCERTS ), FALSE );
			}

			//
			// Create image list for tree view control and add icons to 
			// the images list
			//
			hImageList = ImageList_Create( 16, 16, TRUE, 2, 2 );

			ImageList_AddIcon( hImageList, LoadIcon( ghInstance, MAKEINTRESOURCE( IDI_CERT_ICON ) ) );
			ImageList_AddIcon( hImageList, LoadIcon( ghInstance, MAKEINTRESOURCE( IDI_CERT_ICON_ERROR ) ) );

			TreeView_SetImageList( GetDlgItem( hWnd, IDC_CERT_TREE ), hImageList, TVSIL_NORMAL);

			ConfigUpdateCertificateView( hWnd, pSessionData );

#ifdef _WIN32_WCE
			SetWindowLong( hWnd, GWL_USERDATA, ( LONG_PTR ) pSessionData );
#else
			SetWindowLongPtr( hWnd, GWLP_USERDATA, ( LONG_PTR ) pSessionData );
#endif // _WIN32_WCE
			
			return FALSE;

		break;

	    case WM_COMMAND:

			switch( LOWORD( wParam ) )
			{
				case IDINSTALLCERTS:

					AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDINSTALLCERTS" ) ) );

#ifdef _WIN32_WCE
					pSessionData = ( PSW2_SESSION_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pSessionData = ( PSW2_SESSION_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					AA_TRACE( ( TEXT( "TLSServerTrustDlgProc::IDINSTALLCERTS:: number of certs: %ld" ), pSessionData->dwCertCount ) );

					for( i=0; ( DWORD ) i < pSessionData->dwCertCount; i++ )
					{
						if( ( pCertContext = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
																			pSessionData->pbCertificate[i], 
																			pSessionData->cbCertificate[i]) ) )
						{
							AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: created pCerContext[%ld]" ), i ) );

							//
							// If this is the first certificate in line (server certificate) then 
							// put it in the MY store, else in the ROOT (CA certificate
							//
							if( i == 0 )
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
																		CERT_STORE_ADD_REPLACE_EXISTING, 
																		NULL ) )
								{
									AA_TRACE( ( TEXT( "TLSServerTrustDlgProc::IDINSTALLCERTS::CertAddCertificateContextToStore(), FAILED: %x" ), GetLastError() ) );

									dwRet = SEC_E_UNTRUSTED_ROOT;
								}

								CertCloseStore( hCertStore, CERT_CLOSE_STORE_FORCE_FLAG );
							}
							else
							{
								AA_TRACE( ( TEXT( "TLSServerTrustDlgProc::IDINSTALLCERTS::CertOpenSystemStore(), FAILED: %x" ), GetLastError() ) );

								dwRet = SEC_E_UNTRUSTED_ROOT;
							}

							if( i == ( int ) ( pSessionData->dwCertCount - 1 ) )
							{
								//
								// Also add last certificate to our CA list
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
											AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDINSTALLCERTS::CryptAcquireContext(NEWKEYSET):: FAILED (%d)" ), GetLastError() ) );

											dwRet = ERROR_ENCRYPTION_FAILED;
										}
									}
									else
									{
										AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDINSTALLCERTS::CryptAcquireContext(0):: FAILED (%d)" ), GetLastError() ) );

										dwRet = ERROR_ENCRYPTION_FAILED;
									}
								}

								if( dwRet == NO_ERROR )
								{
				
									//
									// Get HASH of certificate
									//
									if( ( dwRet = TLSGetSHA1( hCSP, 
																pSessionData->pbCertificate[i], 
																pSessionData->cbCertificate[i], 
																&pbSHA1, 
																&cbSHA1 ) ) == NO_ERROR )
									{
										AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDINSTALLCERTS: pSessionData->pProfileData->dwNrOfTrustedRootCAInList: %ld" ), pSessionData->pProfileData->dwNrOfTrustedRootCAInList ) );

										//
										// If not in list then add it
										//
										if( AA_VerifyCertificateInList( pSessionData, pbSHA1 ) != NO_ERROR )
										{
											memcpy( pSessionData->pProfileData->pbTrustedRootCAList[pSessionData->pProfileData->dwNrOfTrustedRootCAInList], 
												pbSHA1, 
												cbSHA1 );

											pSessionData->pProfileData->dwNrOfTrustedRootCAInList++;

											dwRet = AA_WriteCertificates( pSessionData->pProfileData->pwcCurrentProfileId,
																			*( pSessionData->pProfileData ) );
										}

										free( pbSHA1 );
									}
									else
									{
										AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDINSTALLCERTS:: TLSGetMD5 FAILED: %ld" ), dwRet ) );
									}

									CryptReleaseContext( hCSP, 0 );
								}
							}

							CertFreeCertificateContext( pCertContext );

							pCertContext = NULL;
						}
						else
						{
							AA_TRACE( ( TEXT( "TLSServerTrustDlgProc::IDINSTALLCERTS::CertCreateCertificateContext(), FAILED: %x" ), GetLastError() ) );

							dwRet = SEC_E_UNTRUSTED_ROOT;
						}
						
						if( dwRet != NO_ERROR )
							break;
					}

					memset( pwcTemp1, 0, sizeof( pwcTemp1 ) );
					memset( pwcTemp2, 0, sizeof( pwcTemp2 ) );

					if( dwRet == NO_ERROR )
					{
						LoadString( ghInstance, IDS_CERTIFICATES_SUCCESS, pwcTemp1, sizeof( pwcTemp1 ) );
						LoadString( ghInstance, IDS_SW2_CERTIFICATE, pwcTemp2, sizeof( pwcTemp2 ) );

						MessageBox( hWnd, pwcTemp1, pwcTemp2, MB_OK );
					}
					else
					{
						LoadString( ghInstance, IDS_CERTIFICATES_FAILED, pwcTemp1, sizeof( pwcTemp1 ) );
						LoadString( ghInstance, IDS_SW2_ERROR, pwcTemp2, sizeof( pwcTemp2 ) );

						MessageBox( hWnd, pwcTemp1, pwcTemp2, MB_ICONERROR | MB_OK );
					}

					ConfigUpdateCertificateView( hWnd, pSessionData );

					return FALSE;

				break;

				case IDINSTALLCERT:

					AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDINSTALLCERT" ) ) );

#ifdef _WIN32_WCE
					pSessionData = ( PSW2_SESSION_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pSessionData = ( PSW2_SESSION_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( hSelectedItem = TreeView_GetSelection( GetDlgItem( hWnd, IDC_CERT_TREE ) ) ) )
					{
						tvItem.mask = TVIF_PARAM;
						tvItem.hItem = hSelectedItem;

						if( TreeView_GetItem( GetDlgItem( hWnd, IDC_CERT_TREE ), &tvItem ) )
						{
							AA_TRACE( ( TEXT( "TLSServerTrustDlgProc::IDINSTALLCERT::selected item: %d" ), ( int ) tvItem.lParam ) );

							if( ( pCertContext = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
																				pSessionData->pbCertificate[( int ) tvItem.lParam], 
																				pSessionData->cbCertificate[( int ) tvItem.lParam]) ) )
							{
								if( ( int ) tvItem.lParam == 0 )
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
																			CERT_STORE_ADD_REPLACE_EXISTING, 
																			NULL ) )
									{
										AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDINSTALLCERT::CertAddCertificateContextToStore(), FAILED: %x" ), GetLastError() ) );

										dwRet = SEC_E_UNTRUSTED_ROOT;
									}

									CertCloseStore( hCertStore, CERT_CLOSE_STORE_FORCE_FLAG );
								}
								else
								{
									AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDINSTALLCERT::CertOpenSystemStore(), FAILED: %x" ), GetLastError() ) );

									dwRet = SEC_E_UNTRUSTED_ROOT;
								}

								if( ( int ) tvItem.lParam == ( int ) ( pSessionData->dwCertCount - 1 ) )
								{
									//
									// Also add last certificate to our CA list
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
												AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDINSTALLCERT::CryptAcquireContext(NEWKEYSET):: FAILED (%d)" ), GetLastError() ) );

												dwRet = ERROR_ENCRYPTION_FAILED;
											}
										}
										else
										{
											AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDINSTALLCERT::CryptAcquireContext(0):: FAILED (%d)" ), GetLastError() ) );

											dwRet = ERROR_ENCRYPTION_FAILED;
										}
									}

									if( dwRet == NO_ERROR )
									{
					
										//
										// Get HASH of certificate
										//
										if( ( dwRet = TLSGetSHA1( hCSP, 
																	pSessionData->pbCertificate[( int ) tvItem.lParam], 
																	pSessionData->cbCertificate[( int ) tvItem.lParam], 
																	&pbSHA1, 
																	&cbSHA1 ) ) == NO_ERROR )
										{
											//
											// If not in list then add
											//
											if( AA_VerifyCertificateInList( pSessionData, pbSHA1 ) != NO_ERROR )
											{
												AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDINSTALLCERT: pSessionData->pProfileData->dwNrOfTrustedRootCAInList: %ld" ), pSessionData->pProfileData->dwNrOfTrustedRootCAInList ) );

												memcpy( pSessionData->pProfileData->pbTrustedRootCAList[pSessionData->pProfileData->dwNrOfTrustedRootCAInList], 
														pbSHA1, 
														cbSHA1 );

												pSessionData->pProfileData->dwNrOfTrustedRootCAInList++;

												dwRet = AA_WriteCertificates( pSessionData->pProfileData->pwcCurrentProfileId,
																				*( pSessionData->pProfileData ) );
											}

											free( pbSHA1 );
										}
										else
										{
											AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDINSTALLCERT:: TLSGetMD5 FAILED: %ld" ), dwRet ) );
										}

										CryptReleaseContext( hCSP, 0 );
									}
								}

								CertFreeCertificateContext( pCertContext );
							}
							else
							{
								AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDINSTALLCERT::CertCreateCertificateContext(), FAILED: %x" ), GetLastError() ) );

								dwRet = SEC_E_UNTRUSTED_ROOT;
							}
						}
						else
						{
							AA_TRACE( ( TEXT( "TLSServerTrustDlgProc::ERROR::TreeView_GetItem() Failed: %d" ), GetLastError() ) );

							dwRet = SEC_E_UNTRUSTED_ROOT;
						}
					}
					else
					{

						AA_TRACE( ( TEXT( "TLSServerTrustDlgProc::ERROR::TreeView_GetSelection() Failed: %d" ), GetLastError() ) );

						dwRet = SEC_E_UNTRUSTED_ROOT;
					}

					memset( pwcTemp1, 0, sizeof( pwcTemp1 ) );
					memset( pwcTemp2, 0, sizeof( pwcTemp2 ) );

					if( dwRet == NO_ERROR )
					{
						LoadString( ghInstance, IDS_CERTIFICATE_SUCCESS, pwcTemp1, sizeof( pwcTemp1 ) );
						LoadString( ghInstance, IDS_SW2_CERTIFICATE, pwcTemp2, sizeof( pwcTemp2 ) );

						MessageBox( hWnd, pwcTemp1, pwcTemp2, MB_OK );
					}
					else
					{
						LoadString( ghInstance, IDS_CERTIFICATE_FAILED, pwcTemp1, sizeof( pwcTemp1 ) );
						LoadString( ghInstance, IDS_SW2_ERROR, pwcTemp2, sizeof( pwcTemp2 ) );

						MessageBox( hWnd, pwcTemp1, pwcTemp2, MB_ICONERROR | MB_OK );
					}

					ConfigUpdateCertificateView( hWnd, pSessionData );

					return FALSE;

				break;

				case IDVIEWCERT:

					AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDVIEWCERT" ) ) );

#ifdef _WIN32_WCE
					pSessionData = ( PSW2_SESSION_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pSessionData = ( PSW2_SESSION_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE

					if( ( hSelectedItem = TreeView_GetSelection( GetDlgItem( hWnd, IDC_CERT_TREE ) ) ) )
					{
						tvItem.mask = TVIF_PARAM;
						tvItem.hItem = hSelectedItem;

						if( TreeView_GetItem( GetDlgItem( hWnd, IDC_CERT_TREE ), &tvItem ) )
						{
							AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: selected item: %d" ), ( int ) tvItem.lParam ) );

							memset( pwcTemp, 0, sizeof( pwcTemp ) );
#ifdef _WIN32_WCE
							wcscpy( pwcTemp, L"\\Temp" );
#else
							if( GetEnvironmentVariable( L"TMP", pwcTemp, ( sizeof( pwcTemp ) / sizeof( WCHAR ) ) ) == 0 )
							{
								if( GetEnvironmentVariable( L"TEMP", pwcTemp, ( sizeof( pwcTemp ) / sizeof( WCHAR ) ) ) == 0 )
									wcscpy( pwcTemp, L"c:\\" );
							}
#endif

							wcscat( pwcTemp, L"\\aa.cer" );

							WideCharToMultiByte( CP_ACP, 0, pwcTemp, -1, pcTemp, sizeof( pcTemp ), NULL, NULL );

							AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: opening temp file: %s" ), pcTemp ) );

							if( ( pFile = fopen( pcTemp, "w+b" ) ) )
							{
								AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: opened file" ) ) );

								fwrite( pSessionData->pbCertificate[( int ) tvItem.lParam], sizeof( BYTE ), pSessionData->cbCertificate[( int ) tvItem.lParam], pFile );

								fflush( pFile );

								fclose( pFile );

								AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: spawning viewer" ) ) );

								memset( &ExecInfo, 0, sizeof( ExecInfo ) );

								ExecInfo.cbSize = sizeof( ExecInfo );
								ExecInfo.fMask = SEE_MASK_FLAG_NO_UI;
								ExecInfo.hwnd = hWnd;
								ExecInfo.lpVerb = L"open";
								ExecInfo.lpFile = pwcTemp;
								ExecInfo.nShow = SW_SHOWNORMAL;

								ShellExecuteEx( &ExecInfo );
//								ShellExecute( hWnd, L"open", pwcTemp, NULL, NULL, SW_SHOWNORMAL );
							}
							else
							{
								AA_TRACE( ( TEXT( "TLSServerTrustDlgProc::ERROR:could not create certificate temp file: c:\\servercert.cer" ) ) );
							}
						}
						else
						{
							AA_TRACE( ( TEXT( "TLSServerTrustDlgProc::ERROR::TreeView_GetItem() Failed: %d" ), GetLastError() ) );
						}
					}
					else
					{
						AA_TRACE( ( TEXT( "TLSServerTrustDlgProc::ERROR::TreeView_GetSelection() Failed: %d" ), GetLastError() ) );
					}

					return FALSE;

				break;

#ifdef _WIN32_WCE
				case IDOK:

					AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDOK" ) ) );

					return TRUE;

				break;

				case IDOK2:

					AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDOK2" ) ) );

#else // _WIN32_WCE

				case IDOK:

					AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDOK" ) ) );

#endif // _WIN32_WCE

#ifdef _WIN32_WCE
					pSessionData = ( PSW2_SESSION_DATA ) GetWindowLong( hWnd, GWL_USERDATA );
#else
					pSessionData = ( PSW2_SESSION_DATA ) GetWindowLongPtr( hWnd, GWLP_USERDATA );
#endif // _WIN32_WCE
/*
					if( SendMessage( GetDlgItem( hWnd, IDC_TEMP_CHECK ), BM_GETCHECK, 0, 0 ) == BST_CHECKED )
						pSessionData->bUITempCertTrust = TRUE;
					else
						pSessionData->bUITempCertTrust = FALSE;
*/
					EndDialog( hWnd, TRUE );

					return TRUE;

				break;

				case IDCANCEL:

					AA_TRACE( ( TEXT( "TLSServerTrustDlgProc:: IDCANCEL" ) ) );

					EndDialog( hWnd, FALSE );

					return TRUE;

				break;

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

//
// Name: ConfigUpdateCertificateView
// Description: Helper Function for Certificate Dialog to add
//				Certificates to the Certificate List
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
ConfigUpdateCertificateView( IN HWND hWnd, IN PSW2_SESSION_DATA pSessionData )
{
	WCHAR						pwcItemText[256];
	WCHAR						pwcSubjectName[TLS_MAX_CERT_NAME];
	DWORD						cwcSubjectName;
	PCCERT_CONTEXT				pCertContext;
    TVINSERTSTRUCT 				tvInsertStruct;
	HTREEITEM					hPreviousItem;
	PBYTE						pbSHA1;
	DWORD						cbSHA1;
	HCRYPTPROV					hCSP;
	HTREEITEM					hTreeRoot;
	BOOL						bTrustOK;
	DWORD						dwErr;
	int							i;
	DWORD						dwRet;
	
	dwRet = NO_ERROR;
	//
	// Add all the certificates in the list to the list box
	// starting with the root CA. Check every certificate to see if we trust it or
	// not
	//
	hPreviousItem = NULL;

	if( !TreeView_DeleteItem( GetDlgItem( hWnd, IDC_CERT_TREE ), TVI_ROOT ) )
		return ERROR_NOT_ENOUGH_MEMORY;

	AA_TRACE( ( TEXT( "ConfigUpdateCertificateView::parsing %d certificates" ), pSessionData->dwCertCount ) );

	//
	// This will be used to check if we can enable the OK button
	//
	bTrustOK = TRUE;

	for( i=pSessionData->dwCertCount-1; i > -1; i-- )
	{
		AA_TRACE( ( TEXT( "ConfigUpdateCertificateView::certificate[%d](%d):%s" ), i, pSessionData->cbCertificate[i], AA_ByteToHex( pSessionData->pbCertificate[i], pSessionData->cbCertificate[i] ) ) );

		//
		// Just to make sure
		//
		if( pSessionData->pbCertificate[i] && pSessionData->cbCertificate[i] > 0 )
		{
			//
			// Convert raw certificate into x509 cert context
			//
			if( ( pCertContext = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
																pSessionData->pbCertificate[i], 
																pSessionData->cbCertificate[i] ) ) )
			{
				//
				// Get SubjectName
				//
				memset( pwcSubjectName, 0, sizeof( pwcSubjectName ) );

				if( ( cwcSubjectName = CertGetNameString( pCertContext,
														CERT_NAME_SIMPLE_DISPLAY_TYPE,
														0,
														NULL,
														pwcSubjectName,
														TLS_MAX_CERT_NAME ) ) > 0 )
				{
					AA_TRACE( ( TEXT( "ConfigUpdateCertificateView(), certificate name: %ws" ), pwcSubjectName ) );

					tvInsertStruct.hParent = hPreviousItem;
					tvInsertStruct.item.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM;

					memset( pwcItemText, 0, sizeof( pwcItemText ) );

					tvInsertStruct.item.pszText = pwcSubjectName;

					tvInsertStruct.item.iImage = 0;
					tvInsertStruct.item.iSelectedImage = 0;

					//
					// Verify certificate
					//
					if( i == 0 )
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
							if( ( dwRet = AA_VerifyCertificateChain( pCertContext ) ) == NO_ERROR )
							{
								//
								// If required verify if certificate is installed locally
								//
								if( pSessionData->bServerCertificateLocal && dwRet == NO_ERROR )
								{
									dwRet = AA_VerifyCertificateInStore( pCertContext );
								}
							}
						}
						else
							dwRet = AA_VerifyCertificateInStore( pCertContext );

						if( dwRet == NO_ERROR )
						{
							//
							// If required verify MS Extensions
							//
							if( pSessionData->bVerifyMSExtension )
								dwRet = AA_CertCheckEnhkeyUsage( pCertContext );
						}

						if( dwRet != NO_ERROR )
						{
							bTrustOK = FALSE;

							tvInsertStruct.item.iImage = 1;
							tvInsertStruct.item.iSelectedImage = 1;
						}
					}
					else if( AA_VerifyCertificateChain( pCertContext ) != NO_ERROR )
					{
						bTrustOK = FALSE;

						tvInsertStruct.item.iImage = 1;
						tvInsertStruct.item.iSelectedImage = 1;
					}

					if( i == ( int ) ( pSessionData->dwCertCount - 1 ) )
					{
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

						if( dwRet == NO_ERROR )
						{
							if( ( dwRet = TLSGetSHA1( hCSP, 
											pCertContext->pbCertEncoded, 
											pCertContext->cbCertEncoded, 
											&pbSHA1, &cbSHA1 ) ) == NO_ERROR )
							{
								if( ( AA_VerifyCertificateInList( pSessionData, pbSHA1 ) ) != NO_ERROR )
								{
									AA_VerifyCertificateInList( pSessionData, pbSHA1 );

									bTrustOK = FALSE;

									tvInsertStruct.item.iImage = 1;
									tvInsertStruct.item.iSelectedImage = 1;
								}

								free( pbSHA1 );
							}

							CryptReleaseContext( hCSP, 0 );
						}
					}

					tvInsertStruct.item.lParam = i;

					hPreviousItem = TreeView_InsertItem( GetDlgItem( hWnd, IDC_CERT_TREE ), &tvInsertStruct );
				}
				else
				{
					AA_TRACE( ( TEXT( "ConfigUpdateCertificateView(), CertNameToStr(pwcSubjectName), FAILED: %x" ), GetLastError() ) );

					dwRet = SEC_E_UNTRUSTED_ROOT;
				}

				CertFreeCertificateContext( pCertContext );
			}
			else
			{
				AA_TRACE( ( TEXT( "ConfigUpdateCertificateView(), CertCreateCertificateContext(), FAILED: %x" ), GetLastError() ) );

				dwRet = ERROR_INTERNAL_ERROR;
			}
		}
		else
		{
			AA_TRACE( ( TEXT( "ConfigUpdateCertificateView(), pbCertificate[%d] == NULL or 0" ), i ) );

			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
	} // for

	if( bTrustOK )
#ifdef _WIN32_WCE
		EnableWindow( GetDlgItem( hWnd, IDOK2 ), TRUE );
#else
		EnableWindow( GetDlgItem( hWnd, IDOK ), TRUE );
#endif //  _WIN32_WCE

	hTreeRoot = TreeView_GetRoot( GetDlgItem( hWnd, IDC_CERT_TREE ) );
	TreeView_Expand( GetDlgItem( hWnd, IDC_CERT_TREE ), hTreeRoot, TVM_EXPAND );

	while( hTreeRoot = TreeView_GetNextItem( GetDlgItem( hWnd, IDC_CERT_TREE ),
											hTreeRoot,
											TVGN_CHILD ) )
	{
		TreeView_Expand( GetDlgItem( hWnd, IDC_CERT_TREE ), hTreeRoot, TVM_EXPAND );
	}

	AA_TRACE( ( TEXT( "ConfigUpdateCertificateView(), returning %ld" ), dwRet ) );

	return dwRet;
}