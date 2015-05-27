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
// Name: EAP-TTLS_Utils.c
// Description: Contains the main utility functions
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
#ifndef _WIN32_WCE
#include <aclapi.h>
#endif // _WIN32_WCE

//
// Name: AA_XorData
// Description: Helper function that xors a message using the provided key
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
AA_XorData( PBYTE pbDataIn, DWORD cbDataIn, PBYTE pbKey, DWORD cbKey, PBYTE *ppbDataOut )
{
	PBYTE		pbDataOut;
	int			i,j;
	DWORD		dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "AA_XorData::cbDataIn: %ld, cbKey: %d" ), cbDataIn, cbKey ) );

	if( !pbDataIn )
		return ERROR_NOT_ENOUGH_MEMORY;
	
	if( ( *ppbDataOut = ( PBYTE ) malloc( cbDataIn ) ) )
	{
		pbDataOut = *ppbDataOut;

		for( i=0,j=0; i < ( int ) cbDataIn; j++,i++ )
		{
			pbDataOut[i] = pbDataIn[i] ^ pbKey[j];

			if( ( DWORD ) j > cbKey )
				j = 0;
		}
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

//
// Name: AA_SwapArray
// Description: Helper function for swapping a byte array (big/little endian)
// Author: Tom Rixom
// Created: 11 August 2004
//
VOID
AA_SwapArray( IN BYTE *xIn, OUT BYTE *xOut, IN int xLength )
{
    int i;
    BYTE *xOutPtr;
    BYTE *xInPtr;

    xInPtr = xIn + xLength - 1;
    xOutPtr = xOut;

    for (i = 0; i < xLength; i++)
    {
        *xOutPtr++ = *xInPtr--;
    }
}

//
// Name: AA_SwapArray
// Description: Helper function that converts a hex string to bytes
// Author: Tom Rixom
// Created: 11 August 2004
//
PBYTE
AA_HexToByte( PCHAR String, DWORD *Length )
{
	int xLength, i;
	BYTE hiNibble, loNibble;
	BYTE*	xPtr;
	PCHAR	xString;

	xLength = ( int ) strlen( String ) / 2;
	xPtr = ( PBYTE ) malloc( xLength );

	xString = AA_ToUpperString( String );

	for( i = 0; i < xLength; i++ )
	{
		if( *( String + i*2 ) >= 'A' )
		{
			hiNibble = ( BYTE ) ( * ( xString + i*2 ) - 'A' + 10 );
		}
		else
		{
			hiNibble = ( BYTE ) ( * ( xString + i*2 ) - '0' );
		}

		if( * ( String + i*2 + 1 ) >= 'A' )
		{
			loNibble = ( BYTE ) ( * ( xString + i*2 + 1 ) - 'A' + 10 );
		}
		else
		{
			loNibble = ( BYTE ) ( * ( xString + i*2 + 1 ) - '0' );
		}
		
		*( xPtr + i ) = ( ( hiNibble << 4 ) | loNibble );
	}
	
	free( xString );

	( *Length ) = xLength;

	return xPtr;
}

//
// Name: AA_ByteToHex
// Description: Helper function that converts a byte string to a hex repr.
// Author: Tom Rixom
// Created: 11 August 2004
//
TCHAR *
AA_ByteToHex( BYTE *xBytes, int xLength )
{
	TCHAR *xBuffer;
	TCHAR *xPtr;
	BYTE *xbPtr;
	int i, xByte;

	xBuffer = ( TCHAR* ) malloc( sizeof( TCHAR ) * ( xLength + xLength + 10 ) );
	
	xPtr = xBuffer;
	xbPtr = xBytes;

	for (i = 0; i < xLength; i++)
	{
		xByte = ( *xbPtr & 0xf0 ) >> 4;
		*xPtr++ = ( xByte <= 9) ? xByte + '0' : ( xByte - 10 ) + 'A';
		xByte = (*xbPtr & 0x0f );
		*xPtr++ = (xByte <= 9 ) ? xByte + '0' : ( xByte - 10 ) + 'A';
		xbPtr++;
#ifdef UNICODE
		*xPtr = *xPtr + 1;
#endif
	}

	*xPtr++ = 0;

	return xBuffer;
}

//
// Name: AA_ToUpperString
// Description: Helper function that converts a string to uppercase
// Author: Tom Rixom
// Created: 11 August 2004
//
PCHAR
AA_ToUpperString( PCHAR pcString )
{
	byte	x;
	PCHAR	xPtr;
	int		i = 0;

	xPtr = ( PCHAR ) malloc( strlen( pcString ) + 1 );

	while( *( pcString + i ) != '\0' )
	{
		x = *( pcString + i );

		if( x >= 'a' )
		{
			x = x - 32;
		}
		
		*( xPtr + i ) = x;

		i++;
	}

	*( xPtr + i ) = '\0';
	
	return xPtr;
}

//
// Name: AA_HostToWireFormat32
// Description: Helper function that converts a DWORD to a binary representation
// Author: Tom Rixom
// Created: 11 August 2004
//
VOID
AA_HostToWireFormat32( IN     DWORD dwHostFormat,
					IN OUT PBYTE pWireFormat )
{
    *((PBYTE)(pWireFormat)+0) = (BYTE) ((DWORD)(dwHostFormat) >> 24);
    *((PBYTE)(pWireFormat)+1) = (BYTE) ((DWORD)(dwHostFormat) >> 16);
    *((PBYTE)(pWireFormat)+2) = (BYTE) ((DWORD)(dwHostFormat) >>  8);
    *((PBYTE)(pWireFormat)+3) = (BYTE) (dwHostFormat);
}

//
// Name: AA_HostToWireFormat24
// Description: Helper function that converts a 3 byte DWORD 
//				to a binary representation
// Author: Tom Rixom
// Created: 11 August 2004
//
VOID
AA_HostToWireFormat24(	IN     DWORD  dwHostFormat,
						IN OUT PBYTE pWireFormat )
{
    *((PBYTE)(pWireFormat)+0) = (BYTE) ((DWORD)(dwHostFormat) >>  16);
    *((PBYTE)(pWireFormat)+1) = (BYTE) ((DWORD)(dwHostFormat) >>  8);
    *((PBYTE)(pWireFormat)+2) = (BYTE) (dwHostFormat);
}

//
// Name: AA_HostToWireFormat16
// Description: Helper function that converts a 2 byte DWORD 
//				to a binary representation
// Author: Tom Rixom
// Created: 11 August 2004
//
VOID
AA_HostToWireFormat16(	IN     DWORD  wHostFormat,
					IN OUT PBYTE pWireFormat )
{
    *((PBYTE)(pWireFormat)+0) = (BYTE) ((DWORD)(wHostFormat) >>  8);
    *((PBYTE)(pWireFormat)+1) = (BYTE) (wHostFormat);
}

//
// Name: AA_WireToHostFormat32
// Description: Helper function that converts a 4 binary representation
//				to a DWORD
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
AA_WireToHostFormat32(	IN PBYTE pWireFormat )
{
    DWORD dwHostFormat = ((*((PBYTE)(pWireFormat)+0) << 24) +
				          (*((PBYTE)(pWireFormat)+1) << 16) +
						  (*((PBYTE)(pWireFormat)+2) << 8) +
						  (*((PBYTE)(pWireFormat)+3)));

    return(dwHostFormat);
}

//
// Name: AA_WireToHostFormat24
// Description: Helper function that converts a 3 binary representation
//				to a DWORD
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
AA_WireToHostFormat24(	IN PBYTE pWireFormat )
{
    DWORD dwHostFormat = ((*((PBYTE)(pWireFormat)+0) << 16) +
						 (*((PBYTE)(pWireFormat)+1) << 8) +
                         (*((PBYTE)(pWireFormat)+2)));

    return(dwHostFormat);
}

//
// Name: AA_WireToHostFormat16
// Description: Helper function that converts a 2 binary representation
//				to a DWORD
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
AA_WireToHostFormat16(	IN PBYTE pWireFormat )
{
    DWORD wHostFormat = ((*((PBYTE)(pWireFormat)+0) << 8) +
                        (*((PBYTE)(pWireFormat)+1)));

    return(wHostFormat);
}

#ifndef _WIN32_WCE
//
// Name: AA_GetTextualSid
// Description: Helper function retreive the string representation of a SID
// Author: Tom Rixom
// Created: 11 August 2004
//
BOOL
AA_GetTextualSid( PSID pSid,
					LPTSTR TextualSid,
					LPDWORD lpdwBufferLen )
{
    PSID_IDENTIFIER_AUTHORITY psia;
    DWORD dwSubAuthorities;
    DWORD dwSidRev=SID_REVISION;
    DWORD dwCounter;
    DWORD dwSidSize;

    // Validate the binary SID.

    if(!IsValidSid(pSid)) return FALSE;

    // Get the identifier authority value from the SID.

    psia = GetSidIdentifierAuthority(pSid);

    // Get the number of subauthorities in the SID.

    dwSubAuthorities = *GetSidSubAuthorityCount(pSid);

    // Compute the buffer length.
    // S-SID_REVISION- + IdentifierAuthority- + subauthorities- + NULL

    dwSidSize=(15 + 12 + (12 * dwSubAuthorities) + 1) * sizeof(TCHAR);

    // Check input buffer length.
    // If too small, indicate the proper size and set last error.

    if (*lpdwBufferLen < dwSidSize)
    {
        *lpdwBufferLen = dwSidSize;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    // Add 'S' prefix and revision number to the string.

    dwSidSize=wsprintf(TextualSid, TEXT("S-%lu-"), dwSidRev );

    // Add SID identifier authority to the string.

    if ( (psia->Value[0] != 0) || (psia->Value[1] != 0) )
    {
        dwSidSize+=wsprintf(TextualSid + lstrlen(TextualSid),
                    TEXT("0x%02hx%02hx%02hx%02hx%02hx%02hx"),
                    (USHORT)psia->Value[0],
                    (USHORT)psia->Value[1],
                    (USHORT)psia->Value[2],
                    (USHORT)psia->Value[3],
                    (USHORT)psia->Value[4],
                    (USHORT)psia->Value[5]);
    }
    else
    {
        dwSidSize+=wsprintf(TextualSid + lstrlen(TextualSid),
                    TEXT("%lu"),
                    (ULONG)(psia->Value[5]      )   +
                    (ULONG)(psia->Value[4] <<  8)   +
                    (ULONG)(psia->Value[3] << 16)   +
                    (ULONG)(psia->Value[2] << 24)   );
    }

    // Add SID subauthorities to the string.
    //
    for (dwCounter=0 ; dwCounter < dwSubAuthorities ; dwCounter++)
    {
        dwSidSize+=wsprintf(TextualSid + dwSidSize, TEXT("-%lu"),
                    *GetSidSubAuthority(pSid, dwCounter) );
    }

    return TRUE;
}
#endif // _WIN32_WCE
//
// Name: AA_IsAdmin
// Description: Helper function to determine if the logged on user has Administrator
//				priviliges
// Author: Tom Rixom
// Created: 11 August 2004
//
BOOL 
AA_IsAdmin()
{
#ifdef _WIN32_WCE
	return TRUE;
#else
	HANDLE						hHandle;
	HANDLE						hToken;
    PTOKEN_GROUPS				pTokenGroups;
    DWORD						dwTokenGroupSize;
    PSID						psidAdministrators;
    SID_IDENTIFIER_AUTHORITY	siaNtAuthority = SECURITY_NT_AUTHORITY;
	int							i;
	DWORD						dwErr;
    BOOL						bRet;

	dwTokenGroupSize = 0;

	bRet = FALSE;

	if( ( hHandle = GetCurrentProcess() ) != NULL )
	{
		if( OpenProcessToken( hHandle,
							TOKEN_QUERY, 
							&hToken ) )
		{
			GetTokenInformation( hToken,
								TokenGroups,
								NULL,
								0,
								&dwTokenGroupSize );
				
			dwErr = GetLastError();

			SetLastError( dwErr );

			if( dwErr == ERROR_INSUFFICIENT_BUFFER )
			{
				if( ( pTokenGroups = ( PTOKEN_GROUPS ) malloc( dwTokenGroupSize ) ) )
				{
					if( GetTokenInformation( hToken,
											TokenGroups,
											pTokenGroups,
											dwTokenGroupSize,
											&dwTokenGroupSize ) )
					{
						if( AllocateAndInitializeSid( &siaNtAuthority,
														2,
														SECURITY_BUILTIN_DOMAIN_RID,
														DOMAIN_ALIAS_RID_ADMINS,
														0, 0, 0, 0, 0, 0,
														&psidAdministrators ) )
						{
							bRet = FALSE;

							for( i=0; i < ( int ) pTokenGroups->GroupCount; i++ )
							{
								if( EqualSid( psidAdministrators, pTokenGroups->Groups[i].Sid ) )
								{            
									bRet = TRUE;

									break;
								}
							}

							FreeSid( psidAdministrators );
						}
						else
						{
							AA_TRACE( ( TEXT( "AA_IsAdmin()::AllocateAndInitializeSid() FAILED %d" ), GetLastError() ) );
						}
					}
					else
					{
						AA_TRACE( ( TEXT( "AA_IsAdmin()::GetTokenInformation2() FAILED %d" ), GetLastError() ) );
					}
				
					free( pTokenGroups );
				}
				else
				{
					AA_TRACE( ( TEXT( "AA_IsAdmin()::could not allocate memory for pTokenGroups" ) ) );
				}
			}
			else
			{
				AA_TRACE( ( TEXT( "AA_IsAdmin()::GetTokenInformation() %d FAILED %d" ), dwTokenGroupSize, GetLastError() ) );
			}

			CloseHandle( hToken );
		}
		else
		{
			AA_TRACE( ( TEXT( "AA_IsAdmin:: OpenThreadToken FAILED: %d" ), GetLastError() ) );
		}

		CloseHandle( hHandle );
	}
	else
	{
		AA_TRACE( ( TEXT( "AA_IsAdmin:: GetCurrentThread() FAILED: %d" ), GetLastError() ) );
	}

	AA_TRACE( ( TEXT( "AA_IsAdmin()::returning %d" ), bRet ) );

    return bRet;
#endif // _WIN32_WCE
}

//
// Name: AA_KillWindow
// Description: Helper function for closing windows
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
AA_KillWindow( IN HANDLE hTokenImpersonateUser, LPTSTR pClass, WCHAR *pwcWindowText )
{
	HWND		hWnd;
#ifndef _WIN32_WCE
    DWORD		dwThreadId; 
    HWINSTA		hwinstaSave; 
    HDESK		hdeskSave; 
    HWINSTA		hwinstaUser; 
    HDESK		hdeskUser; 
	DWORD		dwErr;
#endif // _WIN32_WCE
	DWORD		dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "AA_KillWindow" ) ) );

	//
    // Ensure connection to service window station and desktop, and 
    // save their handles. 
	//

#ifndef _WIN32_WCE
    GetDesktopWindow(); 

    hwinstaSave = GetProcessWindowStation(); 
    dwThreadId = GetCurrentThreadId(); 
    hdeskSave = GetThreadDesktop( dwThreadId ); 
 
	dwErr = ImpersonateLoggedOnUser( hTokenImpersonateUser );

	if( ( hwinstaUser = OpenWindowStation( L"WinSta0", FALSE, MAXIMUM_ALLOWED ) ) )
	{
		SetProcessWindowStation( hwinstaUser ); 

		if( ( hdeskUser = OpenDesktop( L"Default", 0, FALSE, MAXIMUM_ALLOWED ) ) )
		{
			SetThreadDesktop( hdeskUser ); 
#endif // _WIN32_WCE

			AA_TRACE( ( TEXT( "AA_KillWindow::killing window" ) ) );

			//
			// Kill any dialogs we have
			//
			if( ( hWnd = FindWindow( pClass, pwcWindowText ) ) )
				EndDialog( hWnd, FALSE );

#ifndef _WIN32_WCE
			SetThreadDesktop( hdeskSave ); 
			CloseDesktop( hdeskUser ); 
		}
		else
		{
			dwRet = GetLastError();

			AA_TRACE( ( TEXT( "AA_KillWindow::OpenDesktop FAILED: %x" ), dwRet ) );
		}

		SetProcessWindowStation( hwinstaSave ); 
		CloseWindowStation( hwinstaUser );
	}
	else
	{
		dwRet = GetLastError();

		AA_TRACE( ( TEXT( "AA_KillWindow::OpenWindowStation FAILED: %x" ), dwRet ) );
	}
	
	if( dwErr == NO_ERROR )
		RevertToSelf();
#endif // _WIN32_WCE


	AA_TRACE( ( TEXT( "AA_KillWindow::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: AA_ReportEvent
// Description: Helper function for sending information to the EventViewer
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
AA_ReportEvent( WCHAR *pwcMsg, WORD wType, DWORD dwError )
{
	DWORD	dwRet;
#ifndef _WIN32_WCE
	WCHAR	*pwcMsgArray[1];
    HANDLE	hHandle; 
#endif

	AA_TRACE( ( TEXT( "AA_ReportErrorEvent( %ws, %x )" ), pwcMsg, dwError ) );

	dwRet = NO_ERROR;

#ifndef _WIN32_WCE
    if( ( hHandle = RegisterEventSource( NULL,
								 L"SecureW2" ) ) )
	{
		pwcMsgArray[0] = pwcMsg;

		if( ReportEvent( hHandle,
							wType,
							0,
							dwError,
							NULL,
							1,
							0,
							pwcMsgArray,
							NULL ) )
		{
			DeregisterEventSource( hHandle );
		}
	}
	else
	{
	}
#endif // _WIN32_WCE

	AA_TRACE( ( TEXT( "AA_ReportErrorEvent() returning" ) ) );

	return dwRet;
}

//
// Name: AA_CreateAdminKey
// Description: Helper function that creates a registry key with Administrator
//				read and write priviliges
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
AA_CreateAdminKey( IN HKEY hKey, IN WCHAR *pwcSubKey, OUT HKEY *phSubKey, OUT DWORD *pdwDisposition )
{
    DWORD						dwRet;
#ifndef _WIN32_WCE
    PSID						pAdminSID = NULL;
    PSID						pEveryoneSID = NULL;
    PACL						pACL = NULL;
    PSECURITY_DESCRIPTOR		pSD = NULL;
    EXPLICIT_ACCESS				ea[1];
    SID_IDENTIFIER_AUTHORITY	SIDAuthNT = SECURITY_NT_AUTHORITY;
    SECURITY_ATTRIBUTES			sa;
#endif // _WIN32_WCE

	AA_TRACE( ( TEXT( "AA_CreateAdminKey" ) ) );

	dwRet = NO_ERROR;

#ifndef _WIN32_WCE

	//
	// Create a SID for the BUILTIN\Administrators group.
	//
	if( AllocateAndInitializeSid( &SIDAuthNT, 
									2,
									SECURITY_BUILTIN_DOMAIN_RID,
									DOMAIN_ALIAS_RID_ADMINS,
									0, 0, 0, 0, 0, 0,
									&pAdminSID ) ) 
	{
		AA_TRACE( ( TEXT( "AA_CreateAdminKey::AllocateAndInitializeSid" ) ) );
	
		memset( &ea, 0, sizeof( EXPLICIT_ACCESS ) );

		//
		// Initialize an EXPLICIT_ACCESS structure for an ACE.
		// The ACE will allow the Administrators group full access to the key.
		//
		ea[0].grfAccessPermissions = KEY_ALL_ACCESS;
		ea[0].grfAccessMode = SET_ACCESS;
		ea[0].grfInheritance= NO_INHERITANCE;
		ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
		ea[0].Trustee.ptstrName  = ( LPTSTR ) pAdminSID;

		//
		// Create a new ACL that contains the new ACEs.
		//
		if( ( dwRet = SetEntriesInAcl( 1, ea, NULL, &pACL ) ) == ERROR_SUCCESS )
		{
			AA_TRACE( ( TEXT( "AA_CreateAdminKey::SetEntriesInAcl" ) ) );

			//
			// Initialize a security descriptor.  
			//
			if( ( pSD = ( PSECURITY_DESCRIPTOR ) malloc( SECURITY_DESCRIPTOR_MIN_LENGTH ) ) )
			{
				AA_TRACE( ( TEXT( "AA_CreateAdminKey::malloc" ) ) );

				if( InitializeSecurityDescriptor( pSD, SECURITY_DESCRIPTOR_REVISION ) )
				{
					AA_TRACE( ( TEXT( "AA_CreateAdminKey::InitializeSecurityDescriptor" ) ) );

					//
					// Add the ACL to the security descriptor. 
					//
					if( SetSecurityDescriptorDacl( pSD, 
													TRUE,     // bDaclPresent flag   
													pACL, 
													FALSE))   // not a default DACL 
					{  
						AA_TRACE( ( TEXT( "AA_CreateAdminKey::InitializeSecurityDescriptor" ) ) );

						//
						// Initialize a security attributes structure.
						sa.nLength = sizeof (SECURITY_ATTRIBUTES);
						sa.lpSecurityDescriptor = pSD;
						sa.bInheritHandle = FALSE;
#endif // _WIN32_WCE
						//
						// Use the security attributes to set the security descriptor 
						// when you create a key.
						//
						if( RegCreateKeyEx(	hKey, 
											pwcSubKey, 
											0, 
											NULL, 
											0, 
											KEY_ALL_ACCESS, 
#ifndef _WIN32_WCE
											&sa, 
#else
											NULL,
#endif // _WIN32_WCE
											phSubKey, 
											pdwDisposition ) != ERROR_SUCCESS )
						{
							dwRet = ERROR_CANTOPEN;
						}
#ifndef _WIN32_WCE
					}
					else
						dwRet = ERROR_CANTOPEN;
				}
				else
				{
					dwRet = ERROR_CANTOPEN;
				}
				
				free(pSD);
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}

			LocalFree( pACL );	        
		}

		FreeSid( pAdminSID );
	}

#endif // _WIN32_WCE

	AA_TRACE( ( TEXT( "AA_CreateAdminKey::returning %ld" ), dwRet ) );

    return dwRet;
}

//
// Name: AA_CreateSecureKey
// Description: Helper function that creates a registry key with Administrator
//				read and write priviliges and read priviliges for normal users
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
AA_CreateSecureKey( IN HKEY hKey, IN WCHAR *pwcSubKey, OUT HKEY *phSubKey, OUT DWORD *pdwDisposition )
{
    DWORD						dwRet;
#ifndef _WIN32_WCE
    PSID						pAdminSID = NULL;
    PSID						pEveryoneSID = NULL;
    PACL						pACL = NULL;
    PSECURITY_DESCRIPTOR		pSD = NULL;
    EXPLICIT_ACCESS				ea[2];
	SID_IDENTIFIER_AUTHORITY	SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY	SIDAuthNT = SECURITY_NT_AUTHORITY;
    SECURITY_ATTRIBUTES			sa;
#endif // _WIN32_WCE

	AA_TRACE( ( TEXT( "AA_CreateSecureKey" ) ) );

	dwRet = NO_ERROR;

#ifndef _WIN32_WCE

	//
	// Create a well-known SID for the Everyone group.
	//
	if( AllocateAndInitializeSid( &SIDAuthWorld, 
									1,
									SECURITY_WORLD_RID,
									0, 
									0, 0, 0, 0, 0, 0,
									&pEveryoneSID ) )
	{
		//
		// Create a SID for the BUILTIN\Administrators group.
		//
		if( AllocateAndInitializeSid( &SIDAuthNT, 
										2,
										SECURITY_BUILTIN_DOMAIN_RID,
										DOMAIN_ALIAS_RID_ADMINS,
										0, 0, 0, 0, 0, 0,
										&pAdminSID ) ) 
		{
			AA_TRACE( ( TEXT( "AA_CreateSecureKey::AllocateAndInitializeSid" ) ) );
		
			memset( &ea, 0, 2 * sizeof( EXPLICIT_ACCESS ) );

			// Initialize an EXPLICIT_ACCESS structure for an ACE.
			// The ACE will allow Everyone read access to the key.
			ea[0].grfAccessPermissions = KEY_READ;
			ea[0].grfAccessMode = SET_ACCESS;
			ea[0].grfInheritance= NO_INHERITANCE;
			ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
			ea[0].Trustee.ptstrName  = ( LPTSTR ) pEveryoneSID;

			//
			// Initialize an EXPLICIT_ACCESS structure for an ACE.
			// The ACE will allow the Administrators group full access to the key.
			//
			ea[1].grfAccessPermissions = KEY_ALL_ACCESS;
			ea[1].grfAccessMode = SET_ACCESS;
			ea[1].grfInheritance= NO_INHERITANCE;
			ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
			ea[1].Trustee.ptstrName  = ( LPTSTR ) pAdminSID;

			//
			// Create a new ACL that contains the new ACEs.
			//
			if( ( dwRet = SetEntriesInAcl( 2, ea, NULL, &pACL ) ) == ERROR_SUCCESS )
			{
				AA_TRACE( ( TEXT( "AA_CreateSecureKey::SetEntriesInAcl" ) ) );

				//
				// Initialize a security descriptor.  
				//
				if( ( pSD = ( PSECURITY_DESCRIPTOR ) malloc( SECURITY_DESCRIPTOR_MIN_LENGTH ) ) )
				{
					AA_TRACE( ( TEXT( "AA_CreateSecureKey::malloc" ) ) );

					if( InitializeSecurityDescriptor( pSD, SECURITY_DESCRIPTOR_REVISION ) )
					{
						AA_TRACE( ( TEXT( "AA_CreateSecureKey::InitializeSecurityDescriptor" ) ) );

						//
						// Add the ACL to the security descriptor. 
						//
						if( SetSecurityDescriptorDacl( pSD, 
														TRUE,     // bDaclPresent flag   
														pACL, 
														FALSE))   // not a default DACL 
						{  
							AA_TRACE( ( TEXT( "AA_CreateSecureKey::InitializeSecurityDescriptor" ) ) );

							//
							// Initialize a security attributes structure.
							sa.nLength = sizeof (SECURITY_ATTRIBUTES);
							sa.lpSecurityDescriptor = pSD;
							sa.bInheritHandle = FALSE;
#endif // _WIN32_WCE
							//
							// Use the security attributes to set the security descriptor 
							// when you create a key.
							//
							if( RegCreateKeyEx(	hKey, 
												pwcSubKey, 
												0, 
												NULL, 
												0, 
												KEY_READ | KEY_WRITE, 
#ifndef _WIN32_WCE
												&sa, 
#else
												NULL,
#endif // _WIN32_WCE
												phSubKey, 
												pdwDisposition ) != ERROR_SUCCESS )
							{
								dwRet = ERROR_CANTOPEN;
							}
#ifndef _WIN32_WCE
						}
						else
							dwRet = ERROR_CANTOPEN;
					}
					else
					{
						dwRet = ERROR_CANTOPEN;
					}
					
					free(pSD);
				}
				else
				{
					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

				LocalFree( pACL );	        
			}

			FreeSid( pAdminSID );
		}

		FreeSid( pEveryoneSID );
	}

#endif // _WIN32_WCE

	AA_TRACE( ( TEXT( "AA_CreateSecureKey::returning %ld" ), dwRet ) );

    return dwRet;
}

//
// Name: AA_WriteResult
// Description: Helper function that writes the result of a authentication back
//				to the SecureW2 Gina using the registry
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
AA_WriteResult( DWORD dwRet2 )
{
	HKEY	hKey;
	DWORD	dwDisposition = 0;
	DWORD	dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "AA_WriteResult" ) ) );

	//
	// Using SecureW2 Gina so write the result to the gina
	//
	if( ( dwRet = AA_CreateAdminKey( HKEY_LOCAL_MACHINE,
					AA_GINA_LOCATION,
					&hKey,
					&dwDisposition ) ) == NO_ERROR )
	{
		if( ( dwRet = RegSetValueEx( hKey,
									L"Result",
									0,
									REG_DWORD,
									( PBYTE ) &dwRet2,
									sizeof( dwRet2 ) ) ) != NO_ERROR )
		{
			AA_TRACE( ( TEXT( "AA_WriteResult:: RegSetValueEx FAILED: %d" ), dwRet ) );
		}

		RegCloseKey( hKey );
	}
	else
	{
		AA_TRACE( ( TEXT( "RasEapGetIdentity:: AA_CreateAdminKey FAILED: %d" ), dwRet ) );
	}

	AA_TRACE( ( TEXT( "AA_WriteResult::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: AA_RegGetDWORDValue
// Description: Helper function to retrieve a DWORD from the registry
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
AA_RegGetDWORDValue( HKEY hKey, WCHAR *pwcValue, DWORD *pdwData )
{
	DWORD	cbdwData = sizeof( DWORD );
	DWORD	dwType;
	DWORD	dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "AA_RegGetDWORDValue::cbdwData(%d)" ), cbdwData ) );

	if( RegQueryValueEx( hKey,
						pwcValue,
						0,
						&dwType,
						( PBYTE ) pdwData,
						&cbdwData ) != ERROR_SUCCESS )
	{
		AA_TRACE( ( TEXT( "AA_RegGetDWORDValue::RegQueryValueEx(%ws) FAILED: %x" ), pwcValue, GetLastError() ) );

		dwRet = ERROR_CANTOPEN;
	}

	return dwRet;
}

//
// Name: AA_RegGetValue
// Description: Helper function to retrieve a binary from the registry
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
AA_RegGetValue( HKEY hKey, WCHAR *pwcValue, PBYTE *ppbData, DWORD *pcbData )
{
	DWORD	dwType = 0;
	DWORD	dwRet;

	dwRet = NO_ERROR;

	if( RegQueryValueEx( hKey,
						pwcValue,
						0,
						&dwType,
						NULL,
						pcbData ) == ERROR_SUCCESS )
	{
		if( ( *ppbData = ( PBYTE ) malloc( *pcbData ) ) )
		{
			if( RegQueryValueEx( hKey,
								pwcValue,
								0,
								&dwType,
								*ppbData,
								pcbData ) != ERROR_SUCCESS )
			{
				AA_TRACE( ( TEXT( "AA_RegGetValue::RegQueryValueEx2(%ws) FAILED: %x" ), pwcValue, GetLastError() ) );

				free( *ppbData );
				*pcbData = 0;

				dwRet = ERROR_CANTOPEN;
			}
		}
		else
		{
			AA_TRACE( ( TEXT( "AA_RegGetValue::not enough memory for ppbData" ) ) );

			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
	}
	else
	{
		AA_TRACE( ( TEXT( "AA_RegGetValue::RegQueryValueEx(%ws) FAILED: %x" ), pwcValue, GetLastError() ) );

		dwRet = ERROR_CANTOPEN;
	}

	return dwRet;
}

//
// Name: AA_SetBinRegKey
// Description: Helper function to set a binary registry key 
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
AA_SetBinRegKey( WCHAR *pwcKey, PBYTE pbValue, DWORD cbValue )
{
	HKEY	hKey;
	DWORD	dwDisp;
	DWORD	dwRet;

	dwRet = NO_ERROR;

	//
	// Save information in registry:
	// license key and
	// timestamp
	//
	if( RegCreateKeyEx( HKEY_LOCAL_MACHINE,
						AA_CLIENT_REG_LOCATION,
						0,
						NULL,
						0,
						KEY_READ | KEY_WRITE,
						NULL,
						&hKey,
						&dwDisp ) == ERROR_SUCCESS )
	{
		if( RegSetValueEx( hKey,
							pwcKey,
							0,
							REG_BINARY,
							pbValue,
							cbValue ) != ERROR_SUCCESS )
		{
			dwRet = ERROR_CANTOPEN;
		}

		RegCloseKey( hKey );
	}
	else
	{
		AA_TRACE( ( TEXT( "AA_SerialCheck::AA_SetRegKeys FAILED: %x" ), GetLastError() ) );
	}

	return dwRet;
}

#ifndef _WIN32_WCE
DWORD
AA_StartWZCSVC(IN BOOL bAutomatic)
{
	SC_HANDLE				hSCM;
	SC_HANDLE				hService;
	SERVICE_STATUS_PROCESS	ssStart;
	DWORD					ccData;
	DWORD					dwWaitTime;
	DWORD					dwTickTime;
	DWORD					dwTickOldTime;
	DWORD					dwRet = NO_ERROR;
   
	AA_TRACE( ( TEXT( "AA_StartWZCSVC" ) ) );

	// Open the SCM database
	if( ( hSCM = OpenSCManager( NULL, NULL, SC_MANAGER_CONNECT ) ) )
	{
		// Open the specified service
		AA_TRACE( ( TEXT( "AA_StartWZCSVC:: opened SC Manager" ) ) );

		if( ( hService = OpenService( hSCM, 
								L"WZCSVC", 
								SERVICE_QUERY_STATUS 
								| SERVICE_CHANGE_CONFIG
								| SERVICE_START 
								| SERVICE_STOP ) ) )
		{
			AA_TRACE( ( TEXT( "AA_StartWZCSVC:: opened WZCSVC" ) ) );

			if( bAutomatic )
			{
				if (!ChangeServiceConfig( hService, 
										SERVICE_NO_CHANGE, // service type: no change 
										SERVICE_AUTO_START,// change service start type 
										SERVICE_NO_CHANGE, // error control: no change 
										NULL,              // binary path: no change 
										NULL,              // load order group: no change 
										NULL,              // tag ID: no change 
										NULL,              // dependencies: no change 
										NULL,              // account name: no change 
										NULL,              // password: no change 
										NULL) )            // display name: no change
				{
					AA_TRACE( ( TEXT( "AA_StartWZCSVC:: Failed to set service to auto: %ld" ), GetLastError() ) );
				}
			}

			if( StartService( hService,
									0,
									NULL ) )
			{
				AA_TRACE( ( TEXT( "AA_StartWZCSVC:: started service" ) ) );

				if( QueryServiceStatusEx( hService, 
										SC_STATUS_PROCESS_INFO,
										( PBYTE ) &ssStart, 
										sizeof(SERVICE_STATUS_PROCESS),
										&ccData ) )
				{
					AA_TRACE( ( TEXT( "AA_StartWZCSVC:: queried service" ) ) );

					dwTickTime = GetTickCount();

					while ( ( ssStart.dwCurrentState == SERVICE_START_PENDING ) 
						&& ( dwTickTime < AA_GINA_TIMEOUT ) ) 
					{
						AA_TRACE( ( TEXT( "AA_StartWZCSVC:: looping: %ld" ), ssStart.dwWaitHint ) );

						dwTickOldTime = dwTickTime;

						dwWaitTime = ssStart.dwWaitHint;

						if ( dwWaitTime > 500 )
							dwWaitTime = 500;

						Sleep( dwWaitTime );

						if( !QueryServiceStatusEx( hService, 
													SC_STATUS_PROCESS_INFO,
													( PBYTE ) &ssStart, 
													sizeof(SERVICE_STATUS_PROCESS),
													&ccData ) )
						{
							dwRet = ERROR_OPEN_FAILED;

							break;
						}

						dwTickTime = GetTickCount() - dwTickOldTime;
					}

					AA_TRACE( ( TEXT( "AA_StartWZCSVC:: leaving loop" ) ) );
				}
				else
					dwRet = ERROR_OPEN_FAILED;
			}
			else
				dwRet = ERROR_OPEN_FAILED;

			CloseServiceHandle( hService );
		}
		else
			dwRet = ERROR_OPEN_FAILED;

		CloseServiceHandle( hSCM );
	}
	else
		dwRet = ERROR_OPEN_FAILED;

	AA_TRACE( ( TEXT( "AA_StartWZCSVC:: returning %ld" ), dwRet ) );

	return dwRet;
}

DWORD
AA_StopWZCSVC()
{
	SC_HANDLE				hSCM;
	SC_HANDLE				hService;
	SERVICE_STATUS			ssStop;
	DWORD					ccData;
	DWORD					dwWaitTime;
	DWORD					dwTickTime;
	DWORD					dwTickOldTime;
	DWORD					dwRet = NO_ERROR;
   
	AA_TRACE( ( TEXT( "AA_StopWZCSVC" ) ) );

	// Open the SCM database
	if( ( hSCM = OpenSCManager( NULL, NULL, SC_MANAGER_CONNECT ) ) )
	{
		// Open the specified service
		AA_TRACE( ( TEXT( "AA_StopWZCSVC:: opened SC Manager" ) ) );

		if( ( hService = OpenService( hSCM, 
								L"WZCSVC", 
								SERVICE_QUERY_STATUS 
								| SERVICE_START 
								| SERVICE_STOP ) ) )
		{
			AA_TRACE( ( TEXT( "AA_StopWZCSVC:: opened WZCSVC" ) ) );

			if ( !ControlService( hService, 
					SERVICE_CONTROL_STOP,
					&ssStop ) )
			{
				dwRet = GetLastError();

				if ( dwRet == ERROR_SERVICE_NOT_ACTIVE )
					dwRet = NO_ERROR;
			}

			if( dwRet == NO_ERROR )
			{
				AA_TRACE( ( TEXT( "AA_StopWZCSVC:: stopped service" ) ) );

				dwTickTime = GetTickCount();

                while ( ssStop.dwCurrentState != SERVICE_STOPPED 
					&& ( dwTickTime < AA_GINA_TIMEOUT ) ) 
                {
					AA_TRACE( ( TEXT( "AA_StopWZCSVC:: looping: %ld" ), ssStop.dwWaitHint ) );

					dwTickOldTime = dwTickTime;

					dwWaitTime = ssStop.dwWaitHint;

					if ( dwWaitTime > 500 )
						dwWaitTime = 500;

					Sleep( dwWaitTime );

					if( !QueryServiceStatusEx( hService, 
											SC_STATUS_PROCESS_INFO,
											( PBYTE ) &ssStop, 
											sizeof(SERVICE_STATUS),
											&ccData ) )
					{
						dwRet = ERROR_OPEN_FAILED;

						break;
					}

					dwTickTime = GetTickCount() - dwTickOldTime;
                }
			}

			CloseServiceHandle( hService );
		}
		else
			dwRet = ERROR_OPEN_FAILED;

		CloseServiceHandle( hSCM );
	}
	else
		dwRet = ERROR_OPEN_FAILED;

	AA_TRACE( ( TEXT( "AA_StopWZCSVC:: returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: AA_ReadGinaConfig
// Description: Reads the global Gina Config
// Author: Tom Rixom
// Created: 30 June 2005
//
DWORD
AA_ReadGinaConfig( IN OUT PSW2_GINA_CONFIG_DATA pGinaConfigData )
{
	PBYTE	pbData;
	DWORD	cbData;
	HKEY	hKeyLM;
	DWORD	dwRet;

	dwRet = NO_ERROR;

	AA_InitDefaultGinaConfig( pGinaConfigData );

	//
	// Read Gina Information
	//
	AA_TRACE( ( TEXT( "AA_ReadGinaConfig: opening key: %s" ), AA_GINA_LOCATION ) );

	if( ( dwRet = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
									AA_GINA_LOCATION,
									0,
									KEY_READ,
									&hKeyLM ) ) == ERROR_SUCCESS )
	{
		//
		// UseSecureW2Gina
		//
		if( AA_RegGetValue( hKeyLM, 
							L"UseSecureW2Gina", 
							&pbData,
							&cbData ) == NO_ERROR )
		{
			if( cbData == 1 )
				memcpy( &( pGinaConfigData->bUseSW2Gina) , pbData, 1 );

			AA_TRACE( ( TEXT( "AA_ReadGinaConfig: bUseSW2Gina: %ld" ), pGinaConfigData->bUseSW2Gina ) );

			free( pbData );
		}

		//
		// GinaDomainName
		//
		if( AA_RegGetValue( hKeyLM, 
								L"GinaDomainName", 
								&pbData,
								&cbData ) == NO_ERROR )
		{
			if( cbData <= sizeof( pGinaConfigData->pwcGinaDomainName ) )
				memcpy( pGinaConfigData->pwcGinaDomainName, pbData, cbData );

			AA_TRACE( ( TEXT( "AA_ReadGinaConfig: pwcGinaDomainName: %s" ), pGinaConfigData->pwcGinaDomainName ) );

			free( pbData );
		}

		//
		// GinaType
		//
		if( AA_RegGetValue( hKeyLM, 
								L"GinaType", 
								&pbData,
								&cbData ) == NO_ERROR )
		{
			if( cbData <= sizeof( pGinaConfigData->pwcGinaType ) )
				memcpy( pGinaConfigData->pwcGinaType, pbData, cbData );

			AA_TRACE( ( TEXT( "AA_ReadGinaConfig: pwcGinaType: %s" ), pGinaConfigData->pwcGinaType ) );

			free( pbData );
		}

		//
		// UseGinaVLAN
		//
		if( AA_RegGetValue( hKeyLM, 
							L"UseGinaVLAN", 
							&pbData,
							&cbData ) == NO_ERROR )
		{
			if( cbData == 1 )
				memcpy( &( pGinaConfigData->bUseGinaVLAN ), pbData, 1 );

			AA_TRACE( ( TEXT( "AA_ReadGinaConfig: bUseGinaVLAN: %ld" ), pGinaConfigData->bUseGinaVLAN ) );

			free( pbData );
		}

		//
		// GinaVLANIPAddress
		//
		if( AA_RegGetValue( hKeyLM, 
							L"GinaVLANIPAddress", 
							&pbData,
							&cbData ) == NO_ERROR )
		{
			if( cbData == 4 )
				memcpy( &( pGinaConfigData->dwGinaVLANIPAddress ), pbData, 4 );

			AA_TRACE( ( TEXT( "AA_ReadGinaConfig: dwGinaVLANIPAddress: %ld" ), pGinaConfigData->dwGinaVLANIPAddress ) );

			free( pbData );
		}

		//
		// GinaVLANSubnetMask
		//
		if( AA_RegGetValue( hKeyLM, 
							L"GinaVLANSubnetMask", 
							&pbData,
							&cbData ) == NO_ERROR )
		{
			if( cbData == 4 )
				memcpy( &( pGinaConfigData->dwGinaVLANSubnetMask ), pbData, 4 );

			AA_TRACE( ( TEXT( "AA_ReadGinaConfig: dwGinaVLANSubnetMask : %ld" ), pGinaConfigData->dwGinaVLANSubnetMask ) );

			free( pbData );
		}
	
		RegCloseKey( hKeyLM );
	}

	dwRet = NO_ERROR;

	return dwRet;
}

//
// Name: AA_WriteGinaConfig
// Description: Writes the global Gina Config
// Author: Tom Rixom
// Created: 30 June 2005
//
DWORD
AA_WriteGinaConfig( IN PSW2_GINA_CONFIG_DATA pGinaConfigData )
{
	HKEY	hKeyLM;
	DWORD	dwDisposition;
	DWORD	dwRet;

	dwRet = NO_ERROR;

	//
	// Write Gina Information
	//

	AA_TRACE( ( TEXT( "AA_WriteGinaConfig: opening key: %s" ), AA_GINA_LOCATION ) );

	if( ( dwRet = AA_CreateAdminKey( HKEY_LOCAL_MACHINE,
									AA_GINA_LOCATION,
									&hKeyLM,
									&dwDisposition ) ) == NO_ERROR )
	{
		AA_TRACE( ( TEXT( "AA_WriteProfile: opened key" ) ) );

		//
		// UseSecureW2Gina
		//
		if( RegSetValueEx( hKeyLM,
								L"UseSecureW2Gina",
								0,
								REG_BINARY,
								( PBYTE ) &( pGinaConfigData->bUseSW2Gina ),
								1 ) != ERROR_SUCCESS )
		{
			dwRet = ERROR_CANTOPEN;
		}
		else
		{
			//
			// GinaDomainName
			//
			if( RegSetValueEx( hKeyLM,
								L"GinaDomainName",
								0,
								REG_EXPAND_SZ,
								( PBYTE ) pGinaConfigData->pwcGinaDomainName,
								sizeof( pGinaConfigData->pwcGinaDomainName ) ) != ERROR_SUCCESS )
			{
				dwRet = ERROR_CANTOPEN;
			}

			//
			// GinaType
			//
			if( RegSetValueEx( hKeyLM,
								L"GinaType",
								0,
								REG_EXPAND_SZ,
								( PBYTE ) pGinaConfigData->pwcGinaType,
								sizeof( pGinaConfigData->pwcGinaType ) ) != ERROR_SUCCESS )
			{
				dwRet = ERROR_CANTOPEN;
			}

			//
			//
			// UseGinaVLAN
			//
			if( RegSetValueEx( hKeyLM,
								L"UseGinaVLAN",
								0,
								REG_BINARY,
								( PBYTE ) &( pGinaConfigData->bUseGinaVLAN ),
								1 ) != ERROR_SUCCESS )
			{
				dwRet = ERROR_CANTOPEN;
			}
			else
			{

				//
				//
				// VLANIPAddress
				//
				if( RegSetValueEx( hKeyLM,
									L"GinaVLANIPAddress",
									0,
									REG_DWORD,
									( PBYTE ) &( pGinaConfigData->dwGinaVLANIPAddress ),
									4 ) != ERROR_SUCCESS )
				{
					dwRet = ERROR_CANTOPEN;
				}

				//
				// VLANSubnetMask
				//
				if( RegSetValueEx( hKeyLM,
									L"GinaVLANSubnetMask",
									0,
									REG_DWORD,
									( PBYTE ) &( pGinaConfigData->dwGinaVLANSubnetMask ),
									4 ) != ERROR_SUCCESS )
				{
					dwRet = ERROR_CANTOPEN;
				}
			}
		}

		AA_TRACE( ( TEXT( "AA_WriteGinaConfig: bUseSW2Gina: %ld" ), pGinaConfigData->bUseSW2Gina ) );

		RegCloseKey( hKeyLM );
	}

	return dwRet;
}
#endif _WIN32_WCE
