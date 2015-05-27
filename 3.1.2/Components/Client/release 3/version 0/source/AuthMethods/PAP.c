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
// Name: PAP.c
// Description: Contains the functionality used for PAP authentication
// Author: Tom Rixom
// Created: 17 December 2002
// Version: 1.0
// Last revision: 28 Februari 2003
//
// ----------------------------- Revisions -------------------------------
//
// Revision - <Date of revision> <Version of file which has been revised> <Name of author>
// <Description of what has been revised>

#include "../Main.h"

//
// Name: AuthHandleInnerPAPAuthentication
// Description: This function is called when the TLS tunnel has been setup and the inner authentication must be done
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
AuthHandleInnerPAPAuthentication(	IN PSW2_SESSION_DATA	pSessionData,
									OUT PPP_EAP_PACKET*     pSendPacket,
									IN  DWORD               cbSendPacket,
									IN	PPP_EAP_INPUT		*pInput,
									IN	PPP_EAP_OUTPUT		*pEapOutput )
{
	PBYTE				pbMessage;
	DWORD				cbMessage;
	PBYTE				pbRecord;
	DWORD				cbRecord;
	DWORD				dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "AuthHandleInnerPAPAuthentication" ) ) );

	//
	// If the authentication has failed simply return no error when using PAP
	// no need to de-initialize anything as with EAP
	//
	if( ( dwRet = AuthMakeClientPAPMessage( pSessionData, &pbMessage, &cbMessage ) ) == NO_ERROR )
	{
		if( ( dwRet = TLSMakeApplicationRecord( pSessionData->hCSP, 
												pSessionData->hWriteKey,
												pSessionData->dwMacKey,
												pSessionData->dwMacKeySize,
												pSessionData->pbWriteMAC,
												&( pSessionData->dwSeqNum ),
												pbMessage, 
												cbMessage, 
												&pbRecord, 
												&cbRecord, 
												pSessionData->bCipherSpec ) ) == NO_ERROR )
		{
			dwRet = TLSAddMessage( pbRecord, 
									cbRecord, 
									cbRecord,
									pSendPacket, 
									cbSendPacket );

			pSessionData->AuthState = AUTH_STATE_Inner_Authentication;

			pEapOutput->Action = EAPACTION_Send;

			free( pbRecord );
			cbRecord = 0;
		}

		free( pbMessage );
		cbMessage = 0;
	}

	AA_TRACE( ( TEXT( "AuthHandleInnerPAPAuthentication::returning, action: %x, authcode: %x, error: %x" ), pEapOutput->Action, pEapOutput->dwAuthResultCode, dwRet ) );

	return dwRet;
}

//
// Name: AuthMakeClientPAPMessage
// Description: This function is called when we want to use PAP as the Inner Authentication
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
AuthMakeClientPAPMessage( IN PSW2_SESSION_DATA pSessionData, PBYTE *ppbMessage, DWORD *pcbMessage )
{
	PBYTE	pbUsernameAVP;
	DWORD	cbUsernameAVP;
	PCHAR	pcUsername;
	DWORD	ccUsername;
	PCHAR	pcRealm;
	DWORD	ccRealm;
	PBYTE	pbPasswordAVP;
	DWORD	cbPasswordAVP;
	PCHAR	pcPassword;
	DWORD	ccPassword;
	PBYTE	pbMessage;
	DWORD	cbMessage;
	DWORD	dwRet;

	dwRet = NO_ERROR;

	//
	// Build the AVPS for PAP
	//
	ccRealm = ( DWORD ) wcslen( pSessionData->pUserData->pwcDomain );

	AA_TRACE( ( TEXT( "AuthMakeClientPAPRecord::pwcUsername: %ws" ), pSessionData->pUserData->pwcUsername ) );

	if( ccRealm > 0 )
	{
		AA_TRACE( ( TEXT( "AuthMakeClientPAPRecord::pwcDomain: %ws" ), pSessionData->pUserData->pwcDomain ) );

		ccUsername = ( DWORD ) wcslen( pSessionData->pUserData->pwcUsername ) + 1 + ccRealm;

		if( ( pcRealm = ( PCHAR ) malloc( ccRealm + 1 ) ) )
		{
			WideCharToMultiByte( CP_ACP, 0, pSessionData->pUserData->pwcDomain, -1, pcRealm, ccRealm + 1, NULL, NULL );

			if( ( pcUsername = ( PCHAR ) malloc( ccUsername + 1 ) ) )
			{
				WideCharToMultiByte( CP_ACP, 0, pSessionData->pUserData->pwcUsername, -1, pcUsername, ccUsername + 1, NULL, NULL );

				strcat( pcUsername, "@" );

				strcat( pcUsername, pcRealm );
			}
			else
			{
				AA_TRACE( ( TEXT( "AuthMakeClientPAPRecord::not enough memory" ) ) );

				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}

			free( pcRealm );
			ccRealm = 0;
		}
	}
	else
	{
		ccUsername = ( DWORD ) wcslen( pSessionData->pUserData->pwcUsername );

		if( ( pcUsername = ( PCHAR ) malloc( ccUsername + 1 ) ) )
		{
			WideCharToMultiByte( CP_ACP, 0, pSessionData->pUserData->pwcUsername, -1, pcUsername, ccUsername + 1, NULL, NULL );
		}
		else
		{
			AA_TRACE( ( TEXT( "AuthMakeClientPAPRecord::not enough memory" ) ) );

			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
	}

	if( dwRet == NO_ERROR )
	{
		ccPassword = ( DWORD ) wcslen( pSessionData->pUserData->pwcPassword );

		if( ( pcPassword = ( PCHAR ) malloc( ccPassword + 1 ) ) )
			WideCharToMultiByte( CP_ACP, 0, pSessionData->pUserData->pwcPassword, -1, pcPassword, ccPassword + 1, NULL, NULL );
		else
		{
			AA_TRACE( ( TEXT( "AuthMakeClientPAPRecord::not enough memory" ) ) );

			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
	}
	else
	{
		free( pcUsername );
		ccUsername = 0;
	}

	if( dwRet == NO_ERROR )
	{
		if( ( dwRet = AuthMakeDiameterAttribute( 0x01, pcUsername, ccUsername, &pbUsernameAVP, &cbUsernameAVP ) ) == NO_ERROR )
		{
			AA_TRACE( ( TEXT( "AuthMakeClientPAPRecord::pbUsernameAVP(%d):%s" ), cbUsernameAVP, AA_ByteToHex( pbUsernameAVP, cbUsernameAVP ) ) );

			if( ( dwRet = AuthMakeDiameterAttribute( 0x02, pcPassword, ccPassword, &pbPasswordAVP, &cbPasswordAVP ) ) == NO_ERROR )
			{
				AA_TRACE( ( TEXT( "AuthMakeClientPAPRecord::pbPasswordAVP(%d):%s" ), cbPasswordAVP, AA_ByteToHex( pbPasswordAVP, cbPasswordAVP ) ) );

				*pcbMessage = cbUsernameAVP + cbPasswordAVP;

				if( ( *ppbMessage = ( PBYTE ) malloc( *pcbMessage ) ) )
				{
					pbMessage = *ppbMessage;
					cbMessage = *pcbMessage;

					memcpy( pbMessage, pbUsernameAVP, cbUsernameAVP );
					memcpy( &( pbMessage[cbUsernameAVP] ), pbPasswordAVP, cbPasswordAVP );
				}

				free( pbPasswordAVP );
				cbPasswordAVP = 0;
			}
			else
			{
				AA_TRACE( ( TEXT( "AuthMakeClientPAPRecord::not enough memory" ) ) );

				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}

			free( pbUsernameAVP );
			pbUsernameAVP = 0;
		}
		else
		{
			AA_TRACE( ( TEXT( "AuthMakeClientPAPRecord::not enough memory" ) ) );

			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		free( pcPassword );
		ccPassword = 0;

		free( pcUsername );
		ccUsername = 0;
	}
	else
	{
			AA_TRACE( ( TEXT( "AuthMakeClientPAPRecord::not enough memory" ) ) );

			dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}