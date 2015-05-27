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
// Name: Auth.c
// Description: Contains the functionality used for authentication
// Author: Tom Rixom
// Created: 17 December 2002
// Version: 1.0
// Last revision: 28 Februari 2003
//
// ----------------------------- Revisions -------------------------------
//
// Revision - <Date of revision> <Version of file which has been revised> <Name of author>
// <Description of what has been revised>
//
// Added handling of InnerEapOutput - 28 Februari 2003 - Tom Rixom
// When the makemessage routing of the inner EAP dll returns we should act according to the action set
// fail / show interactiveUI and so forth
//

#include "Main.h"

//
// Name: AuthHandleInnerAuthentication
// Description: This function is called when the TLS tunnel has been setup and the inner authentication must be done
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
AuthHandleInnerAuthentication(	IN PSW2_SESSION_DATA	pSessionData,
							OUT PPP_EAP_PACKET*     pSendPacket,
							IN  DWORD               cbSendPacket,
							IN	PPP_EAP_INPUT		*pInput,
							IN	PPP_EAP_OUTPUT		*pEapOutput )
{
	DWORD				dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "AuthHandleInnerAuthentication" ) ) );

	switch( pSessionData->AuthState )
	{
		case AUTH_STATE_Change_Cipher_Spec:
		case AUTH_STATE_Inner_Authentication:

			if( wcscmp( L"PAP", pSessionData->pProfileData->pwcInnerAuth ) == 0 )
			{
				AA_TRACE( ( TEXT( "AuthHandleInnerAuthentication::PAP" ) ) );

				dwRet = AuthHandleInnerPAPAuthentication(pSessionData, 
														pSendPacket,
														cbSendPacket,
														pInput,
														pEapOutput);
			}
			else if( wcscmp( L"EAP", pSessionData->pProfileData->pwcInnerAuth ) == 0 )
			{
				AA_TRACE( ( TEXT( "AuthHandleInnerAuthentication::EAP" ) ) );

				dwRet = AuthHandleInnerEAPAuthentication(pSessionData, 
														pSendPacket,
														cbSendPacket,
														pInput,
														pEapOutput);
			}

			pSessionData->AuthState = AUTH_STATE_Inner_Authentication;

		break;

		default:

			AA_TRACE( ( TEXT( "AuthHandleInnerAuthentication::unknown authentication state" ) ) );

			dwRet = ERROR_PPP_INVALID_PACKET;

		break;
	}

	AA_TRACE( ( TEXT( "AuthHandleInnerAuthentication::returning, action: %x, authcode: %x, error: %x" ), pEapOutput->Action, pEapOutput->dwAuthResultCode, dwRet ) );

	return dwRet;
}

//
// Name: AuthMakeDiameterAttribute
// Description: This function builds a diameter attribute
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
AuthMakeDiameterAttribute( DWORD dwType,
						   PBYTE pbData,
						   DWORD cbData,
						   PBYTE *ppbDiameter,
						   DWORD *pcbDiameter )
{
	DWORD	dwPadding;
	PBYTE	pbDiameter;
	DWORD	cbDiameter;
	DWORD	dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "AuthMakeDiameterAttribute::pbAttribute(%d):%s" ), cbData, AA_ByteToHex( pbData, cbData ) ) );

	// length of AVP must be multiple of 4 octets
	//
	dwPadding = ( 0x08 + cbData ) % 4;
	
	if( dwPadding != 0 )
		dwPadding = 4 - dwPadding;

	AA_TRACE( ( TEXT( "AuthMakeDiameterAttribute::padding: %d" ), dwPadding ) );

	*pcbDiameter = 0x08 + cbData + dwPadding;

	if( ( *ppbDiameter = ( PBYTE ) malloc( *pcbDiameter ) ) )
	{
		pbDiameter = *ppbDiameter;
		cbDiameter = *pcbDiameter;

		memset( pbDiameter, 0, cbDiameter );

		AA_HostToWireFormat32( dwType, &( pbDiameter[0] ) );

		//
		// Not vendor specific and important so
		// set the M bit
		// 01000000
		//
		pbDiameter[4] = 0x40;

		//
		// Length of AVP (3 bytes)
		// avp_header(7) + lenght of Password
		//
		AA_HostToWireFormat24( ( WORD ) ( 0x08 + cbData ), &( pbDiameter[5] ) );

		memcpy( &( pbDiameter[8] ), pbData, cbData );
	}
	else
	{
		AA_TRACE( ( TEXT( "AuthMakeDiameterAttribute::not enough memory" ) ) );

		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}