//
// Copyright Alfa & Ariss B.V. 2002
//
// Name: MSCHAPV2.c
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
// Name: AuthHandleInnerMSCHAPV2Authentication
// Description: This function is called when the TLS tunnel has been setup and the inner authentication must be done
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
AuthHandleInnerMSCHAPV2Authentication(	IN PSW2_SESSION_DATA	pSessionData,
										OUT PPP_EAP_PACKET*     pSendPacket,
										IN  DWORD               cbSendPacket,
										IN	PPP_EAP_INPUT		*pInput,
										IN	PPP_EAP_OUTPUT		*pEapOutput )
{
//	PBYTE				pbMessage;
//	DWORD				cbMessage;
//	PBYTE				pbRecord;
//	DWORD				cbRecord;
	DWORD				dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "AuthHandleInnerMSCHAPV2Authentication" ) ) );

	AA_TRACE( ( TEXT( "AuthHandleInnerMSCHAPV2Authentication::returning, action: %x, authcode: %x, error: %x" ), pEapOutput->Action, pEapOutput->dwAuthResultCode, dwRet ) );

	return dwRet;
}