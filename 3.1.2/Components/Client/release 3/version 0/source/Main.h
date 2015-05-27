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
// Name: Main.h
// Description: Main header file for SecureW2
// Author: Tom Rixom
// Created: 17 December 2002
//
#ifndef AA_SECUREW2_MAIN_H
#define AA_SECUREW2_MAIN_H

#define AA_VERSION		"3.0"

#include "..\..\..\..\Common\release 3\version 0\source\common.h"

#include <lmcons.h>
#include <time.h>
#include <stdio.h>

#ifdef _WIN32_WCE
#include "..\..\..\..\Resource\English\Client\Release 2\Version 0\source\resource_CE.h"
#else
#include "..\..\..\..\Resource\English\Client\Release 2\Version 0\source\resource.h"
#endif

//
// In CE the WC_DIALOG is not present, so set it
//
#ifndef WC_DIALOG
#define WC_DIALOG L"Dialog"
#endif 

//--------------------
// Globals
//--------------------
HINSTANCE								ghInstance;			// global instance used for dialogs
HMODULE									hDLL;				// global module used for resources

//--------------------
// Definitions
//--------------------
#define AA_MAX_CONFIG_TAB				5

#define UI_TYPE_VERIFY_CERT				0x20
#define UI_TYPE_INNER_EAP				0x40
#define UI_TYPE_ERROR					0x60
#define UI_TYPE_CREDENTIALS				0x80

#define RADIUS_MAX_STATE				64

typedef enum _PREV_AUTH_RESULT
{
    PREV_AUTH_RESULT_pending,
    PREV_AUTH_RESULT_failed,
	PREV_AUTH_RESULT_success
	
} PREV_AUTH_RESULT;

//--------------------
// Structs
//--------------------

typedef struct _SW2_USER_DATA 
{
	//
	// General user information
	//
	WCHAR					pwcUsername[UNLEN];
	WCHAR					pwcPassword[PWLEN];
	WCHAR					pwcDomain[UNLEN];

	//
	// Adapter information
	//
	WCHAR					pwcPhonebook[UNLEN];
	WCHAR					pwcEntry[UNLEN];

	BOOL					bSaveUserCredentials;

	//
	//
	// Stuff needed for session resumption
	//
	int						cbTLSSessionID;
	BYTE					pbTLSSessionID[TLS_SESSION_ID_SIZE];
	time_t					tTLSSessionID; // the time this TTLS session ID was set

	BYTE					pbMS[TLS_MS_SIZE];

	//
	// To see what happened in a previous session
	// 
	PREV_AUTH_RESULT		PrevAuthResult;

	//
	// Stuff needed for inner EAP authentication
	//
	SW2_INNER_EAP_USER_DATA	InnerEapUserData;

} SW2_USER_DATA, *PSW2_USER_DATA;

typedef enum _AUTH_STATE
{
    AUTH_STATE_Start,
	AUTH_STATE_Server_Hello,
	AUTH_STATE_Verify_Cert,
	AUTH_STATE_Change_Cipher_Spec,
	AUTH_STATE_Resume_Session,
	AUTH_STATE_Resume_Session_Ack,
	AUTH_STATE_Inner_Authentication,
	AUTH_STATE_Error,
	AUTH_STATE_Finished

} AUTH_STATE;

typedef struct _SW2_SESSION_DATA 
{
	DWORD					dwError;

	AUTH_STATE				AuthState;
    DWORD					fFlags;
    BOOL					fAuthenticator;

	WCHAR					pwcCurrentProfileId[UNLEN];

	BYTE					pbInnerUIContextData[EAP_MAX_INNER_UI_DATA];
	DWORD					dwInnerSizeOfUIContextData;

	HCRYPTPROV				hCSP;

	HANDLE					hTokenImpersonateUser;

	BYTE					pbPMS[TLS_PMS_SIZE];

	DWORD					dwEncKey;
	DWORD					dwEncKeySize;

	DWORD					dwMacKey;
	DWORD					dwMacKeySize;

	HCRYPTKEY				hReadKey;
	HCRYPTKEY				hWriteKey;
	BYTE					pbWriteMAC[TLS_MAX_MAC];
	BYTE					pbReadMAC[TLS_MAX_MAC];

	BYTE					pbCertificate[TLS_MAX_CERT][TLS_MAX_CERT_SIZE];
	DWORD					cbCertificate[TLS_MAX_CERT];

	DWORD					dwCertCount;

	BYTE					pbRandomClient[TLS_RANDOM_SIZE];

	BYTE					pbRandomServer[TLS_RANDOM_SIZE];

	BYTE					pbCipher[2];

	BYTE					bCompression;

	PBYTE					pbHandshakeMsg[TLS_MAX_HS];
	DWORD					cbHandshakeMsg[TLS_MAX_HS];
	DWORD					dwHandshakeMsgCount;

	BYTE					pbReceiveMsg[TLS_MAX_MSG];
	DWORD					cbReceiveMsg;
	DWORD					dwReceiveCursor;

	DWORD					dwSeqNum;

	BYTE					bPacketId;

	BOOL					bCipherSpec;

	BOOL					bServerFinished;

	BYTE					bInteractiveUIType;

	BOOL					bFoundAlert; // send if something was wrong

	BOOL					bSentFinished; // we have sent our finished message

	BOOL					bCertRequest; // server requested certificate

	BYTE					pbState[RADIUS_MAX_STATE];

	DWORD					cbState;

	BOOL					bServerCertificateLocal;

	BOOL					bVerifyMSExtension;

	PSW2_USER_DATA			pUserData;

	PSW2_PROFILE_DATA		pProfileData;

	SW2_INNER_SESSION_DATA	InnerSessionData;

	RAS_AUTH_ATTRIBUTE		*pUserAttributes;

} SW2_SESSION_DATA, *PSW2_SESSION_DATA;

typedef struct _EAP_NAME_DIALOG
{
    WCHAR               pwcIdentity[UNLEN + 1 ];
    WCHAR               pwcPassword[PWLEN + 1 ];
	WCHAR				pwcDomain[UNLEN + 1 ];

} EAP_NAME_DIALOG, *PEAP_NAME_DIALOG;

//--------------------
// Functions
//--------------------

//
// Inner Authentication
//
DWORD				AuthHandleInnerAuthentication(	IN PSW2_SESSION_DATA		pSessionData,
												OUT PPP_EAP_PACKET*     pSendPacket,
												IN  DWORD               cbSendPacket,
												IN	PPP_EAP_INPUT		*pInput,
												IN PPP_EAP_OUTPUT		*pEapOutput );

DWORD				AuthHandleInnerPAPAuthentication(	IN PSW2_SESSION_DATA		pSessionData,
												OUT PPP_EAP_PACKET*     pSendPacket,
												IN  DWORD               cbSendPacket,
												IN	PPP_EAP_INPUT		*pInput,
												IN PPP_EAP_OUTPUT		*pEapOutput );

DWORD				AuthHandleInnerEAPAuthentication(	IN PSW2_SESSION_DATA		pSessionData,
												OUT PPP_EAP_PACKET*     pSendPacket,
												IN  DWORD               cbSendPacket,
												IN	PPP_EAP_INPUT		*pInput,
												IN PPP_EAP_OUTPUT		*pEapOutput );

DWORD				AuthMakeDiameterAttribute( DWORD dwType,
												PBYTE pbAttribute,
												DWORD cbAttribute,
												PBYTE *ppbDiameter,
												DWORD *pcbDiameter );

//
// PAP
//
DWORD				AuthMakeClientPAPMessage( IN PSW2_SESSION_DATA pSessionData, PBYTE *ppbMessage, DWORD *pcbMessage );

//
// EAP
//
DWORD				AuthMakeEAPResponseAttribute(	IN BYTE bType,
													IN BYTE bPacketID,
													IN PBYTE pbData,
													IN DWORD cbData,
													OUT PBYTE *ppbEAPAttribute,
													OUT DWORD *pcbEAPAttribute );

//
// RAS
//
DWORD APIENTRY		RasEapInitialize( BOOL bInitialize );
DWORD APIENTRY		RasEapBegin( OUT VOID** ppWorkBuf, IN PPP_EAP_INPUT* pInput );
DWORD APIENTRY		RasEapEnd( IN VOID* pWorkBuf );
DWORD APIENTRY		RasEapMakeMessage( IN VOID* pWorkBuf, IN PPP_EAP_PACKET* pReceiveBuf, OUT PPP_EAP_PACKET* pSendBuf, IN DWORD cbSendBuf, OUT PPP_EAP_OUTPUT* pResult, IN PPP_EAP_INPUT* pInput );
DWORD APIENTRY		RasEapInvokeConfigUI( IN DWORD dwEapTypeId, IN HWND hwndParent, IN DWORD dwFlags, IN BYTE* pConnectionDataIn, IN DWORD dwSizeOfConnectionDataIn, OUT BYTE** ppConnectionDataOut, OUT DWORD* pdwSizeOfConnectionDataOut );
DWORD APIENTRY		RasEapFreeMemory( IN BYTE* pbMemory );

DWORD APIENTRY		RasEapGetIdentity(	DWORD dwEapTypeId,
										HWND hwndParent,
										DWORD dwFlags,
										const WCHAR * pwszPhonebook,
										const WCHAR * pwszEntry,
										BYTE * pConnectionDataIn,
										DWORD dwSizeOfConnectionDataIn,
										BYTE * pUserDataIn,
										DWORD dwSizeOfUserDataIn,
										BYTE ** ppUserDataOut,
										DWORD * pdwSizeOfUserDataOut,
										WCHAR ** ppwszIdentity );

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
						OUT WCHAR **		ppwcIdentity );

#ifndef _WIN32_WCE

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
						OUT WCHAR **		ppwcIdentity  );
#endif // _WIN32_WCE

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
						OUT WCHAR **		ppwcIdentity );
//
// Dialog
//
INT_PTR	CALLBACK	ConfigProfileNewDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
INT_PTR	CALLBACK	ProfileDlgProc(	IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
INT_PTR CALLBACK	ConfigDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
INT_PTR CALLBACK	CredentialsDlgProc(	IN  HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM  lParam );
INT_PTR CALLBACK	TLSServerTrustDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
INT_PTR CALLBACK	ConfigConnDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
INT_PTR	CALLBACK	ConfigCADlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM  wParam, IN  LPARAM  lParam );
INT_PTR CALLBACK	ConfigCertDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
INT_PTR	CALLBACK	ConfigAuthDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
INT_PTR CALLBACK	ConfigUserDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
INT_PTR CALLBACK	ConfigProfileDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
#ifndef _WIN32_WCE
INT_PTR CALLBACK	ConfigGinaDlgProc( IN HWND hWnd, IN UINT unMsg, IN WPARAM wParam, IN LPARAM lParam );
#endif // _WIN32_WCE
DWORD				ConfigUpdateCertificateView( IN HWND hWnd, IN PSW2_SESSION_DATA pSessionData );

#ifndef _WIN32_WCE
DWORD	WINAPI		AA_RenewIP( LPVOID lpvoid );
#endif // _WIN32_WCE

//
// Crypto
//
DWORD				TLSGenRSAEncPMS( IN PSW2_SESSION_DATA pSessionData, PBYTE *ppbEncPMS, DWORD *pcbEncPMS );

DWORD				TLSSetAlgorithm( IN PSW2_SESSION_DATA pSessionData );

DWORD				TLSDeriveKeys( IN PSW2_SESSION_DATA pSessionData );

DWORD				AA_VerifyCertificateChain( IN PCCERT_CONTEXT pCertContext );

DWORD				AA_VerifyCertificateInStore( IN PCCERT_CONTEXT pCertContext );

//DWORD				AA_CreateCertChainEngine( OUT HCERTCHAINENGINE *phChainEngine );

DWORD				AA_CertGetTrustedRootCAList( HWND hWnd, BYTE pbTrustedCA[AA_MAX_CA][20], DWORD dwNrOfTrustedRootCAInList );
DWORD				AA_CertGetRootCAList( IN HWND hWnd, IN BYTE pbTrustedRootCAList[AA_MAX_CA][20], IN DWORD dwNrOfTrustedRootCAInList );
DWORD				AA_CertAddTrustedRootCA( IN DWORD dwSelected, IN OUT BYTE pbTrustedRootCA[AA_MAX_CA][20], IN OUT DWORD *dwNrOfTrustedCAInList );
DWORD				AA_CertRemoveTrustedRootCA( IN DWORD dwSelected, IN OUT BYTE pbTrustedRootCA[AA_MAX_CA][20], IN OUT DWORD *dwNrOfTrustedCAInList );

DWORD				AA_CertCheckEnhkeyUsage( IN PCCERT_CONTEXT pCertContext );

DWORD				AA_VerifyServerCertificate( IN PSW2_PROFILE_DATA pProfileData, IN PCCERT_CONTEXT pCertContext );

DWORD				AA_VerifyCertificateInList( IN PSW2_SESSION_DATA pSessionData, IN PBYTE pbSHA1 );

DWORD				MakeMPPEKey(	IN HCRYPTPROV	hCSP,
									IN PBYTE		pbRandomClient,
									IN PBYTE		pbRandomServer,
									IN PBYTE		pbMS,
									IN OUT RAS_AUTH_ATTRIBUTE ** ppUserAttributes);

//
// TLS
//
DWORD				TLSParseHandshakeRecord(	IN PSW2_SESSION_DATA pSessionData, 
												IN PBYTE pbRecord, 
												IN DWORD cbRecord );

DWORD				TLSBuildResponsePacket( PSW2_SESSION_DATA		pSessionData,
											OUT PPP_EAP_PACKET		*pSendPacket,
											IN  DWORD               cbSendPacket,
											IN PPP_EAP_INPUT		*pEapInput,
											IN PPP_EAP_OUTPUT		*pEapOutput );

DWORD				TLSParseServerPacket(	IN PSW2_SESSION_DATA pSessionData, 
											IN PBYTE pbEapMsg, 
											IN DWORD cbEAPMsg );


#endif