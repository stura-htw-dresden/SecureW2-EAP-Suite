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
#ifndef AA_COMMON_H
#define AA_COMMON_H

#ifndef UNICODE
#define UNICODE
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS

#include <windows.h>
#include <tchar.h>
#include <Raseapif.h>
#include <raserror.h>

#ifdef _WIN32_WCE
#include <wincrypt.h>
#endif // _WIN32_WCE

#include <lmcons.h>

#define AA_CONFIG_VERSION				0x07

#ifdef _WIN32_WCE
#define EAP_EAP_METHOD_LOCATION			L"Comm\\EAP\\Extension"
#else
#define EAP_EAP_METHOD_LOCATION			L"SYSTEM\\CurrentControlSet\\Services\\RasMan\\PPP\\EAP"
#endif // _WIN32_WCE

#define AA_SECRET						"8FC8E6CF371C2D049BBC243E84F2A3766ED907EF0960EE39284E83C267B032C63EE448A7BCE76F64149AC82AC2DE5613E76F190FF2DC41E31CBF5610BEAEC079F64AE45A884C74CFDC61A19D5C1C1CA44BD28A73D51DF25A9D5147B63164A60459670924AA0F42376D7E1551632AE72F0FF44CBED3C5F313ED6C408D641931BB"
#define AA_CLIENT_REG_LOCATION			L"SOFTWARE\\Alfa & Ariss\\SecureW2 Client\\3.0.0"
#define AA_CLIENT_PROFILE_LOCATION		L"SOFTWARE\\Alfa & Ariss\\SecureW2 Client\\3.0.0\\Profiles"
#define AA_GINA_LOCATION				L"SOFTWARE\\Alfa & Ariss\\SecureW2 Client\\3.0.0\\Gina"
#define AA_SERVER_PROFILE_LOCATION		L"SOFTWARE\\Alfa & Ariss\\SecureW2\\3.0.0\\Profiles"

#define EAP_TTLS_PROTOCOL_ID			21					// the EAP ID for Eap-TTLS is 21

#define AA_MAX_ID						256
#define AA_MAX_SERIAL					32
#define AA_MAX_REGKEY					256
#define AA_MAX_TIMESTAMP				256

//
// GINA
//

#define AA_GINA_TIMEOUT 2000

//
// TLS
//
#define TLS_SESSION_ID_SIZE				32
#define TLS_MAX_ENC_PMS_SIZE			128

#define TLS_FINISH_SIZE					12

#define TLS_MAX_HS						10
#define TLS_MAX_CERT					5
#define	TLS_MAX_CERT_SIZE				2048
#define TLS_MAX_CERT_NAME				256
#define TLS_MAX_RECORD_SIZE				1024
#define TLS_MAX_FRAG_SIZE				1024

#define	TLS_MAX_MAC						20

#define	TLS_MAX_MASTER_KEY				2048

#define TLS_MAX_MSG						16384

#define TLS_MAX_EAPMSG					8192

#define TLS_ANONYMOUS_USERNAME			L"anonymous"

#define TLS_REQUEST_LENGTH_INC			0x80
#define TLS_REQUEST_MORE_FRAG			0x40
#define TLS_REQUEST_START				0x20

#define TLS_CLIENT_FINISHED_LABEL		"client finished"
#define TLS_SERVER_FINISHED_LABEL		"server finished"

#define TLS_KEY_EXPANSION_LABEL			"key expansion"

#define TLS_RANDOM_SIZE					32

#define TLS_PMS_SIZE					48
#define TLS_MS_SIZE						48

#define EAP_PROTOCOL_ID					21					// the EAP ID for TTLS is 21

#define EAP_MAX_INNER_UI_DATA			2048
#define EAP_MAX_INNER_DATA				1024
#define EAP_MAX_CONNECTION_DATA			4000
#define MAX_UI_CONTEXT_DATA				8192

#define TLS_MAX_CIPHERSUITE				30

#define EAP_KEYING_MATERIAL_LABEL		"ttls keying material"

#define AA_MAX_CA						20

#define AA_MAX_TAB						5

#ifndef _WIN32_WCE

#define GINA_TYPE_Microsoft				L"Microsoft"
#define GINA_TYPE_Novell				L"Novell"

#endif // _WIN32_WCE

//--------------------
// Structs
//--------------------

typedef struct _SW2_INNER_EAP_CONFIG_DATA
{
	BYTE				pbConnectionData[EAP_MAX_CONNECTION_DATA];
	DWORD				cbConnectionData;

	DWORD				dwEapType;
	WCHAR				pwcEapFriendlyName[UNLEN];
	WCHAR				pwcEapConfigUiPath[UNLEN];
	WCHAR				pwcEapIdentityPath[UNLEN];
	WCHAR				pwcEapInteractiveUIPath[UNLEN];
	WCHAR				pwcEapPath[UNLEN];

	DWORD				dwInvokeUsernameDlg;
	DWORD				dwInvokePasswordDlg;

} SW2_INNER_EAP_CONFIG_DATA, *PSW2_INNER_EAP_CONFIG_DATA;

typedef struct _SW2_INNER_EAP_USER_DATA 
{
	WCHAR			pwcIdentity[UNLEN];
	BYTE			pbUserData[EAP_MAX_INNER_DATA];
	DWORD			cbUserData;

} SW2_INNER_EAP_USER_DATA, *P_SW2_INNER_EAP_USER_DATA;

typedef enum _INNER_AUTH_STATE
{
    INNER_AUTH_STATE_Start,
	INNER_AUTH_STATE_Identity,
	INNER_AUTH_STATE_EAPType,
	INNER_AUTH_STATE_InteractiveUI,
	INNER_AUTH_STATE_MakeMessage,
	INNER_AUTH_STATE_Finished

} INNER_AUTH_STATE;

//
// INNER EAP DLL entrypoint functions
// have to define them before using them in SESSION_DATA
//
typedef DWORD ( APIENTRY * PINNEREAPGETINFO ) ( IN DWORD dwEapTypeId, IN PPP_EAP_INFO *pEapInfo );

typedef DWORD ( APIENTRY * PINNEREAPGETIDENTITY ) (	IN DWORD dwEapTypeId,
													IN HWND hwndParent,
													IN DWORD dwFlags,
													IN const WCHAR * pwszPhonebook,
													IN const WCHAR * pwszEntry,
													IN BYTE * pConnectionDataIn,
													IN DWORD dwSizeOfConnectionDataIn,
													IN BYTE * pUserDataIn,
													IN DWORD dwSizeOfUserDataIn,
													OUT BYTE ** ppUserDataOut,
													OUT DWORD * pdwSizeOfUserDataOut,
													OUT WCHAR ** ppwszIdentity );

typedef DWORD ( APIENTRY * PINNEREAPINVOKECONFIGUI ) ( IN DWORD dwEapTypeId,
														IN HWND hwndParent,
														IN DWORD dwFlags,
														IN BYTE* pConnectionDataIn,
														IN DWORD dwSizeOfConnectionDataIn,
														OUT BYTE** ppConnectionDataOut,
														OUT DWORD* pdwSizeOfConnectionDataOut );

typedef DWORD ( APIENTRY * PINNEREAPFREEMEMORY ) ( IN  BYTE *pMemory );

typedef DWORD ( APIENTRY * PINNEREAPINITIALIZE )( IN BOOL fInitialize );

typedef DWORD ( APIENTRY * PINNEREAPBEGIN )( OUT VOID **ppWorkBuffer, IN PPP_EAP_INPUT *pPppEapInput );

typedef DWORD ( APIENTRY * PINNEREAPEND )( IN VOID *pWorkBuffer );

typedef DWORD ( APIENTRY * PINNEREAPMAKEMESSAGE )(	IN VOID *pWorkBuf,
													IN PPP_EAP_PACKET *pReceivePacket,
													IN PPP_EAP_PACKET *pSendPacket,
													IN DWORD cbSendPacket,
													IN PPP_EAP_OUTPUT *pEapOutput,
													IN PPP_EAP_INPUT *pEapInput );

typedef DWORD ( APIENTRY * PINNEREAPINVOKEINTERACTIVEUI ) (	IN DWORD	dwEapTypeId,
															IN  HWND	hWndParent,
															IN  PBYTE	pUIContextData,
															IN  DWORD	dwSizeofUIContextData,
															OUT PBYTE*	ppDataFromInteractiveUI,
															OUT DWORD*	lpdwSizeOfDataFromInteractiveUI );

#ifndef _WIN32_WCE
typedef struct _SW2_GINA_CONFIG_DATA
{

	BOOL						bUseSW2Gina;
	WCHAR						pwcGinaDomainName[UNLEN];
	BOOL						bUseGinaVLAN;
	DWORD						dwGinaVLANIPAddress;
	DWORD						dwGinaVLANSubnetMask;
	WCHAR						pwcGinaType[UNLEN];

} SW2_GINA_CONFIG_DATA, *PSW2_GINA_CONFIG_DATA;
#endif // _WIN32_WCE

typedef struct _SW2_INNER_SESSION_DATA
{
    PBYTE					pbInnerEapSessionData;

	BOOL					bInnerEapExtSuccess;

	HINSTANCE				hInnerEapInstance;
	PINNEREAPINITIALIZE		pInnerEapInitialize;
	PINNEREAPBEGIN			pInnerEapBegin;
	PINNEREAPEND			pInnerEapEnd;
	PINNEREAPMAKEMESSAGE	pInnerEapMakeMessage;
	PPP_EAP_INPUT			InnerEapInput;
	PPP_EAP_OUTPUT			InnerEapOutput;
	INNER_AUTH_STATE		InnerAuthState;
	BYTE					pbInnerEapMessage[TLS_MAX_EAPMSG];
	DWORD					cbInnerEapMessage;

	BYTE					pInnerEapDataFromInteractiveUI[MAX_UI_CONTEXT_DATA];
	DWORD					dwInnerEapSizeOfDataFromInteractiveUI;

	//
	// Stuff needed for inner EAP authentication
	//
	PSW2_INNER_EAP_CONFIG_DATA	pInnerEapConfigData;

} SW2_INNER_SESSION_DATA; *PSW2_INNER_SESSION_DATA;

typedef struct _SW2_PROFILE_DATA
{
	INT							iVersion;
	WCHAR						pwcUserName[UNLEN];
	WCHAR						pwcUserPassword[PWLEN];
	WCHAR						pwcUserDomain[UNLEN];

#ifndef _WIN32_WCE
	WCHAR						pwcCompName[UNLEN];
	WCHAR						pwcCompPassword[PWLEN];
	WCHAR						pwcCompDomain[UNLEN];
#endif // _WIN32_WCE

	WCHAR						pwcInnerAuth[UNLEN];

	BOOL						bUseAlternateOuter;
	BOOL						bUseAlternateAnonymous;
	WCHAR						pwcAlternateOuter[UNLEN];

	BOOL						bVerifyServer;
	BOOL						bVerifyServerName;
	BOOL						bServerCertificateLocal;
	WCHAR						pwcServerName[UNLEN];

#ifndef _WIN32_WCE
	BOOL						bUseAlternateComputerCred;
	BOOL						bUseCredentialsForComputer;
#endif // _WIN32_WCE
	BOOL						bPromptUser;
	BOOL						bUseSessionResumption;

#ifndef _WIN32_WCE
	BOOL						bRenewIP;
#endif // _WIN32_WCE

	BOOL						bVerifyMSExtension;
	BOOL						bAllowNewConnection;

	HWND						hWndTabs[AA_MAX_TAB];

	//
	// Current EAP ID this SecureW2 config is using
	//
	DWORD						dwCurrentInnerEapMethod;

	WCHAR						pwcCurrentProfileId[UNLEN];

	//
	// Currently the profile description is only used during 
	// installation on non Windows CE, to save space we ignore
	// this on Windows CE
	//
	// Windows CE only support registry keys up to 4096 bytes, so we need to save space
	//
	// 
#ifndef _WIN32_WCE
	WCHAR						pwcProfileDescription[UNLEN];
#endif _WIN32_WCE
	//
	// SHA1 of trusted root certificates
	//
	DWORD						dwNrOfTrustedRootCAInList;
	BYTE						pbTrustedRootCAList[AA_MAX_CA][20];

#ifndef _WIN32_WCE
	SW2_GINA_CONFIG_DATA		GinaConfigData;
#endif // _WIN32_WCE

} SW2_PROFILE_DATA, *PSW2_PROFILE_DATA;

typedef struct _SW2_CONFIG_DATA
{
	HWND						hWndTabs[2];

	WCHAR						pwcProfileId[UNLEN];

} SW2_CONFIG_DATA, *PSW2_CONFIG_DATA;

//
// Profile
//
VOID				AA_InitDefaultProfile( IN OUT PSW2_PROFILE_DATA pProfile );
#ifndef _WIN32_WCE
VOID				AA_InitDefaultGinaConfig( IN OUT PSW2_GINA_CONFIG_DATA pGinaConfigData );
#endif // _WIN32_WCE

DWORD				AA_CreateProfile( IN WCHAR *pwcProfileID );
DWORD				AA_DeleteProfile( IN WCHAR	*pwcProfileID );

DWORD				AA_ReadProfile( IN WCHAR *pwcProfileID, 
									IN HANDLE hTokenImpersonateUser,
									IN OUT PSW2_PROFILE_DATA pProfileData );

DWORD				AA_WriteCertificates( IN WCHAR *pwcProfileID, IN SW2_PROFILE_DATA ProfileData );
DWORD				AA_ReadCertificates( IN WCHAR *pwcProfileID, IN PSW2_PROFILE_DATA ProfileData );

DWORD				AA_WriteProfile( IN WCHAR *pwcProfileID, 
									IN HANDLE hTokenImpersonateUser,
									IN OUT SW2_PROFILE_DATA ProfileData );

DWORD				AA_ReadInnerEapMethod( IN DWORD dwEapType, 
											IN WCHAR *pwcCurrentProfileId, 
											IN OUT PSW2_INNER_EAP_CONFIG_DATA pInnerEapConfigData );

DWORD				AA_WriteInnerEapMethod( IN DWORD dwEapType, 
											IN WCHAR *pwcCurrentProfileId, 
											IN OUT SW2_INNER_EAP_CONFIG_DATA InnerEapConfigData );


//
// Registration key 
//
DWORD	AA_XorData( PBYTE pbDataIn, DWORD cbDataIn, PBYTE pbKey, DWORD cbKey, PBYTE *ppbDataOut );
DWORD	AA_SetBinRegKey( WCHAR *pwcKey, PBYTE pbValue, DWORD cbValue );
DWORD	AA_RegGetDWORDValue( HKEY hKey, WCHAR *pwcValue, DWORD *pdwData );
DWORD	AA_RegGetValue( HKEY hKey, WCHAR *pwcValue, PBYTE *ppbData, DWORD *pcbData );
DWORD	AA_ImportAAPublicKey( HCRYPTPROV hCSP, HCRYPTKEY *hKey );

//
// Utils
//
PBYTE				AA_HexToByte( PCHAR String, DWORD *Length );
TCHAR*				AA_ByteToHex( BYTE *xBytes, int xLength );
PCHAR				AA_ToUpperString( PCHAR String );
VOID				AA_SwapArray( IN BYTE *xIn, OUT BYTE *xOut, IN int xLength );

VOID				AA_HostToWireFormat32( IN DWORD dwHostFormat, IN OUT PBYTE pWireFormat );
VOID				AA_HostToWireFormat24( IN DWORD dwHostFormat, IN OUT PBYTE pWireFormat );
VOID				AA_HostToWireFormat16(	IN DWORD  wHostFormat, IN OUT PBYTE pWireFormat );
DWORD				AA_WireToHostFormat32(	IN PBYTE pWireFormat );
DWORD				AA_WireToHostFormat24(	IN PBYTE pWireFormat );
DWORD				AA_WireToHostFormat16(	IN PBYTE pWireFormat );

BOOL				AA_GetTextualSid( IN PSID pSid, OUT LPTSTR TextualSid, OUT LPDWORD lpdwBufferLen );
BOOL				AA_IsAdmin();

DWORD				AA_KillWindow( IN HANDLE hTokenImpersonateUser, IN LPTSTR pClass, IN WCHAR *pwcWindowText );

DWORD				AA_ReportEvent( WCHAR *pwcMsg, WORD wType, DWORD wError );

//
// WZCSVC Functions
//
DWORD				AA_StartWZCSVC(IN BOOL bAutomatic);
DWORD				AA_StopWZCSVC();

//
// SecureW2 Gina Functions
//
#ifndef _WIN32_WCE
DWORD				AA_WriteResult( DWORD dwRet );
DWORD				AA_ReadGinaConfig( IN OUT PSW2_GINA_CONFIG_DATA pGinaConfigData );
DWORD				AA_WriteGinaConfig( IN PSW2_GINA_CONFIG_DATA pGinaConfigData );
#endif // _WIN32_WCE

//
// Trace macro controlling amount of output
//
#ifdef AA_TRACE_ON
#define AA_TRACE( fmt )								\
        {											\
                AA_Trace fmt;						\
        }
#else
#define AA_TRACE( fmt )								\
        {											\
        }
#endif // AA_TRACE_ON

//
// Main trace function
//
void	AA_Trace( TCHAR* fmt, ... );

//
// Crypto
//
DWORD				AA_GenSecureRandom( PBYTE pbRandom, DWORD cbRandom );

DWORD				AA_CryptAcquireContext( HCRYPTPROV *phCSP, 
											WCHAR *pwcContainer,
											WCHAR *pwcCSPName, 
											DWORD dwType );
DWORD				AA_CryptAcquireDefaultContext( HCRYPTPROV *phCSP, WCHAR *pwcContainer );


DWORD				TLSDecBlock( 	IN HCRYPTPROV	hCSP,
									IN HCRYPTKEY	hReadKey,
									IN DWORD		cbHash,
									IN PBYTE		pbEncBlock,
									IN DWORD		cbEncBlock,
									OUT PBYTE		*ppbRecord,
									OUT DWORD		*pcbRecord);

DWORD				TLSEncBlock(	IN HCRYPTPROV	hCSP,
									IN HCRYPTKEY	hWriteKey,
									IN DWORD		dwMacKeySize,
									IN DWORD		dwMacKey,
									IN PBYTE		pbWriteMAC,
									IN OUT DWORD	*pdwSeqNum,
									IN PBYTE		pbData,
									IN DWORD		cbData,
									OUT PBYTE		*ppbEncBlock,
									OUT DWORD		*pcbEncBlock );

DWORD				TLSGetSHA1( IN HCRYPTPROV hCSP, 
								IN PBYTE pbMsg, 
								IN DWORD cbMsg, 
								OUT PBYTE *ppbSHA1, 
								OUT DWORD *pcbSHA1 );

DWORD				TLSGetMD5(	IN HCRYPTPROV hCSP,
								IN PBYTE pbMsg,
								IN DWORD cbMsg,
								OUT PBYTE *ppbMD5,
								OUT DWORD *pcbMD5 );

DWORD				TLSComputeMS(	IN HCRYPTPROV		hCSP,
									IN PBYTE			pbRandomClient,
									IN PBYTE			pbRandomServer,
									IN OUT PBYTE		pbPMS,
									IN OUT PBYTE		pbMS );

DWORD				TLS_PRF(IN HCRYPTPROV hCSP, 
							IN PBYTE pbSecret, 
							IN DWORD cbSecret, 
							IN PBYTE pbLabel, 
							IN DWORD cbLabel, 
							IN PBYTE pbSeed,
							IN DWORD cbSeed,
							IN OUT PBYTE pbData,
							IN DWORD cbData );

DWORD				TLS_P_hash( IN HCRYPTPROV hCSP, 
								IN DWORD dwAlgID, 
								IN PBYTE pbSecret, 
								IN DWORD cbSecret, 
								IN PBYTE pbSeed,
								IN DWORD cbSeed,
								OUT PBYTE pbData, 
								IN DWORD cbData  );

DWORD				TLS_HMAC( HCRYPTPROV hCSP,
								DWORD dwAlgID,
								IN PBYTE pbOrigKey, 
								IN DWORD cbOrigKey, 
								IN PBYTE pbSeed, 
								IN DWORD cbSeed, 
								PBYTE pbData, 
								DWORD cbData );

DWORD				AA_GetCertificate(	PBYTE pbServerCertSHA1, OUT PCCERT_CONTEXT *ppCertContext );

//
// Functions for importing session keys
//
BOOL CreatePrivateExponentOneKey(HCRYPTPROV hProv, 
								 DWORD dwKeySpec,
                                 HCRYPTKEY *hPrivateKey);

BOOL GenerateSessionKeyWithAlgorithm(HCRYPTPROV hProv, 
                                     ALG_ID Alg,
                                     HCRYPTKEY *hSessionKey);

BOOL DeriveSessionKeyWithAlgorithm(HCRYPTPROV hProv, 
                                   ALG_ID Alg,
                                   LPBYTE lpHashingData,
                                   DWORD dwHashingData,
                                   HCRYPTKEY *hSessionKey);

BOOL ExportPlainSessionBlob(HCRYPTKEY hPublicKey,
                            HCRYPTKEY hSessionKey,
                            LPBYTE *pbKeyMaterial,
                            DWORD *dwKeyMaterial);

BOOL ImportPlainSessionBlob(HCRYPTPROV hProv,
                            HCRYPTKEY hPrivateKey,
                            ALG_ID dwAlgId,
                            LPBYTE pbKeyMaterial,
                            DWORD dwKeyMaterial,
                            HCRYPTKEY *hSessionKey);

//
// TLS
//
DWORD				TLSGenSessionID(	IN OUT BYTE pbSessionID[TLS_RANDOM_SIZE],
										IN OUT DWORD *pcbSessionID,
										IN DWORD dwMaxSessionID );

DWORD				TLSGenRandom( IN OUT BYTE pbRandom[TLS_RANDOM_SIZE] );

DWORD				TLSGenPMS( IN OUT BYTE pbPMS[TLS_PMS_SIZE] );

DWORD				TLSInitTLSResponsePacket( IN BYTE bPacketId, 
												IN PPP_EAP_PACKET* pSendPacket, 
												IN DWORD cbSendPacket );

DWORD				TLSInitTLSRequestPacket(IN BYTE		bPacketId, 
											IN PPP_EAP_PACKET* pSendPacket, 
											IN DWORD cbSendPacket );

DWORD				TLSInitTLSAcceptPacket(	IN BYTE				bPacketId,
											IN PPP_EAP_PACKET*	pSendPacket,
											IN DWORD			cbSendPacket );

DWORD				TLSInitTLSRejectPacket(	IN BYTE				bPacketId,
											IN PPP_EAP_PACKET*	pSendPacket,
											IN DWORD			cbSendPacket );

DWORD				TLSReadMessage( IN	PBYTE				pbReceiveMsg,
									IN  DWORD *				pcbReceiveMsg,
									IN	DWORD *				pdwReceiveCursor,
									IN	BYTE				bPacketId,
									IN  PPP_EAP_PACKET*     pReceivePacket,
									OUT PPP_EAP_PACKET*     pSendPacket,
									IN  DWORD               cbSendPacket,
									IN  PPP_EAP_INPUT*      pEapInput,
									OUT PPP_EAP_OUTPUT*     pEapOutput,
									DWORD					dwEAPPacketLength );

DWORD				TLSSendMessage(	IN PBYTE				pbSendMsg,	
									IN DWORD				cbSendMsg,
									IN OUT DWORD			*pdwSendCursor,
									IN BYTE					bPacketId,
									IN PPP_EAP_PACKET*		pSendPacket, 
									IN DWORD				cbSendPacket,
									IN PPP_EAP_INPUT*		pEapInput,
									OUT PPP_EAP_OUTPUT*     pEapOutput );

DWORD				TLSAddHandshakeMessage(	IN OUT DWORD *pdwHandshakeMsgCount,
											IN OUT PBYTE pbHandshakeMsg[TLS_MAX_HS],
											IN OUT DWORD cbHandshakeMsg[TLS_MAX_HS],
											IN PBYTE pbMessage, 
											IN DWORD cbMessage );

DWORD				TLSAddRecord(	IN	PBYTE		pbRecord,
									IN  DWORD		cbRecord,
									IN	OUT PBYTE	pbMessage,
									IN	OUT DWORD	*pcbMessage );

DWORD				TLSAddMessage(	IN PBYTE			pbMessage,
									IN DWORD			cbMessage,
									IN DWORD			cbTotalMessage,
									IN PPP_EAP_PACKET*	pSendPacket,
									IN DWORD			cbSendPacket );

DWORD				TLSMakeFragResponse(	IN BYTE bPacketId,
											IN PPP_EAP_PACKET* pSendPacket, 
											IN DWORD cbSendPacket );

DWORD				TLSMakeApplicationRecord(	IN HCRYPTPROV	hCSP,
												IN HCRYPTKEY	hWriteKey,
												IN DWORD		dwMacKey,
												IN DWORD		dwMacKeySize,
												IN PBYTE		pbWriteMAC,
												IN DWORD		*pdwSeqNum,
												IN PBYTE		pbMessage,
												IN DWORD		cbMessage,
												IN PBYTE		*ppbRecord,
												IN DWORD		*pcbRecord,
												IN BOOL			bEncrypt );

DWORD				TLSMakeHandshakeRecord( IN HCRYPTPROV	hCSP,
											IN HCRYPTKEY	hWriteKey,
											IN DWORD		dwMacKey,
											IN DWORD		dwMacKeySize,
											IN PBYTE		pbWriteMAC,
											IN DWORD		*pdwSeqNum,
											IN PBYTE		pbMessage,
											IN DWORD		cbMessage,
											IN PBYTE*		ppbRecord,
											IN DWORD*		pcbRecord,
											IN BOOL			bEncrypt );

DWORD				TLSMakeChangeCipherSpecRecord(	IN PBYTE			*ppbRecord,
													IN DWORD			*pcbRecord );

DWORD				TLSMakeClientHelloMessage(	IN BYTE				pbRandomClient[TLS_RANDOM_SIZE],
												IN PBYTE			pbTLSSessionID,
												IN DWORD			cbTLSSessionID,
												OUT PBYTE			*ppbTLSMessage,
												OUT DWORD			*pcbTLSMessage,
												OUT DWORD			*pdwEncKey,
												OUT DWORD			*pdwEncKeySize,
												OUT DWORD			*pdwMacKey,
												OUT DWORD			*pdwMacKeySize );

DWORD				TLSMakeServerHelloMessage(	IN BYTE				pbRandomServer[TLS_RANDOM_SIZE],
												IN PBYTE			pbTLSSessionID,
												IN DWORD			cbTLSSessionID,
												OUT PBYTE			*ppbTLSMessage,
												OUT DWORD			*pcbTLSMessage,
												OUT DWORD			*pdwEncKey,
												OUT DWORD			*pdwEncKeySize,
												OUT DWORD			*pdwMacKey,
												OUT DWORD			*pdwMacKeySize );

DWORD				TLSMakeCertificateRequestMessage(	IN PBYTE	*ppbTLSMessage,
														IN DWORD	*pcbTLSMessage );

DWORD				TLSMakeServerHelloDoneMessage(	IN PBYTE	*ppbTLSMessage,
													IN DWORD	*pcbTLSMessage );

DWORD				TLSMakeClientCertificateMessage(	OUT PBYTE			*ppbTLSMessage,
														OUT DWORD			*pcTLSMessage );

DWORD				TLSMakeServerCertificateMessage( 	PBYTE				pbServerCert,
														OUT PBYTE			*ppbTLSMessage,
														OUT DWORD			*pcbTLSMessage );

DWORD				TLSMakeClientKeyExchangeMessage(	IN PBYTE			pbEncPMS,
														IN DWORD			cbEncPMS,
														OUT PBYTE			*ppbTLSMessage,
														OUT DWORD			*pcTLSMessage );

DWORD				TLSMakeFinishedMessage(	IN HCRYPTPROV		hCSP,
											IN DWORD			dwHandshakeMsgCount,
											IN PBYTE			pbHandshakeMsg[TLS_MAX_HS],
											IN DWORD			cbHandshakeMsg[TLS_MAX_HS],
											IN PCHAR			pcLabel,
											IN DWORD			ccLabel,
											IN PBYTE			pbMS,
											IN DWORD			cbMS,
											OUT PBYTE			*ppbTLSMessage,
											OUT DWORD			*pcbTLSMessage );

DWORD				TLSVerifyFinishedMessage(	IN HCRYPTPROV		hCSP,
												IN DWORD			dwHandshakeMsgCount,
												IN PBYTE			pbHandshakeMsg[TLS_MAX_HS],
												IN DWORD			cbHandshakeMsg[TLS_MAX_HS],
												IN PCHAR			pcLabel,
												IN DWORD			ccLabel,
												IN PBYTE			pbMS,
												IN DWORD			cbMS,
												IN PBYTE			pbVerifyFinished,
												IN DWORD			cbVerifyFinished );

//
// Profile
//
DWORD				AA_CreateAdminKey( IN HKEY hKey, 
										IN WCHAR *pwcSubKey, 
										OUT HKEY *phSubKey,
										OUT DWORD *pdwDisposition );

DWORD				AA_CreateSecureKey( IN HKEY hKey, 
										IN WCHAR *pwcSubKey, 
										OUT HKEY *phSubKey,
										OUT DWORD *pdwDisposition );

#endif