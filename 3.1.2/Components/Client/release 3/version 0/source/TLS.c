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
// Name: TLS.c
// Description: Contains the main TLS functionality
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
#include "Main.h"
#include <math.h>

//
// Name: TLSParseHandshakeRecord
// Description: This function parses a handshake message and acts accordingly
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSParseHandshakeRecord(	IN PSW2_SESSION_DATA pSessionData, 
							IN PBYTE pbRecord, 
							IN DWORD cbRecord )
{
	DWORD		dwRecordLength;
	DWORD		dwCursor = 0;
	DWORD		dwCertificateListLength = 0;
	DWORD		dwCertCount = 0;
	DWORD		dwServerKeyExchangeLength;
	DWORD		dwCertRequestLength;
	DWORD		dwErr;
	DWORD		dwRet;

	dwRet = NO_ERROR;


	AA_TRACE( ( TEXT( "TLSParseHandshakeRecord" ) ) );

	AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::TLS message dump(%d):\n%s" ), cbRecord, AA_ByteToHex( pbRecord, cbRecord ) ) );

	//
	// Loop through message
	//
	while( dwCursor < cbRecord && dwRet == NO_ERROR )
	{
		switch( pbRecord[dwCursor] )
		{
			case 0x02: //server_hello

				dwCursor++;

				if( dwCursor > cbRecord )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				//
				// Length of record is 3 bytes!!
				// skip first byte and read in integer
				//
				AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::found server_hello record, length: %ld" ), AA_WireToHostFormat24( &( pbRecord[dwCursor] ) ) ) );

				dwCursor+=3;

				if( dwCursor > cbRecord )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				//
				// Check TLS version
				//
				if( ( pbRecord[dwCursor] == 0x03 ) && ( pbRecord[dwCursor+1] == 0x01 ) )
				{
					dwCursor+=2;

					if( dwCursor > cbRecord )
					{
						dwRet = ERROR_PPP_INVALID_PACKET;

						break;
					}

					//
					// Copy Random data
					//
					memcpy( pSessionData->pbRandomServer, &( pbRecord[dwCursor] ), TLS_RANDOM_SIZE );

					AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::Server Random: %s" ), AA_ByteToHex( pSessionData->pbRandomServer, 32 ) ) );

					dwCursor += TLS_RANDOM_SIZE;

					if( dwCursor > cbRecord )
					{
						dwRet = ERROR_PPP_INVALID_PACKET;

						break;
					}

					//
					// Session length
					//
					pSessionData->pUserData->cbTLSSessionID = ( int ) pbRecord[dwCursor];

					AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::SessionID length: %d" ), pSessionData->pUserData->cbTLSSessionID ) );

					if( pSessionData->pUserData->cbTLSSessionID > 0 )
					{
						dwCursor++;

						if( dwCursor > cbRecord )
						{
							dwRet = ERROR_PPP_INVALID_PACKET;

							break;
						}

						//
						// Save session ID
						//
						memcpy( pSessionData->pUserData->pbTLSSessionID, &( pbRecord[dwCursor] ), pSessionData->pUserData->cbTLSSessionID );

						AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::SessionID:%s" ), AA_ByteToHex( pSessionData->pUserData->pbTLSSessionID, pSessionData->pUserData->cbTLSSessionID ) ) );

#ifndef _WIN32_WCE
						//
						// set the time this session ID was set
						//
						time( &( pSessionData->pUserData->tTLSSessionID ) );
#endif

						dwCursor = dwCursor + pSessionData->pUserData->cbTLSSessionID;
					}
					else
					{
						//
						// previous securew2 version required a session id, according to RFC this
						// is not correct as an empty one simply means do not cache this session
						//
						AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::SessionID empty" ) ) );

						memset( pSessionData->pUserData->pbTLSSessionID, 0, sizeof( pSessionData->pUserData->pbTLSSessionID ) );

						dwCursor++;
					}

					if( dwCursor > cbRecord )
					{
						dwRet = ERROR_PPP_INVALID_PACKET;

						break;
					}

					pSessionData->pbCipher[0] = pbRecord[dwCursor];

					dwCursor++;

					if( dwCursor > cbRecord )
					{
						dwRet = ERROR_PPP_INVALID_PACKET;

						break;
					}

					pSessionData->pbCipher[1] = pbRecord[dwCursor];

					AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::Cypher(%x, %x)" ), pSessionData->pbCipher[0], pSessionData->pbCipher[1] ) );

					//
					// Found the cipher message, should be either 0x13 or 0x0A
					//
					if( pSessionData->pbCipher[0] == 0x00 &&
						pSessionData->pbCipher[1] == 0x0A )
					{
						//
						// TLS_RSA_WITH_3DES_EDE_CBC_SHA { 0x00, 0x0A }
						//
						//
						//
						// Connect to help CSP
						//
						if( !CryptAcquireContext( &pSessionData->hCSP,
													NULL,
													MS_ENHANCED_PROV,
													PROV_RSA_FULL,
													0 ) )
						{
							dwErr = GetLastError();

							if( dwErr == NTE_BAD_KEYSET )
							{
								if( !CryptAcquireContext( &pSessionData->hCSP,
														NULL,
														MS_ENHANCED_PROV,
														PROV_RSA_FULL,
														CRYPT_NEWKEYSET ) )
								{
									AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::CryptAcquireContext(NEWKEYSET):: FAILED (%d)" ), GetLastError() ) );

									dwRet = ERROR_ENCRYPTION_FAILED;
								}
							}
							else
							{
								AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::CryptAcquireContext(0):: FAILED (%d)" ), GetLastError() ) );

								dwRet = ERROR_ENCRYPTION_FAILED;
							}
						}
					}
					else if( pSessionData->pbCipher[0] == 0x00 &&
							pSessionData->pbCipher[1] == 0x13 )
					{
						//
						// TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA { 0x00, 0x13 }
						//

						//
						// Connect to help CSP
						//
						if( !CryptAcquireContext( &pSessionData->hCSP,
													NULL,
													MS_ENH_DSS_DH_PROV,
													PROV_DH_SCHANNEL,
													0 ) )
						{
							dwErr = GetLastError();

							if( dwErr == NTE_BAD_KEYSET )
							{
								if( !CryptAcquireContext( &pSessionData->hCSP,
														NULL,
														MS_ENH_DSS_DH_PROV,
														PROV_DH_SCHANNEL,
														CRYPT_NEWKEYSET ) )
								{
									AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::CryptAcquireContext(NEWKEYSET):: FAILED (%d)" ), GetLastError() ) );

									dwRet = ERROR_ENCRYPTION_FAILED;
								}
							}
							else
							{
								AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::CryptAcquireContext(0):: FAILED (%d)" ), GetLastError() ) );

								dwRet = ERROR_ENCRYPTION_FAILED;
							}
						}
					}
					else
					{
						//
						// this is not possible, except if the RADIUS TLS implementation is screwy
						//
						AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::no cipher" ) ) );

						dwRet = ERROR_ENCRYPTION_FAILED;
					}

					if( dwRet != NO_ERROR )
						break;

					dwCursor++;

					if( dwCursor > cbRecord )
					{
						dwRet = ERROR_PPP_INVALID_PACKET;

						break;
					}

					pSessionData->bCompression = pbRecord[dwCursor];

					AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::Compression(%x)" ), pSessionData->bCompression ) );

					dwCursor++;
				}
				else
				{
					AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::ERROR::TLS:incorrect version" ) ) );

					dwRet = ERROR_PPP_INVALID_PACKET;
				}

			break;

			case 0x0B: // certificate

				dwCursor++;

				if( dwCursor > cbRecord )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::found certificate list record, length: %ld" ), AA_WireToHostFormat24( &( pbRecord[dwCursor] ) ) ) );

				dwCursor+=3;

				if( dwCursor > cbRecord )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				dwCertificateListLength = AA_WireToHostFormat24( &( pbRecord[dwCursor] ) );

				AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::found another certificate list record, length: %d" ), dwCertificateListLength ) );

				dwCursor+=3;

				if( dwCursor > cbRecord )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				dwCertCount = 0;

				//
				// Loop through cert list until done or we have read in 10 certs
				//
				while( ( dwCursor <= dwCertificateListLength ) && ( dwCertCount < TLS_MAX_CERT ) && dwRet == NO_ERROR )
				{
					pSessionData->cbCertificate[dwCertCount] = AA_WireToHostFormat24( &( pbRecord[dwCursor] ) );

					dwCursor+=3;

					if( dwCursor > cbRecord )
					{
						dwRet = ERROR_PPP_INVALID_PACKET;

						break;
					}

					AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::found certificate record, length: %ld" ), pSessionData->cbCertificate[dwCertCount] ) );

					if( pSessionData->cbCertificate[dwCertCount] <= TLS_MAX_CERT_SIZE )
					{
						memcpy( pSessionData->pbCertificate[dwCertCount], &( pbRecord[dwCursor] ), pSessionData->cbCertificate[dwCertCount] );

						AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::Certificate dump(%ld):\n%s" ), pSessionData->cbCertificate[dwCertCount], AA_ByteToHex( pSessionData->pbCertificate[dwCertCount], pSessionData->cbCertificate[dwCertCount] ) ) );
					}
					else
					{
						AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::ERROR:could not allocate memory for pSessionData->pbCertificate" ) ) );

						dwRet = ERROR_NOT_ENOUGH_MEMORY;

						break;
					}

					dwCursor += pSessionData->cbCertificate[dwCertCount];

					dwCertCount++;
				}

				//
				// Save number of certificates
				//
				pSessionData->dwCertCount = dwCertCount;// - 1;

			break;

			case 0x0C: // server_key_exchange
				
				//
				//
				//
				dwCursor++;

				if( dwCursor > cbRecord )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				dwServerKeyExchangeLength = AA_WireToHostFormat24( &( pbRecord[dwCursor] ) );

				AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::found server_key_exchange record, length: %ld" ), dwServerKeyExchangeLength ) );

				dwCursor+=3;

				if( dwCursor > cbRecord )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::dump:\n%s" ), AA_ByteToHex( &( pbRecord[dwCursor] ), dwServerKeyExchangeLength ) ) );

				dwCursor = dwCursor + dwServerKeyExchangeLength;

			break;

			case 0x0D: // certificate request

				dwCursor++;

				if( dwCursor > cbRecord )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				dwCertRequestLength = AA_WireToHostFormat24( &( pbRecord[dwCursor] ) );

				AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::found certificate_request, length: %ld" ), dwCertRequestLength ) );

				dwCursor+=3;

				if( dwCursor > cbRecord )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::dump:\n%s" ), AA_ByteToHex( &( pbRecord[dwCursor] ), dwCertRequestLength ) ) );

				dwCursor += dwCertRequestLength;

				pSessionData->bCertRequest = TRUE;

			break;

			case 0x0E: // ServerDone

				dwCursor++;

				if( dwCursor > cbRecord )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::found server_done record, length: %d" ), AA_WireToHostFormat24( &( pbRecord[dwCursor] ) ) ) );

				dwCursor+=3;

			break;

			case 0x14: // Finished message

				dwCursor++;

				if( dwCursor > cbRecord )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				dwRecordLength = AA_WireToHostFormat24( &( pbRecord[dwCursor] ) );

				dwCursor+=3;

				if( dwCursor > cbRecord )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				//
				// Verify the finished message
				//
				if( ( dwRet = TLSVerifyFinishedMessage( pSessionData->hCSP,
														pSessionData->dwHandshakeMsgCount,
														pSessionData->pbHandshakeMsg,
														pSessionData->cbHandshakeMsg,
														TLS_SERVER_FINISHED_LABEL,
														sizeof( TLS_SERVER_FINISHED_LABEL ) -1,
														pSessionData->pUserData->pbMS,
														TLS_MS_SIZE,
														&( pbRecord[dwCursor] ), 
														dwRecordLength ) ) == NO_ERROR )
					pSessionData->bServerFinished = TRUE;

				dwCursor += dwRecordLength;

			break;

			default:

				AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::WARNING::unknown TLS record: %x" ), pbRecord[dwCursor] ) );

				dwCursor++;

			break;
		}
	}

	//
	// Add the message for finished message hash
	//
	TLSAddHandshakeMessage( &pSessionData->dwHandshakeMsgCount,
							pSessionData->pbHandshakeMsg,
							pSessionData->cbHandshakeMsg,
							pbRecord, 
							cbRecord );

	AA_TRACE( ( TEXT( "TLSParseHandshakeRecord::returning: %x" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSParseApplicationDataRecord
// Description: This function parses a application data message (DIAMETER AVPs) and acts accordingly
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSParseApplicationDataRecord( IN PSW2_SESSION_DATA pSessionData, IN PBYTE pbRecord, IN DWORD cbRecord )
{
	DWORD		dwAVPLength;
	DWORD		dwDataLength;
	DWORD		dwCode;
	DWORD		dwPadding;
	BYTE		bFlags;
	DWORD		dwCursor = 0;
	DWORD		dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSParseApplicationDataRecord::message dump(%d):\n%s" ), cbRecord, AA_ByteToHex( pbRecord, cbRecord ) ) );

	if( cbRecord < 1 )
		return dwRet;

	//
	// Loop through message
	//
	while( dwCursor < cbRecord && dwRet == NO_ERROR )
	{
		dwCode = AA_WireToHostFormat32( &( pbRecord[dwCursor] ) );

		AA_TRACE( ( TEXT( "TLSParseApplicationDataRecord::Code: %x" ), dwCode ) );

		dwCursor+=4;

		if( dwCursor > cbRecord )
		{
			dwRet = ERROR_PPP_INVALID_PACKET;

			break;
		}

		bFlags = pbRecord[dwCursor];

		AA_TRACE( ( TEXT( "TLSParseApplicationDataRecord::Flags: %x" ), bFlags ) );

		dwCursor++;

		if( dwCursor > cbRecord )
		{
			dwRet = ERROR_PPP_INVALID_PACKET;

			break;
		}

		//
		// Length of total AVP
		//
		dwAVPLength = AA_WireToHostFormat24(&( pbRecord[dwCursor] ) );

		AA_TRACE( ( TEXT( "TLSParseApplicationDataRecord::Length: %ld" ), dwAVPLength ) );

		dwCursor+=3;

		if( dwCursor > cbRecord )
		{
			dwRet = ERROR_PPP_INVALID_PACKET;

			break;
		}

		//
		// TODO: if AVP FLags contains the V (Vendor bit) then the following 4 bytes are
		// the vendor field
		//

		//
		// Calculate padding
		//
		// length of AVP must be multiple of 4 octets
		//
		dwPadding = ( dwAVPLength ) % 4;

		if( dwPadding != 0 )
			dwPadding = 4 - dwPadding;

		AA_TRACE( ( TEXT( "TLSParseApplicationDataRecord::Padding: %ld" ), dwPadding ) );

		//
		// Length of rest of packet is
		//
		// dwDataLength = dwAVPLength - code (4) - Flags(1) - Length of msg (3)
		//
		dwDataLength = dwAVPLength - 4 - 1 - 3;

		switch( dwCode )
		{
			case 0x4F: // Eap-Message
				
				AA_TRACE( ( TEXT( "TLSParseApplicationDataRecord::Eap-Message(%d): %s" ), dwDataLength, AA_ByteToHex( &( pbRecord[dwCursor] ), dwDataLength ) ) );

				if( dwDataLength <= TLS_MAX_EAPMSG )
				{
					pSessionData->InnerSessionData.cbInnerEapMessage = dwDataLength;

					memset( pSessionData->InnerSessionData.pbInnerEapMessage, 0, sizeof( pSessionData->InnerSessionData.pbInnerEapMessage ) );
					memcpy( pSessionData->InnerSessionData.pbInnerEapMessage, &( pbRecord[dwCursor] ), pSessionData->InnerSessionData.cbInnerEapMessage );
				}
				else
				{
					AA_TRACE( ( TEXT( "TLSParseApplicationDataRecord::could not copy Eap-Message attribute" ) ) );
				}

			break;

			case 0x50: // Message-Authenticator

				AA_TRACE( ( TEXT( "TLSParseApplicationDataRecord::Message-Authenticator(%d): %s" ), dwDataLength, AA_ByteToHex( &( pbRecord[dwCursor] ), dwDataLength ) ) );

				//
				// Is ignored
				//
			
			break;

			case 0x18: // State

				AA_TRACE( ( TEXT( "TLSParseApplicationDataRecord::State(%d): %s" ), dwDataLength, AA_ByteToHex( &( pbRecord[dwCursor] ), dwDataLength ) ) );

				if( dwDataLength <= RADIUS_MAX_STATE )
				{
					pSessionData->cbState = dwDataLength;

					memset( pSessionData->pbState, 0, sizeof( pSessionData->pbState ) );
					memcpy( pSessionData->pbState, &( pbRecord[dwCursor] ), pSessionData->cbState );
				}
				else
				{
					AA_TRACE( ( TEXT( "TLSParseApplicationDataRecord::could not copy State attribute" ) ) );
				}

			break;

			default:

				AA_TRACE( ( TEXT( "TLSParseApplicationDataRecord::WARNING::unknown record: %x" ), pbRecord[dwCursor] ) );

			break;
		}

		dwCursor+=dwDataLength+dwPadding;
	}

	AA_TRACE( ( TEXT( "TLSParseApplicationDataRecord::returning: %x" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSParseServerPacket
// Description: This function parses a server packet message and acts accordingly
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSParseServerPacket(	IN PSW2_SESSION_DATA pSessionData, 
						IN PBYTE pbEapMsg, 
						IN DWORD cbEAPMsg )
{
	DWORD		dwRecordLength;
	DWORD		dwCursor = 0;
	PBYTE		pbRecord;
	DWORD		cbRecord;
	DWORD		dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSParseServerPacket" ) ) );
	AA_TRACE( ( TEXT( "TLSParseServerPacket::length of TLS message: %d" ), cbEAPMsg ) );
	AA_TRACE( ( TEXT( "TLSParseServerPacket::TLS message dump:\n%s" ), AA_ByteToHex( pbEapMsg, cbEAPMsg ) ) );

	//
	// Check for TTLS
	//
	while( ( dwCursor < cbEAPMsg ) && ( dwRet == NO_ERROR ) )
	{
		AA_TRACE( ( TEXT( "TLSParseServerPacket::entering loop, cursor: %d: byte %x" ), dwCursor, pbEapMsg[dwCursor] ) );

		//
		// ssl record header
		//
		if( pbEapMsg[dwCursor] == 0x16 ) // handshake message
		{
			dwCursor++;

			//
			// Check major minor number
			//
			if( ( pbEapMsg[dwCursor] = 0x03 ) && ( pbEapMsg[dwCursor+1] == 0x01 ) )
			{			
				dwCursor+=2;

				if( dwCursor > cbEAPMsg )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				dwRecordLength = AA_WireToHostFormat16( &( pbEapMsg[dwCursor] ) );

				dwCursor+=2;

				if( dwCursor > cbEAPMsg )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				AA_TRACE( ( TEXT( "TLSParseServerPacket::length of Handshake Record: %d" ), dwRecordLength ) );

				if( pSessionData->bCipherSpec )
				{
					if( ( dwRet = TLSDecBlock( pSessionData->hCSP,
												pSessionData->hReadKey,
												pSessionData->dwMacKeySize,
												&( pbEapMsg[dwCursor] ), 
												dwRecordLength, 
												&pbRecord, 
												&cbRecord ) ) == NO_ERROR )
					{
						AA_TRACE( ( TEXT( "TLSParseServerPacket::decrypted block(%d): %s" ), cbRecord, AA_ByteToHex( pbRecord, cbRecord ) ) );

						dwRet = TLSParseHandshakeRecord( pSessionData, pbRecord, cbRecord );

						free( pbRecord );
						cbRecord = 0;
					}
				}
				else
					dwRet = TLSParseHandshakeRecord( pSessionData, &( pbEapMsg[dwCursor] ), dwRecordLength );

				dwCursor+=dwRecordLength;
			}
			else
			{
				AA_TRACE( ( TEXT( "TLSParseServerPacket::ERROR::SSL::incorrect version" ) ) );

				dwRet = ERROR_PPP_INVALID_PACKET;
			}
		}
		else if( pbEapMsg[dwCursor] == 0x14 ) // change_cipher_spec message
		{
			AA_TRACE( ( TEXT( "TLSParseServerPacket::found changed cipher_spec message" ) ) );

			dwCursor++;

			if( dwCursor > cbEAPMsg )
			{
				dwRet = ERROR_PPP_INVALID_PACKET;

				break;
			}

			//
			// Check major minor number
			//
			if( ( pbEapMsg[dwCursor] = 0x03 ) && ( pbEapMsg[dwCursor+1] == 0x01 ) )
			{			
				dwCursor+=2;

				if( dwCursor > cbEAPMsg )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}				
				
				dwRecordLength = AA_WireToHostFormat16( &( pbEapMsg[dwCursor] ) );

				dwCursor+=2;

				if( dwCursor > cbEAPMsg )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				if( pbEapMsg[dwCursor] != 0x01 )
				{
					//
					// ChangeCypherSpec should be value 1 from now on 
					// indicating we are encrypting the line
					//
					pSessionData->bCipherSpec = FALSE;

					dwRet = ERROR_NO_REMOTE_ENCRYPTION;
				}
				else
				{
					//
					// If we receive a change_cipher_spec 1 from the server
					// and we are not in change_cipher_spec 1 mode this could
					// mean a session resumption
					// If we also want to resume a session then import the 
					// previous master_key and derive the encryption keys
					// (to read the server finished message)
					// and set the change_cipher_spec to 1
					//
					if( !pSessionData->bCipherSpec )
					{
						if( pSessionData->pProfileData->bUseSessionResumption )
						{
							if( ( dwRet = TLSDeriveKeys( pSessionData ) ) == NO_ERROR )
								pSessionData->bCipherSpec = TRUE;						
						}
						else
							dwRet = ERROR_PPP_INVALID_PACKET;
					}

					dwCursor++;
				}
			}
			else
			{
				AA_TRACE( ( TEXT( "TLSParseServerPacket::ERROR::SSL::incorrect version" ) ) );

				dwRet = ERROR_PPP_INVALID_PACKET;

				break;
			}
		} 
		else if( pbEapMsg[dwCursor] == 0x17 ) // application data
		{
			AA_TRACE( ( TEXT( "TLSParseServerPacket::application data" ) ) );

			dwCursor++;

			if( dwCursor > cbEAPMsg )
			{
				dwRet = ERROR_PPP_INVALID_PACKET;

				break;
			}

			//
			// Check major minor number
			//
			if( ( pbEapMsg[dwCursor] = 0x03 ) && ( pbEapMsg[dwCursor+1] == 0x01 ) )
			{			
				dwCursor++;
				dwCursor++;

				if( dwCursor > cbEAPMsg )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}				
				
				dwRecordLength = AA_WireToHostFormat16( &( pbEapMsg[dwCursor] ) );

				dwCursor++;
				dwCursor++;

				if( dwCursor > cbEAPMsg )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				if( ( dwRet = TLSDecBlock( pSessionData->hCSP,
												pSessionData->hReadKey,
												pSessionData->dwMacKeySize, &pbEapMsg[dwCursor], dwRecordLength, &pbRecord, &cbRecord ) ) == NO_ERROR )
				{
					AA_TRACE( ( TEXT( "TLSParseServerPacket::application data (%d): %s" ), cbRecord, AA_ByteToHex( pbRecord, cbRecord) ) );

					//
					// When using PEAP we do not need to parse the server packet
					// the data that was encrypted is the EAP message itself
					//
#ifdef EAP_USE_PEAP
					if( cbRecord <= TLS_MAX_EAPMSG )
					{
#ifdef EAP_USE_MS_PEAP

						//
						// First check if this is a message for our EAP dll
						// 
						if( ( DWORD ) pbRecord[0] == pSessionData->InnerSessionData.pInnerEapConfigData->dwEapType[pSessionData->InnerSessionData.pInnerEapConfigData->dwCurrentEapMethod] )
						{
							//
							// When in MS mode then we must the EAP headers
							//
							pSessionData->InnerSessionData.cbInnerEapMessage = 0x04 + cbRecord;

							memset( pSessionData->InnerSessionData.pbInnerEapMessage, 0, sizeof( pSessionData->InnerSessionData.pbInnerEapMessage ) );

							//
							// Request
							//
							pSessionData->InnerSessionData.pbInnerEapMessage[0] = 0x01; // Code
							pSessionData->InnerSessionData.pbInnerEapMessage[1] = pSessionData->bPacketId; // Id
							AA_HostToWireFormat16( ( DWORD ) pSessionData->InnerSessionData.cbInnerEapMessage, &( pSessionData->InnerSessionData.pbInnerEapMessage[2] ) ); // length

							memcpy( &( pSessionData->InnerSessionData.pbInnerEapMessage[4] ), pbRecord, cbRecord );
						}
						else
						{
							//
							// Handle normally
							//
							pSessionData->InnerSessionData.cbInnerEapMessage = cbRecord;

							memset( pSessionData->InnerSessionData.pbInnerEapMessage, 0, sizeof( pSessionData->InnerSessionData.pbInnerEapMessage ) );

							memcpy( pSessionData->InnerSessionData.pbInnerEapMessage, pbRecord, cbRecord );
						}

						AA_TRACE( ( TEXT( "TLSParseServerPacket::pSessionData->InnerSessionData.pbInnerEapMessage(%d): %s" ), pSessionData->InnerSessionData.cbInnerEapMessage, AA_ByteToHex( pSessionData->InnerSessionData.pbInnerEapMessage, pSessionData->InnerSessionData.cbInnerEapMessage ) ) );
#else
						pSessionData->InnerSessionData.cbInnerEapMessage = cbRecord;

						memset( pSessionData->InnerSessionData.pbInnerEapMessage, 0, sizeof( pSessionData->InnerSessionData.pbInnerEapMessage ) );
						memcpy( pSessionData->InnerSessionData.pbInnerEapMessage, pbRecord, pSessionData->InnerSessionData.cbInnerEapMessage );
#endif
					}
					else
					{
						dwRet = ERROR_PPP_INVALID_PACKET;
					}

#else
					dwRet = TLSParseApplicationDataRecord( pSessionData, pbRecord, cbRecord );
#endif

					free( pbRecord );
					cbRecord = 0;
				}
				else
				{
					if( dwRet == ERROR_PPP_INVALID_PACKET )
						dwRet = NO_ERROR;
					else
						break;
				}

				dwCursor = dwCursor + dwRecordLength;
			}
			else
			{
				dwRet = ERROR_PPP_INVALID_PACKET;

				break;
			}
		}
		else if( pbEapMsg[dwCursor] == 0x15 ) // alert!
		{
			AA_TRACE( ( TEXT( "TLSParseServerPacket::alert" ) ) );

			dwCursor++;

			if( dwCursor > cbEAPMsg )
			{
				dwRet = ERROR_PPP_INVALID_PACKET;

				break;
			}

			//
			// Check major minor number
			//
			if( ( pbEapMsg[dwCursor] = 0x03 ) && ( pbEapMsg[dwCursor+1] == 0x01 ) )
			{			
				dwCursor++;
				dwCursor++;

				if( dwCursor > cbEAPMsg )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}				
				
				dwRecordLength = AA_WireToHostFormat16( &( pbEapMsg[dwCursor] ) );

				dwCursor++;
				dwCursor++;

				if( dwCursor > cbEAPMsg )
				{
					dwRet = ERROR_PPP_INVALID_PACKET;

					break;
				}

				AA_TRACE( ( TEXT( "TLSParseServerPacket::alert data (%d): %s" ), dwRecordLength, AA_ByteToHex( &pbEapMsg[dwCursor], dwRecordLength ) ) );

				pSessionData->bFoundAlert;

				dwRet = ERROR_NOT_AUTHENTICATED;

				dwCursor = dwCursor + dwRecordLength;
			}
			else
			{
				dwRet = ERROR_PPP_INVALID_PACKET;

				break;
			}
		}
		else
		{
			AA_TRACE( ( TEXT( "TLSParseServerPacket::ERROR::SSL::unknown record" ) ) );

			dwRet = ERROR_PPP_INVALID_PACKET;
		}
	}

	AA_TRACE( ( TEXT( "TLSParseServerPacket::returning: %d" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSBuildResponsePacket
// Description: This function builds the next response message
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSBuildResponsePacket( PSW2_SESSION_DATA			pSessionData,
						OUT PPP_EAP_PACKET		*pSendPacket,
						IN  DWORD               cbSendPacket,
						IN PPP_EAP_INPUT		*pEapInput,
						IN PPP_EAP_OUTPUT		*pEapOutput )
{
	PBYTE			pbTLSMessage;
	DWORD			cbTLSMessage;
	PBYTE			pbRecord;
	DWORD			cbRecord;
	PBYTE			pbEncPMS;
	DWORD			cbEncPMS;
	DWORD			dwRet;

	AA_TRACE( ( TEXT( "TLSBuildResponsePacket" ) ) );

	dwRet = NO_ERROR;

	switch( pSessionData->AuthState )
	{
		case AUTH_STATE_Start:

			if( ( dwRet = TLSInitTLSResponsePacket( pSessionData->bPacketId, pSendPacket, cbSendPacket ) ) == NO_ERROR )
			{
				if( ( dwRet = TLSMakeClientHelloMessage( pSessionData->pbRandomClient,
														pSessionData->pUserData->pbTLSSessionID,
														pSessionData->pUserData->cbTLSSessionID,
														&pbTLSMessage, 
														&cbTLSMessage, 
														&pSessionData->dwEncKey, 
														&pSessionData->dwEncKeySize,
														&pSessionData->dwMacKey,
														&pSessionData->dwMacKeySize ) ) == NO_ERROR )
				{
					if( ( dwRet = TLSMakeHandshakeRecord( pSessionData->hCSP,
															pSessionData->hWriteKey,
															pSessionData->dwMacKey,
															pSessionData->dwMacKeySize,
															pSessionData->pbWriteMAC,
															&( pSessionData->dwSeqNum ),
															pbTLSMessage, 
															cbTLSMessage, 
															&pbRecord, 
															&cbRecord, 
															pSessionData->bCipherSpec ) ) == NO_ERROR )
					{
						if( ( dwRet = TLSAddMessage( pbRecord, 
													cbRecord, 
													cbRecord,
													pSendPacket, 
													cbSendPacket ) ) == NO_ERROR )
						{
							//
							// Save for later use with finished message
							//
							dwRet = TLSAddHandshakeMessage( &( pSessionData->dwHandshakeMsgCount ), 
													pSessionData->pbHandshakeMsg,
													pSessionData->cbHandshakeMsg,
													pbTLSMessage,
													cbTLSMessage );

							pEapOutput->Action = EAPACTION_Send;

							pSessionData->AuthState = AUTH_STATE_Server_Hello;
						}

						free( pbRecord );
						cbRecord = 0;
					}

					free( pbTLSMessage );
					cbTLSMessage = 0;
				}
			}

		break;

		case AUTH_STATE_Verify_Cert:
		case AUTH_STATE_Server_Hello:

			if( ( dwRet = TLSInitTLSResponsePacket( pSessionData->bPacketId, 
													pSendPacket, 
													cbSendPacket ) ) == NO_ERROR )
			{
				//
				// If a certificate was requested then respond with an empty certificate list
				//
				if( pSessionData->bCertRequest )
				{
					//
					// Add certificate handshake record
					//
					if( ( dwRet = TLSMakeClientCertificateMessage( &pbTLSMessage, 
																	&cbTLSMessage ) ) == NO_ERROR )
					{
						if( ( dwRet = TLSMakeHandshakeRecord(	pSessionData->hCSP,
																pSessionData->hWriteKey,
																pSessionData->dwMacKey,
																pSessionData->dwMacKeySize,
																pSessionData->pbWriteMAC,
																&( pSessionData->dwSeqNum ), 
																pbTLSMessage, 
																cbTLSMessage, 
																&pbRecord, 
																&cbRecord, 
																pSessionData->bCipherSpec ) ) == NO_ERROR )
						{
							if( ( dwRet = TLSAddMessage( pbRecord, 
														cbRecord, 
														cbRecord,
														pSendPacket, 
														cbSendPacket ) ) == NO_ERROR )
							{
								dwRet = TLSAddHandshakeMessage( &( pSessionData->dwHandshakeMsgCount ), 
														pSessionData->pbHandshakeMsg,
														pSessionData->cbHandshakeMsg,
														pbTLSMessage, 
														cbTLSMessage );
							}

							free( pbRecord );
							cbRecord = 0;
						}

						free( pbTLSMessage );
						cbTLSMessage = 0;
					}
				}
				
				//
				// Add client key exchange handshake record
				//
				if( dwRet == NO_ERROR )
				{
					//
					// Generate and encrypt the pre_master_secret or
					// ClientDiffieHellmanPublic
					//
					if( pSessionData->pbCipher[0] == 0x00 &&
						pSessionData->pbCipher[1] == 0x0A )
					{
						dwRet = TLSGenRSAEncPMS( pSessionData, &pbEncPMS, &cbEncPMS );
					}
					else if( pSessionData->pbCipher[0] == 0x00 &&
							pSessionData->pbCipher[1] == 0x13 )
					{
						dwRet = ERROR_NOT_SUPPORTED;
					}
					else
					{
						//
						// Will never reach this point but....
						//
						dwRet = ERROR_ENCRYPTION_FAILED;
					}

					if( dwRet == NO_ERROR )
					{
						if( ( dwRet = TLSComputeMS( pSessionData->hCSP,
													pSessionData->pbRandomClient,
													pSessionData->pbRandomServer,
													pSessionData->pbPMS,
													pSessionData->pUserData->pbMS ) ) == NO_ERROR )
						{
							if( ( dwRet = TLSMakeClientKeyExchangeMessage( pbEncPMS, cbEncPMS, &pbTLSMessage, &cbTLSMessage ) ) == NO_ERROR )
							{
								if( ( dwRet = TLSMakeHandshakeRecord( pSessionData->hCSP,
																		pSessionData->hWriteKey,
																		pSessionData->dwMacKey,
																		pSessionData->dwMacKeySize,
																		pSessionData->pbWriteMAC,
																		&( pSessionData->dwSeqNum ),
																		pbTLSMessage, 
																		cbTLSMessage, 
																		&pbRecord, 
																		&cbRecord, 
																		pSessionData->bCipherSpec ) ) == NO_ERROR )
								{
									if( ( dwRet = TLSAddMessage( pbRecord, 
																cbRecord, 
																cbRecord,
																pSendPacket, 
																cbSendPacket ) ) == NO_ERROR )
									{
										dwRet = TLSAddHandshakeMessage( &( pSessionData->dwHandshakeMsgCount ), 
																pSessionData->pbHandshakeMsg,
																pSessionData->cbHandshakeMsg,
																pbTLSMessage, 
																cbTLSMessage );
									}

									free( pbRecord );
									cbRecord = 0;
								}

								free( pbTLSMessage );
								cbTLSMessage = 0;
							}
						}

						free( pbEncPMS );
						cbEncPMS = 0;
					}
				}

				//
				// Add change cipher spec record
				//
				if( dwRet == NO_ERROR )
				{
					if( ( dwRet = TLSMakeChangeCipherSpecRecord( &pbRecord, &cbRecord ) ) == NO_ERROR )
					{
						dwRet = TLSAddMessage( pbRecord, 
												cbRecord, 
												cbRecord,
												pSendPacket, 
												cbSendPacket );

						free( pbRecord );
						cbRecord  = 0;
					}
				}

				//
				// Change the cipher_spec
				//
				pSessionData->bCipherSpec = TRUE;

				//
				// Add finished handshake record
				//
				if( dwRet == NO_ERROR )
				{
					if( ( dwRet = TLSDeriveKeys( pSessionData ) ) == NO_ERROR )
					{
						if( ( dwRet = TLSMakeFinishedMessage(	pSessionData->hCSP,
																pSessionData->dwHandshakeMsgCount,
																pSessionData->pbHandshakeMsg,
																pSessionData->cbHandshakeMsg,
																TLS_CLIENT_FINISHED_LABEL,
																sizeof( TLS_CLIENT_FINISHED_LABEL ) - 1,
																pSessionData->pUserData->pbMS,
																TLS_MS_SIZE,
																&pbTLSMessage, 
																&cbTLSMessage ) ) == NO_ERROR )
						{
							if( ( dwRet = TLSMakeHandshakeRecord( pSessionData->hCSP,
																pSessionData->hWriteKey,
																pSessionData->dwMacKey,
																pSessionData->dwMacKeySize,
																pSessionData->pbWriteMAC,
																&( pSessionData->dwSeqNum ),
																pbTLSMessage, 
																cbTLSMessage, 
																&pbRecord, 
																&cbRecord, 
																pSessionData->bCipherSpec ) ) == NO_ERROR )
							{
								if( ( dwRet = TLSAddMessage( pbRecord, 
															cbRecord, 
															cbRecord,
															pSendPacket, 
															cbSendPacket ) ) == NO_ERROR )
								{
									//
									// It is now safe add the client finished message needed to verify the 
									// server finished message
									//
									if( ( dwRet = TLSAddHandshakeMessage( &( pSessionData->dwHandshakeMsgCount ), 
																pSessionData->pbHandshakeMsg,
																pSessionData->cbHandshakeMsg,
																pbTLSMessage,
																cbTLSMessage ) ) == NO_ERROR )
									{
										//
										// We have sent our finished message!
										//
										pSessionData->bSentFinished = TRUE;

										pEapOutput->Action = EAPACTION_Send;

										pSessionData->AuthState = AUTH_STATE_Change_Cipher_Spec;
									}
								}

								free( pbRecord );
								cbRecord = 0;
							}

							free( pbTLSMessage );
							cbTLSMessage = 0;
						}
					}
				}
			}

		break;

		case AUTH_STATE_Resume_Session:

			if( ( dwRet = TLSInitTLSResponsePacket( pSessionData->bPacketId, pSendPacket, cbSendPacket ) ) == NO_ERROR )
			{
				//
				// Add change cipher spec record
				//
				if( dwRet == NO_ERROR )
				{
					if( ( dwRet = TLSMakeChangeCipherSpecRecord( &pbRecord, &cbRecord ) ) == NO_ERROR )
					{
						dwRet = TLSAddMessage( pbRecord, cbRecord, cbRecord, pSendPacket, cbSendPacket );

						free( pbRecord );
						cbRecord  = 0;
					}
				}

				//
				// Add finished handhshake record
				//
				if( dwRet == NO_ERROR )
				{
					if( ( dwRet = TLSMakeFinishedMessage( pSessionData->hCSP,
																pSessionData->dwHandshakeMsgCount,
																pSessionData->pbHandshakeMsg,
																pSessionData->cbHandshakeMsg,
																TLS_CLIENT_FINISHED_LABEL,
																sizeof( TLS_CLIENT_FINISHED_LABEL ) - 1,
																pSessionData->pUserData->pbMS,
																TLS_MS_SIZE,
																&pbTLSMessage, 
																&cbTLSMessage ) ) == NO_ERROR )
					{
						if( ( dwRet = TLSMakeHandshakeRecord( pSessionData->hCSP,
																pSessionData->hWriteKey,
																pSessionData->dwMacKey,
																pSessionData->dwMacKeySize,
																pSessionData->pbWriteMAC,
																&( pSessionData->dwSeqNum ),
																pbTLSMessage, 
																cbTLSMessage, 
																&pbRecord, 
																&cbRecord, 
																pSessionData->bCipherSpec ) ) == NO_ERROR )
						{
							if( ( dwRet = TLSAddMessage( pbRecord, 
														cbRecord, 
														cbRecord,
														pSendPacket, 
														cbSendPacket ) ) == NO_ERROR )
							{
								//
								// It is now safe add the client finished message needed to verify the 
								// server finished message
								//
								if( ( dwRet = TLSAddHandshakeMessage( &( pSessionData->dwHandshakeMsgCount ), 
																pSessionData->pbHandshakeMsg,
																pSessionData->cbHandshakeMsg,
																pbTLSMessage, 
																cbTLSMessage ) ) == NO_ERROR )
								{
									//
									// We have sent our finished message!
									//
									pSessionData->bSentFinished = TRUE;

									pEapOutput->Action = EAPACTION_Send;

									pSessionData->AuthState = AUTH_STATE_Resume_Session_Ack;
								}
							}

							free( pbRecord );
							cbRecord = 0;
						}

						free( pbTLSMessage );
						cbTLSMessage = 0;
					}
				}
			}
			
		break;

		case AUTH_STATE_Resume_Session_Ack:

			if( ( dwRet = TLSMakeFragResponse( pSessionData->bPacketId, 
												pSendPacket, 
												cbSendPacket ) ) == NO_ERROR )
			{
				pEapOutput->Action = EAPACTION_Send;

				pSessionData->AuthState = AUTH_STATE_Inner_Authentication;
			}

		break;

		case AUTH_STATE_Change_Cipher_Spec:
		case AUTH_STATE_Inner_Authentication:

			AA_TRACE( ( TEXT( "TLSBuildResponsePacket::AUTH_STATE_Inner_Authentication" ) ) );

			if( ( dwRet = TLSInitTLSResponsePacket( pSessionData->bPacketId, pSendPacket, cbSendPacket ) ) == NO_ERROR )
				dwRet = AuthHandleInnerAuthentication( pSessionData, pSendPacket, cbSendPacket, pEapInput, pEapOutput );

		break;

		default:

			dwRet = ERROR_PPP_INVALID_PACKET;

		break;
	}

	AA_TRACE( ( TEXT( "TLSBuildResponsePacket:: returning: %x" ), dwRet ) );

	return dwRet;
}