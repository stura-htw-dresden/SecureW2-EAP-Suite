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
// Name: CommonTLS.c
// Description: Contains the common TLS functionality
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
// Fixed Insecure Pre-Master Secret Generation Vulnerability by adding a better random generator (Microsoft Enhanced CSP) - 03 October 2005 - Tom Rixom
//

#include "Common.h"
#include <math.h>

//
// Name: TLSGenSessionID
// Description: Generate a new SSL Session ID
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSGenSessionID( IN OUT BYTE pbSessionID[TLS_SESSION_ID_SIZE],
				IN OUT DWORD *pcbSessionID,
				IN DWORD dwMaxSessionID )
{
	DWORD			dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSGenSessionID" ) ) );

	*pcbSessionID = dwMaxSessionID;

	if( ( dwRet = AA_GenSecureRandom( pbSessionID, TLS_RANDOM_SIZE ) ) == NO_ERROR )
	{
		AA_TRACE( ( TEXT( "TLSGenSessionID::random bytes: %s" ), AA_ByteToHex( pbSessionID, *pcbSessionID ) ) );
	}

	return dwRet;
}

//
// Name: TLSGenRandom
// Description: Generate the 32 random bytes for the client
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSGenRandom( IN OUT BYTE pbRandom[TLS_RANDOM_SIZE] )
{
	DWORD			dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSGenRandom" ) ) );

	if( ( dwRet = AA_GenSecureRandom( pbRandom, TLS_RANDOM_SIZE ) ) == NO_ERROR )
	{
		AA_TRACE( ( TEXT( "TLSGenRandom::random bytes: %s" ), AA_ByteToHex( pbRandom, TLS_RANDOM_SIZE ) ) );
	}

	return dwRet;
}

//
// Name: TLSGenPMS
// Description: Generate the 48 random bytes for the PMS (Pre Master Secret)
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSGenPMS( IN OUT BYTE pbPMS[TLS_PMS_SIZE] )
{
	DWORD			dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSGenPMS" ) ) );

	pbPMS[0] = 0x03;
	pbPMS[1] = 0x01;

	if( ( dwRet = AA_GenSecureRandom( &pbPMS[2], TLS_PMS_SIZE - 2 ) ) == NO_ERROR )
	{
		AA_TRACE( ( TEXT( "TLSGenPMS::random bytes: %s" ), AA_ByteToHex( pbPMS, TLS_PMS_SIZE ) ) );	
	}

	return dwRet;
}

//
// Name: TLSMakeFragResponse
// Description: This function builds the frag response message
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSMakeFragResponse( IN BYTE bPacketId, IN PPP_EAP_PACKET* pSendPacket, IN DWORD cbSendPacket )
{
	DWORD		dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSMakeFragResponse" ) ) );

	//
	// Build send packet
	//
	pSendPacket->Code = EAPCODE_Response;
	pSendPacket->Id = bPacketId;

	//
	// Length of total packet, EAP_PACKET header (5)
	//
	AA_HostToWireFormat16( 0x06, pSendPacket->Length );

	//
	// Which EAP are we using?
	//
	pSendPacket->Data[0] = EAP_PROTOCOL_ID;

#ifdef EAP_USE_PEAP
	pSendPacket->Data[1] = 1;
#else
	pSendPacket->Data[1] = 0;
#endif

	AA_TRACE( ( TEXT( "TLSMakeFragResponse returning" ) ) );

	return dwRet;
}

//
// Name: TLSReadMessage
// Description: This function reads in fragmented message and put the result in the pbFragmentedMessage
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSReadMessage(		IN	PBYTE				pbReceiveMsg,
					IN  DWORD *				pcbReceiveMsg,
					IN	DWORD *				pdwFragCursor,
					IN	BYTE				bPacketId,
					IN  PPP_EAP_PACKET*     pReceivePacket,
					OUT PPP_EAP_PACKET*     pSendPacket,
					IN  DWORD               cbSendPacket,
					IN  PPP_EAP_INPUT*      pEapInput,
					OUT PPP_EAP_OUTPUT*     pEapOutput,
					IN  DWORD				dwEAPPacketLength )
{
	DWORD	dwRet;

	AA_TRACE( ( TEXT( "TLSReadMessage" ) ) );

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSReadMessage::message length: %ld" ), dwEAPPacketLength ) );

	if( dwEAPPacketLength < 7 )
	{
		AA_TRACE( ( TEXT( "TLSReadMessage::header message" ) ) );

		memset( pbReceiveMsg, 0, sizeof( pbReceiveMsg ) );

		*pcbReceiveMsg = 0;
	}
	else if( pReceivePacket->Data[1] & TLS_REQUEST_MORE_FRAG )
	{
		AA_TRACE( ( TEXT( "TLSReadMessage::TLS_REQUEST_MORE_FRAG" ) ) );

		//
		// First look how big the complete message is
		// Then request other fragments
		//
		if( *pcbReceiveMsg == 0 )
		{
			//
			// First fragmented message
			//
			AA_TRACE( ( TEXT( "TLSReadMessage::first fragmented message" ) ) );

			if( pReceivePacket->Data[1] & TLS_REQUEST_LENGTH_INC )
			{
				//
				// Length of total fragmented EAP-TLS packet
				//
				*pcbReceiveMsg = AA_WireToHostFormat32( &( pReceivePacket->Data[2] ) );

				if( *pcbReceiveMsg <= TLS_MAX_MSG )
				{
					AA_TRACE( ( TEXT( "TLSReadMessage::length of total fragged message: %d" ), *pcbReceiveMsg ) );

					memset( pbReceiveMsg, 0, *pcbReceiveMsg );

					if( pReceivePacket->Data[1] & TLS_REQUEST_LENGTH_INC )
					{						
						//
						// Copy Fragmented data (length of message - EAP header(10) )
						//
						*pdwFragCursor = dwEAPPacketLength - 10;

						memcpy( pbReceiveMsg, &( pReceivePacket->Data[6] ), *pdwFragCursor ); 
					}
					else
					{
						*pdwFragCursor = dwEAPPacketLength - 6;

						memcpy( pbReceiveMsg, &( pReceivePacket->Data[2] ), *pdwFragCursor ); 
					}

					AA_TRACE( ( TEXT( "TLSReadMessage:: copyied %d bytes of fragented data" ), *pdwFragCursor ) );
					AA_TRACE( ( TEXT( "TLSReadMessage::total message: %s" ), AA_ByteToHex( pbReceiveMsg, *pcbReceiveMsg ) ) );
					AA_TRACE( ( TEXT( "TLSReadMessage::set cursor to %d" ), *pdwFragCursor ) );
				}
				else
				{
					AA_TRACE( ( TEXT( "TLSReadMessage::Not enough memory for pbReceiveMsg" ) ) );

					dwRet = ERROR_NOT_ENOUGH_MEMORY;

					pEapOutput->Action = EAPACTION_Done;

					pEapOutput->dwAuthResultCode = dwRet;
				}
			}
			else
			{
				AA_TRACE( ( TEXT( "TLSReadMessage::NOT TLS_REQUEST_MORE_FRAG::NOT IMPLEMENTED" ) ) );

				//
				// NOT IMPLEMENTED YET
				//
				//
				// Length is not include
				// don't now how to react yet
				// NOTE: should we continue?
				//
				dwRet = ERROR_PPP_INVALID_PACKET;

				pEapOutput->Action = EAPACTION_Done;

				pEapOutput->dwAuthResultCode = dwRet;
			}
		}
		else
		{
			AA_TRACE( ( TEXT( "TLSReadMessage::Nth fragmented message" ) ) );

			//
			// Nth fragmented message
			//

			//
			// Just copy memory from previous frag cursor till length of message
			//

			if( pReceivePacket->Data[1] & TLS_REQUEST_LENGTH_INC )
			{
				AA_TRACE( ( TEXT( "TLSReadMessage:: copying %d bytes of fragmented data, starting at: %d" ), dwEAPPacketLength - 10, *pdwFragCursor ) );
				AA_TRACE( ( TEXT( "TLSReadMessage:: fragged message: %s" ), AA_ByteToHex( &( pReceivePacket->Data[6] ), dwEAPPacketLength - 10 ) ) );

				//
				// If length is included then copy from 6th byte and onwards
				//
				memcpy( &( pbReceiveMsg[*pdwFragCursor] ), &( pReceivePacket->Data[6] ), dwEAPPacketLength - 10 ); 
				*pdwFragCursor = *pdwFragCursor + dwEAPPacketLength - 10;
			}
			else
			{
				AA_TRACE( ( TEXT( "TLSReadMessage:: copying %d bytes of fragmented data, starting at: %d" ), dwEAPPacketLength - 6, *pdwFragCursor ) );
				AA_TRACE( ( TEXT( "TLSReadMessage:: fragged message: %s" ), AA_ByteToHex( &( pReceivePacket->Data[2] ), dwEAPPacketLength - 6 ) ) );

				//
				// If length is not included then copy from 2nd byte and onwards
				//
				memcpy( &( pbReceiveMsg[*pdwFragCursor] ), &( pReceivePacket->Data[2] ), dwEAPPacketLength - 6 ); 
				*pdwFragCursor = *pdwFragCursor + dwEAPPacketLength - 6;
			}

			AA_TRACE( ( TEXT( "TLSReadMessage::total message: %s" ), AA_ByteToHex( pbReceiveMsg, *pcbReceiveMsg ) ) );
		}

		if( dwRet == NO_ERROR )
		{
			//
			//
			// When an EAP-TLS peer receives an EAP-Request packet with the M bit
			// set (MORE_FRAGMENTS), it MUST respond with an EAP-Response with EAP-Type=EAPTYPE and
			// no data
			//
			if( ( dwRet = TLSMakeFragResponse( bPacketId, pSendPacket, cbSendPacket ) ) == NO_ERROR )
			{
				AA_TRACE( ( TEXT( "TLSReadMessage::TLSMakeFragResponse:pSendPacket(%d): %s" ), cbSendPacket, AA_ByteToHex( ( PBYTE ) pSendPacket, cbSendPacket ) ) );

				pEapOutput->Action = EAPACTION_Send;
			}
			else
			{
				pEapOutput->Action = EAPACTION_Done;

				pEapOutput->dwAuthResultCode = ERROR_AUTH_INTERNAL;
			}
		}
	}
	else
	{
		if( *pcbReceiveMsg != 0 )
		{
			AA_TRACE( ( TEXT( "TLSReadMessage::Last fragmented message" ) ) );
			AA_TRACE( ( TEXT( "TLSReadMessage::complete EAP_PACKET: %s" ), AA_ByteToHex( ( PBYTE ) pReceivePacket, dwEAPPacketLength ) ) );
			AA_TRACE( ( TEXT( "TLSReadMessage::copying last fragment to cursor: %d" ), *pdwFragCursor ) );

			if( pReceivePacket->Data[1] & TLS_REQUEST_LENGTH_INC )
			{
				//
				// If length is included then copy from 6th byte and onwards
				//
				memcpy( &( pbReceiveMsg[*pdwFragCursor] ), &( pReceivePacket->Data[6] ), dwEAPPacketLength - 10 ); 
			}
			else
			{
				//
				// If length is included then copy from 6th byte and onwards
				//
				if( pReceivePacket->Data[1] & TLS_REQUEST_LENGTH_INC )
				{
					//
					// If length is included then copy from 6th byte and onwards
					//
					memcpy( &( pbReceiveMsg[*pdwFragCursor] ), &( pReceivePacket->Data[6] ), dwEAPPacketLength - 10 ); 
				}
				else
				{
					//
					// If length is not included then copy from 2nd byte and onwards
					//
					memcpy( &( pbReceiveMsg[*pdwFragCursor] ), &( pReceivePacket->Data[2] ), dwEAPPacketLength - 6 ); 
				}
			}
		}
		else
		{
			//
			// Normal unfragmented message
			//
			//
			// Length of total fragmented EAP-TLS packet
			//

			if( pReceivePacket->Data[1] & TLS_REQUEST_LENGTH_INC )
			{
				*pcbReceiveMsg = AA_WireToHostFormat32( &( pReceivePacket->Data[2] ) );	
			}
			else
			{
				*pcbReceiveMsg = dwEAPPacketLength - 6;	
			}

			AA_TRACE( ( TEXT( "TLSReadMessage::length of total unfragged message: %d" ), *pcbReceiveMsg ) );

			if( *pcbReceiveMsg <= TLS_MAX_MSG )
			{
				//
				// If length is included then copy from 6th byte and onwards
				//
				if( pReceivePacket->Data[1] & TLS_REQUEST_LENGTH_INC )
				{
					//
					// If length is included then copy from 6th byte and onwards
					//
					memcpy( &( pbReceiveMsg[*pdwFragCursor] ), &( pReceivePacket->Data[6] ), dwEAPPacketLength - 10 ); 
				}
				else
				{
					//
					// If length is not included then copy from 2nd byte and onwards
					//
					memcpy( &( pbReceiveMsg[*pdwFragCursor] ), &( pReceivePacket->Data[2] ), dwEAPPacketLength - 6 ); 
				}
			}
			else
			{
				AA_TRACE( ( TEXT( "TLSReadMessage::Not enough memory for pbReceiveMsg" ) ) );

				dwRet = ERROR_NOT_ENOUGH_MEMORY;

				pEapOutput->Action = EAPACTION_Done;

				pEapOutput->dwAuthResultCode = dwRet;
			}
		}
	}

	AA_TRACE( ( TEXT( "TLSReadMessage::returning: %d" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSSendMessage
// Description: Create the SendPacket
//				This function will fragment the actual EAP packet into segments
//				if the packet is to large
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
TLSSendMessage(	IN PBYTE				pbSendMsg,	
				IN DWORD				cbSendMsg,
				IN OUT	DWORD			*pdwSendCursor,
				IN BYTE					bPacketId,
				IN PPP_EAP_PACKET*		pSendPacket, 
				IN DWORD				cbSendPacket,
				IN PPP_EAP_INPUT*		pEapInput,
				OUT PPP_EAP_OUTPUT*     pEapOutput )
{
	DWORD	dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSSendMessage" ) ) );

	//
	// First let see if we need to fragment the message
	//
	if( cbSendMsg > TLS_MAX_FRAG_SIZE )
	{
		AA_TRACE( ( TEXT( "TLSSendMessage::pbSendMsg( %d ): %s" ), cbSendMsg, AA_ByteToHex( pbSendMsg, cbSendMsg ) ) );

		if( *pdwSendCursor == 0 )
		{
			AA_TRACE( ( TEXT( "TLSSendMessage::First Message" ) ) );

			pSendPacket->Data[1] |= TLS_REQUEST_LENGTH_INC | TLS_REQUEST_MORE_FRAG;

			//
			// Add message
			//
			if( ( dwRet = TLSAddMessage( &( pbSendMsg[0] ),
										TLS_MAX_FRAG_SIZE, // EAP Packet size
										cbSendMsg, // Total EAP Message
										pSendPacket,
										cbSendPacket ) ) == NO_ERROR )
			{
				*pdwSendCursor = TLS_MAX_FRAG_SIZE;

				pEapOutput->Action = EAPACTION_Send;
			}
		}
		else
		{
			if( ( *pdwSendCursor + TLS_MAX_FRAG_SIZE ) > cbSendMsg )
			{
				AA_TRACE( ( TEXT( "TLSSendMessage::Last Message" ) ) );

				//
				// Add message
				//
				if( ( dwRet = TLSAddMessage( &( pbSendMsg[*pdwSendCursor] ),
											cbSendMsg - *pdwSendCursor, // EAP Packet size
											cbSendMsg, // Total EAP Message
											pSendPacket,
											cbSendPacket ) ) == NO_ERROR )
				{
					*pdwSendCursor += TLS_MAX_FRAG_SIZE;

					pEapOutput->Action = EAPACTION_Send;
				}
			}
			else
			{
				AA_TRACE( ( TEXT( "TLSSendMessage::Nth Message" ) ) );

				//
				// Nth message
				//
				pSendPacket->Data[1] |= TLS_REQUEST_MORE_FRAG;

				//
				// Add message
				//
				if( ( dwRet = TLSAddMessage( &( pbSendMsg[*pdwSendCursor] ),
											TLS_MAX_FRAG_SIZE, // EAP Packet size
											cbSendMsg, // Total EAP Message
											pSendPacket,
											cbSendPacket ) ) == NO_ERROR )
				{
					*pdwSendCursor += TLS_MAX_FRAG_SIZE;

					pEapOutput->Action = EAPACTION_Send;
				}
			}
		}
	}
	else if( cbSendMsg == 0 )
	{
		if( ( dwRet = TLSAddMessage( pbSendMsg,
									cbSendMsg,
									cbSendMsg,
									pSendPacket, 
									cbSendPacket ) ) == NO_ERROR )
		{
			pEapOutput->Action = EAPACTION_Send;

			AA_TRACE( ( TEXT( "TLSSendMessage::pbSendMsg( %d ): %s" ), cbSendMsg, AA_ByteToHex( pbSendMsg, cbSendMsg ) ) );
		}
	}
	else
	{
		pSendPacket->Data[1] |= TLS_REQUEST_LENGTH_INC;

		if( ( dwRet = TLSAddMessage( pbSendMsg,
									cbSendMsg,
									cbSendMsg,
									pSendPacket, 
									cbSendPacket ) ) == NO_ERROR )
		{
			pEapOutput->Action = EAPACTION_Send;

			AA_TRACE( ( TEXT( "TLSSendMessage::pbSendMsg( %d ): %s" ), cbSendMsg, AA_ByteToHex( pbSendMsg, cbSendMsg ) ) );
		}
	}

	AA_TRACE( ( TEXT( "TLSSendMessage::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSAddHandshakeMessage
// Description: This function adds a message to the handshake buffer used for the finished message
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSAddHandshakeMessage(	IN OUT DWORD *pdwHandshakeMsgCount,
						IN OUT PBYTE pbHandshakeMsg[TLS_MAX_HS],
						IN OUT DWORD cbHandshakeMsg[TLS_MAX_HS],
						IN PBYTE pbMessage, 
						IN DWORD cbMessage )
{
	DWORD	dwRet;

	AA_TRACE( ( TEXT( "TLSAddHandshakeMessage::slot( %d ):msg( %d ): %s" ), *pdwHandshakeMsgCount, cbMessage, AA_ByteToHex( pbMessage, cbMessage ) ) );
	
	dwRet = NO_ERROR;

	cbHandshakeMsg[*pdwHandshakeMsgCount] = cbMessage;
	
	if( ( pbHandshakeMsg[*pdwHandshakeMsgCount] = ( PBYTE ) malloc( cbHandshakeMsg[*pdwHandshakeMsgCount] ) ) )
	{
		memcpy( pbHandshakeMsg[*pdwHandshakeMsgCount], pbMessage, cbHandshakeMsg[*pdwHandshakeMsgCount] );

		( *pdwHandshakeMsgCount )++;
	}
	else
	{
		AA_TRACE( ( TEXT( "TLSAddHandshakeMessage::ERROR:Not enough memory for pbHandshakeMsg[%ld]" ), *pdwHandshakeMsgCount ) );

		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	AA_TRACE( ( TEXT( "TLSAddHandshakeMessage::returning %x" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSInitTLSResponsePacket
// Description: Initialises the send message for a TLS response packet
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSInitTLSResponsePacket(	IN BYTE				bPacketId,
							IN PPP_EAP_PACKET*	pSendPacket,
						    IN DWORD			cbSendPacket )
{
	DWORD		dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSInitTTLSResponsePacket: packet id: %ld" ), bPacketId ) );

	memset( pSendPacket, 0, cbSendPacket );

	//
	// Build send packet
	//
	pSendPacket->Code = EAPCODE_Response;
	pSendPacket->Id = bPacketId;

	//
	// Length of total packet
	//
	AA_HostToWireFormat16( ( WORD ) 0x06, pSendPacket->Length );

	//
	// Which protocol are we using?
	//
	pSendPacket->Data[0] = EAP_PROTOCOL_ID;

	//
	// Length is included in EAP-TTLS packet
	//
	pSendPacket->Data[1] = TLS_REQUEST_LENGTH_INC;

	AA_TRACE( ( TEXT( "TLSInitTTLSResponsePacket::pSendPacket(%d): %s" ), cbSendPacket, AA_ByteToHex( ( PBYTE ) pSendPacket, cbSendPacket ) ) );

	return dwRet;
}

//
// Name: TLSInitTLSRequestPacket
// Description: Initialises the send message for a TLS request packet
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSInitTLSRequestPacket(	IN BYTE				bPacketId,
							IN PPP_EAP_PACKET*	pSendPacket,
						    IN DWORD			cbSendPacket )
{
	DWORD		dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSInitTLSRequestPacket: packet id: %ld" ), bPacketId ) );

	memset( pSendPacket, 0, cbSendPacket );

	//
	// Build send packet
	//
	pSendPacket->Code = EAPCODE_Request;
	pSendPacket->Id = bPacketId + 1;

	//
	// Length of total packet
	//
	AA_HostToWireFormat16( ( WORD ) 0x06, pSendPacket->Length );

	//
	// Which protocol are we using?
	//
	pSendPacket->Data[0] = EAP_PROTOCOL_ID;

	AA_TRACE( ( TEXT( "TLSInitTLSRequestPacket::pSendPacket(%d): %s" ), cbSendPacket, AA_ByteToHex( ( PBYTE ) pSendPacket, cbSendPacket ) ) );

	AA_TRACE( ( TEXT( "TLSInitTLSRequestPacket returning" ) ) );

	return dwRet;
}

//
// Name: TLSInitTLSAcceptPacket
// Description: Initialises the accept message for a TLS request packet
// Author: Tom Rixom
// Created: 21 August 2004
//
DWORD
TLSInitTLSAcceptPacket(	IN BYTE				bPacketId,
						IN PPP_EAP_PACKET*	pSendPacket,
						IN DWORD			cbSendPacket )
{
	DWORD		dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSInitTLSAcceptPacket: packet id: %ld" ), bPacketId ) );

	memset( pSendPacket, 0, cbSendPacket );

	//
	// Build send packet
	//
	pSendPacket->Code = EAPCODE_Success;
	pSendPacket->Id = bPacketId + 1;

	//
	// Length of total packet
	//
	AA_HostToWireFormat16( ( WORD ) 0x06, pSendPacket->Length );

	//
	// Which protocol are we using?
	//
	pSendPacket->Data[0] = EAP_PROTOCOL_ID;

	AA_TRACE( ( TEXT( "TLSInitTLSAcceptPacket::pSendPacket(%d): %s" ), cbSendPacket, AA_ByteToHex( ( PBYTE ) pSendPacket, cbSendPacket ) ) );

	AA_TRACE( ( TEXT( "TLSInitTLSAcceptPacket returning" ) ) );

	return dwRet;
}

//
// Name: TLSInitTLSAcceptPacket
// Description: Initialises the reject message for a TLS request packet
// Author: Tom Rixom
// Created: 21 August 2004
//
DWORD
TLSInitTLSRejectPacket(	IN BYTE				bPacketId,
						IN PPP_EAP_PACKET*	pSendPacket,
						IN DWORD			cbSendPacket )
{
	DWORD		dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSInitTLSRejectPacket: packet id: %ld" ), bPacketId ) );

	memset( pSendPacket, 0, cbSendPacket );

	//
	// Build send packet
	//
	pSendPacket->Code = EAPCODE_Failure;
	pSendPacket->Id = bPacketId + 1;

	//
	// Length of total packet
	//
	AA_HostToWireFormat16( ( WORD ) 0x06, pSendPacket->Length );

	//
	// Which protocol are we using?
	//
	pSendPacket->Data[0] = EAP_PROTOCOL_ID;

	AA_TRACE( ( TEXT( "TLSInitTLSRejectPacket::pSendPacket(%d): %s" ), cbSendPacket, AA_ByteToHex( ( PBYTE ) pSendPacket, cbSendPacket ) ) );

	AA_TRACE( ( TEXT( "TLSInitTLSRejectPacket returning" ) ) );

	return dwRet;
}

//
// Name: TLSAddRecord
// Description: Adds a record to the send message
// Author: Tom Rixom
// Created: 13 August 2003
//
DWORD
TLSAddRecord(	IN	PBYTE	pbRecord,
				IN  DWORD	cbRecord,
				IN	PBYTE	pbMessage,
				IN	DWORD	*pcbMessage )
{
	DWORD	dwRet;

	dwRet = NO_ERROR;

	//
	// First check if we have room
	//
	if( ( cbRecord + *pcbMessage ) <= TLS_MAX_MSG )
	{
		//
		// Copy message
		//
		memcpy( &( pbMessage[*pcbMessage] ), pbRecord, cbRecord );

		*pcbMessage += cbRecord;
	}
	else
		dwRet = ERROR_NOT_ENOUGH_MEMORY;

	return dwRet;
}

//
// Name: TLSAddMessage
// Description: Adds a message to the send packet
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSAddMessage(	IN PBYTE			pbMessage,
				IN DWORD			cbMessage,
				IN DWORD			cbTotalMessage,
				IN PPP_EAP_PACKET*	pSendPacket,
				IN DWORD			cbSendPacket )
{
	DWORD		wPacketLength = AA_WireToHostFormat16( &pSendPacket->Length[0] );
	DWORD		wRecordLength = AA_WireToHostFormat32( &pSendPacket->Data[2] );
	DWORD		dwCursor;
	DWORD		dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSAddMessage" ) ) );
	AA_TRACE( ( TEXT( "TLSAddMessage::current wPacketLength: %d" ), wPacketLength ) );
	AA_TRACE( ( TEXT( "TLSAddMessage::current wRecordLength: %d" ), wRecordLength ) );
	AA_TRACE( ( TEXT( "TLSAddMessage::current cbMessage: %d" ), cbMessage ) );
	AA_TRACE( ( TEXT( "TLSAddMessage::current cbTotalMessage: %d" ), cbTotalMessage ) );

	if( ( wPacketLength + cbMessage ) > cbSendPacket )
	{
		AA_TRACE( ( TEXT( "TLSAddMessage::packet (%d) too big for buffer" ), ( wPacketLength + cbMessage ) ) );

		return ERROR_NOT_ENOUGH_MEMORY;
	}

	if( pSendPacket->Data[1] & TLS_REQUEST_LENGTH_INC )
	{
		//
		// Update length of total packet
		//
		AA_TRACE( ( TEXT( "TLSAddMessage::TLS_REQUEST_LENGTH_INC" ) ) );

		if( wRecordLength == 0 )
		{
			//
			// If this is the first packet we are adding we need to also
			// add the extra length
			//
			AA_TRACE( ( TEXT( "TLSAddMessage::adding first packet" ) ) );

			AA_HostToWireFormat16( ( DWORD ) ( wPacketLength + 0x04 + cbMessage ), pSendPacket->Length );

			dwCursor = wPacketLength;
		}
		else
		{
			AA_TRACE( ( TEXT( "TLSAddMessage::adding next packet" ) ) );

			AA_HostToWireFormat16( ( DWORD ) ( wPacketLength + cbMessage ), pSendPacket->Length );

			dwCursor = wPacketLength - 0x04;
		}

		AA_TRACE( ( TEXT( "TLSAddMessage::updated wPacketLength: %d" ), AA_WireToHostFormat16( &pSendPacket->Length[0] ) ) );

		//
		// Update length of EAP-TLS packet
		//
		AA_HostToWireFormat32( ( DWORD ) ( wRecordLength + cbTotalMessage ), &( pSendPacket->Data[2] ) );

		AA_TRACE( ( TEXT( "TLSAddMessage::TLS message length: %ld" ), AA_WireToHostFormat32( &pSendPacket->Data[2] ) ) );
	}
	else
	{
		AA_HostToWireFormat16( ( DWORD ) ( wPacketLength + cbMessage ), pSendPacket->Length );

		AA_TRACE( ( TEXT( "TLSAddMessage::updated wPacketLength: %d" ), AA_WireToHostFormat16( &pSendPacket->Length[0] ) ) );

		dwCursor = wPacketLength - 0x04;
	}

	memcpy( &( pSendPacket->Data[dwCursor] ), pbMessage, cbMessage );

	AA_TRACE( ( TEXT( "TLSAddMessage::pSendPacket(%d): %s" ), cbSendPacket, AA_ByteToHex( ( PBYTE ) pSendPacket, cbSendPacket ) ) );

	AA_TRACE( ( TEXT( "TLSAddMessage::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSMakeApplicationRecord
// Description: build a application record
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSMakeApplicationRecord(	IN HCRYPTPROV	hCSP,
							IN HCRYPTKEY	hWriteKey,
							IN DWORD		dwMacKey,
							IN DWORD		dwMacKeySize,
							IN PBYTE		pbWriteMAC,
							IN DWORD		*pdwSeqNum,
							IN PBYTE		pbMessage,
							IN DWORD		cbMessage,
							IN PBYTE		*ppbRecord,
							IN DWORD		*pcbRecord,
							IN BOOL			bEncrypt )
{
	PBYTE		pbTLSMessage;
	DWORD		cbTLSMessage;
	PBYTE		pbTempRecord;
	DWORD		cbTempRecord;
	PBYTE		pbRecord;
	DWORD		cbRecord;
	DWORD		dwCursor = 0;
	DWORD		dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSMakeApplicationRecord" ) ) );

	//
	// Do we need to encrypt the application record?
	//
	if( bEncrypt )
	{
		//
		// First build a application record (no encryption)
		//
		if( ( dwRet = TLSMakeApplicationRecord( hCSP,
												hWriteKey,
												dwMacKey,
												dwMacKeySize,
												pbWriteMAC,
												pdwSeqNum,
												pbMessage, 
												cbMessage, 
												&pbTempRecord, 
												&cbTempRecord, 
												FALSE ) ) == NO_ERROR )
		{
			//
			// Encrypt this record which will be add to the final handshake record
			//
			dwRet = TLSEncBlock( hCSP,
								hWriteKey,
								dwMacKeySize,
								dwMacKey,
								pbWriteMAC,
								pdwSeqNum,
								pbTempRecord, 
								cbTempRecord, 
								&pbTLSMessage, 
								&cbTLSMessage );

			free( pbTempRecord );
			cbTempRecord = 0;

			if( dwRet != NO_ERROR )
			{
				free( pbTLSMessage );
				pbTLSMessage = 0;
			}
		}
	}
	else
	{
		pbTLSMessage = pbMessage;
		cbTLSMessage = cbMessage;
	}

	if( dwRet != NO_ERROR )
		return dwRet;

	*pcbRecord = 0x05+cbTLSMessage;

	if( ( *ppbRecord = ( PBYTE ) malloc( *pcbRecord ) ) )
	{
		pbRecord = *ppbRecord;
		cbRecord = *pcbRecord;

		//
		// ssl record header
		//
		pbRecord[dwCursor++] = 0x17;			// ssl record type is application = 23
		pbRecord[dwCursor++] = 0x03;			// ssl major version number
		pbRecord[dwCursor++] = 0x01;			// ssl minor version number

		AA_HostToWireFormat16( cbTLSMessage, &( pbRecord[dwCursor] ) );

		dwCursor+=2;

		memcpy( &( pbRecord[dwCursor] ), pbTLSMessage, cbTLSMessage );

		dwCursor += cbTLSMessage;

		AA_TRACE( ( TEXT( "TLSMakeApplicationRecord::pbRecord(%d): %s" ), cbRecord, AA_ByteToHex( ( PBYTE ) pbRecord, cbRecord  ) ) );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

//
// Name: TLSMakeHandshakeRecord
// Description: build a handshake record
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSMakeHandshakeRecord( IN HCRYPTPROV	hCSP,
						IN HCRYPTKEY	hWriteKey,
						IN DWORD		dwMacKey,
						IN DWORD		dwMacKeySize,
						IN PBYTE		pbWriteMAC,
						IN DWORD		*pdwSeqNum,
						IN PBYTE		pbMessage,
						IN DWORD		cbMessage,
						IN PBYTE		*ppbRecord,
						IN DWORD		*pcbRecord,
						IN BOOL			bEncrypt )
{
	PBYTE		pbTLSMessage;
	DWORD		cbTLSMessage;
	PBYTE		pbRecord;
	DWORD		cbRecord;
	PBYTE		pbTempRecord;
	DWORD		cbTempRecord;
	DWORD		dwCursor = 0;
	DWORD		dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSMakeHandshakeRecord, %d" ), bEncrypt ) );

	//
	// Do we need to encrypt the handshake record?
	//
	if( bEncrypt )
	{
		//
		// First build a handshake record (no encryption)
		//
		if( ( dwRet = TLSMakeHandshakeRecord( hCSP,
												hWriteKey,
												dwMacKeySize,
												dwMacKey,
												pbWriteMAC,
												pdwSeqNum,
												pbMessage, 
												cbMessage, 
												&pbTempRecord, 
												&cbTempRecord, 
												FALSE ) ) == NO_ERROR )
		{
			//
			// Encrypt this record which will be add to the final handshake record
			//
			dwRet = TLSEncBlock( hCSP,
									hWriteKey,
									dwMacKeySize,
									dwMacKey,
									pbWriteMAC,
									pdwSeqNum,
									pbTempRecord, 
									cbTempRecord, 
									&pbTLSMessage, 
									&cbTLSMessage );

			free( pbTempRecord );
			cbTempRecord = 0;

			if( dwRet != NO_ERROR )
			{
				free( pbTLSMessage );
				pbTLSMessage = 0;
			}
		}
	}
	else
	{
		pbTLSMessage = pbMessage;
		cbTLSMessage = cbMessage;
	}

	if( dwRet != NO_ERROR )
		return dwRet;

	AA_TRACE( ( TEXT( "TLSMakeHandshakeRecord, allocating %ld data for *pcbRecord" ), cbTLSMessage ) );

	*pcbRecord = 0x05+cbTLSMessage;

	if( ( *ppbRecord = ( PBYTE ) malloc( *pcbRecord ) ) )
	{
		pbRecord = *ppbRecord;
		cbRecord = *pcbRecord;

		//
		// ssl record header
		//
		pbRecord[dwCursor++] = 0x16;			// ssl record type is handshake = 22
		pbRecord[dwCursor++] = 0x03;			// ssl major version number
		pbRecord[dwCursor++] = 0x01;			// ssl minor version number

		AA_HostToWireFormat16( cbTLSMessage, &( pbRecord[dwCursor] ) );

		dwCursor+=2;

		memcpy( &( pbRecord[dwCursor] ), pbTLSMessage, cbTLSMessage );

		dwCursor += cbTLSMessage;

		AA_TRACE( ( TEXT( "TLSMakeHandshakeRecord::pbRecord(%d): %s" ), cbRecord, AA_ByteToHex( ( PBYTE ) pbRecord, cbRecord  ) ) );

		//
		// If we used encryption then we must free the allocated TLSMessage
		//
		if( bEncrypt )
		{
			free( pbTLSMessage );
			cbTLSMessage = 0;
		}
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

//
// Name: TLSMakeClientHelloMessage
// Description: This function will build the TLS ClientHello record
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSMakeClientHelloMessage(	IN BYTE				pbRandomClient[TLS_RANDOM_SIZE],
							IN PBYTE			pbTLSSessionID,
							IN DWORD			cbTLSSessionID,
							OUT PBYTE			*ppbTLSMessage,
							OUT DWORD			*pcbTLSMessage,
							OUT DWORD			*pdwEncKey,
							OUT DWORD			*pdwEncKeySize,
							OUT DWORD			*pdwMacKey,
							OUT DWORD			*pdwMacKeySize )
{
	PBYTE		pbTLSMessage;
	DWORD		cbTLSMessage;
	DWORD		dwCursor = 0;
	DWORD		dwRet;

	AA_TRACE( ( TEXT( "TLSMakeClientHelloMessage" ) ) );

	dwRet = NO_ERROR;

	*pcbTLSMessage = 0x0D+TLS_RANDOM_SIZE+cbTLSSessionID;

	if( ( *ppbTLSMessage = ( PBYTE ) malloc( *pcbTLSMessage ) ) )
	{
		pbTLSMessage = *ppbTLSMessage;
		cbTLSMessage = *pcbTLSMessage;

		memset( pbTLSMessage, 0, cbTLSMessage );

		//
		// ssl handshake header
		//
		pbTLSMessage[dwCursor++] = 0x01;   // message type is client_hello = 1

		// length of fragment is length of total message ( cbTLSMessage ) - header( 4 )
		AA_HostToWireFormat24( ( DWORD ) ( cbTLSMessage  - 4 ), &( pbTLSMessage[dwCursor] ) );

		dwCursor+=3;

		//
		// Version 3.1 ( WORD )
		// 00000011 00000001
		// 
		pbTLSMessage[dwCursor++] = 0x03;

		pbTLSMessage[dwCursor++] = 0x01;

		if( ( dwRet = TLSGenRandom( pbRandomClient ) ) == NO_ERROR )
		{
			//
			// Random
			//
			memcpy( &( pbTLSMessage[dwCursor] ), pbRandomClient, TLS_RANDOM_SIZE );

			dwCursor += TLS_RANDOM_SIZE;

			//
			// Session ID size
			//
			pbTLSMessage[dwCursor++] = ( BYTE ) cbTLSSessionID;

			//
			// SessionID
			//			
			memcpy( &( pbTLSMessage[dwCursor] ), pbTLSSessionID, cbTLSSessionID );

			dwCursor+=cbTLSSessionID;

			//
			// Length of cypher_suite:
			//
			AA_HostToWireFormat16( ( DWORD ) ( 0x02 ), &( pbTLSMessage[dwCursor] ) );

			dwCursor+=2;

			//
			// TLS_RSA_WITH_3DES_EDE_CBC_SHA { 0x00, 0x0A }
			// TLS_RSA_WITH_RC4_128_MD5      { 0x00,0x04 }
			// TLS_RSA_WITH_RC4_128_SHA1     { 0x00,0x05 }
			//
			*pdwEncKey = CALG_3DES;
			*pdwEncKeySize = 24;

			*pdwMacKey = CALG_SHA1;
			*pdwMacKeySize = 20;

			pbTLSMessage[dwCursor++] = 0x00;
			pbTLSMessage[dwCursor++] = 0x0A;
	 
			//
			// Compression
			//
			pbTLSMessage[dwCursor++] = 0x01;   // length of compression section
			pbTLSMessage[dwCursor++] = 0x00;	// no compression

			AA_TRACE( ( TEXT( "TLSMakeClientHelloMessage::pbTLSMessage(%d): %s" ), cbTLSMessage,  AA_ByteToHex( ( PBYTE ) pbTLSMessage, cbTLSMessage ) ) );
		}
		else
		{
			free( *ppbTLSMessage );
			*pcbTLSMessage = 0;
		}
	}
	else
	{
		AA_TRACE( ( TEXT( "TLSMakeClientHelloMessage::could not allocate memory for pbTLSMessage" ) ) );

		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	AA_TRACE( ( TEXT( "TLSMakeClientHelloMessage::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSMakeServerHelloMessage
// Description: This function will build the TLS ServerHello record
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
TLSMakeServerHelloMessage(	IN BYTE				pbRandomServer[TLS_RANDOM_SIZE],
							IN PBYTE			pbTLSSessionID,
							IN DWORD			cbTLSSessionID,
							OUT PBYTE			*ppbTLSMessage,
							OUT DWORD			*pcbTLSMessage,
							OUT DWORD			*pdwEncKey,
							OUT DWORD			*pdwEncKeySize,
							OUT DWORD			*pdwMacKey,
							OUT DWORD			*pdwMacKeySize )
{
	PBYTE		pbTLSMessage;
	DWORD		cbTLSMessage;
	DWORD		dwCursor = 0;
	DWORD		dwRet;

	AA_TRACE( ( TEXT( "TLSMakeServerHelloMessage" ) ) );

	dwRet = NO_ERROR;

	*pcbTLSMessage = 0x0A+TLS_RANDOM_SIZE+cbTLSSessionID;

	if( ( *ppbTLSMessage = ( PBYTE ) malloc( *pcbTLSMessage ) ) )
	{
		pbTLSMessage = *ppbTLSMessage;
		cbTLSMessage = *pcbTLSMessage;

		memset( pbTLSMessage, 0, cbTLSMessage );

		//
		// ssl handshake header
		//
		pbTLSMessage[dwCursor++] = 0x02;   // message type is server_hello = 2

		// length of fragment is length of total message ( cbTLSMessage ) - header( 4 )
		AA_HostToWireFormat24( ( DWORD ) ( cbTLSMessage  - 4 ), &( pbTLSMessage[dwCursor] ) );

		dwCursor+=3;

		//
		// Version 3.1 ( WORD )
		// 00000011 00000001
		// 
		pbTLSMessage[dwCursor++] = 0x03;

		pbTLSMessage[dwCursor++] = 0x01;

		if( ( dwRet = TLSGenRandom( pbRandomServer ) ) == NO_ERROR )
		{
			//
			// Random
			//
			memcpy( &( pbTLSMessage[dwCursor] ), pbRandomServer, TLS_RANDOM_SIZE );

			dwCursor += TLS_RANDOM_SIZE;

			//
			// Session ID size
			//
			pbTLSMessage[dwCursor++] = ( BYTE ) cbTLSSessionID;

			//
			// SessionID
			//			
			memcpy( &( pbTLSMessage[dwCursor] ), pbTLSSessionID, cbTLSSessionID );

			dwCursor+=cbTLSSessionID;

			//
			// TLS_RSA_WITH_3DES_EDE_CBC_SHA { 0x00, 0x0A }
			// TLS_RSA_WITH_RC4_128_MD5      { 0x00,0x04 }
			// TLS_RSA_WITH_RC4_128_SHA1     { 0x00,0x05 }
			//
			*pdwEncKey = CALG_3DES;
			*pdwEncKeySize = 24;

			*pdwMacKey = CALG_SHA1;
			*pdwMacKeySize = 20;

			pbTLSMessage[dwCursor++] = 0x00;
			pbTLSMessage[dwCursor++] = 0x0A;
	 
			//
			// Compression
			//
			pbTLSMessage[dwCursor++] = 0x00;	// no compression

			AA_TRACE( ( TEXT( "TLSMakeServerHelloMessage::pbTLSMessage(%d): %s" ), cbTLSMessage,  AA_ByteToHex( ( PBYTE ) pbTLSMessage, cbTLSMessage ) ) );
		}
		else
		{
			free( *ppbTLSMessage );
			*pcbTLSMessage = 0;
		}
	}
	else
	{
		AA_TRACE( ( TEXT( "TLSMakeServerHelloMessage::could not allocate memory for pbTLSMessage" ) ) );

		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	AA_TRACE( ( TEXT( "TLSMakeServerHelloMessage::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSMakeCertificateRequestMessage
// Description: This function will build Certificate Request
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
TLSMakeCertificateRequestMessage(	IN PBYTE	*ppbTLSMessage,
									IN DWORD	*pcbTLSMessage )
{
	PBYTE		pbTLSMessage;
	DWORD		cbTLSMessage;
	DWORD		dwCursor = 0;
	DWORD		dwRet;

	AA_TRACE( ( TEXT( "TLSMakeCertificateRequestMessage" ) ) );

	dwRet = NO_ERROR;

	*pcbTLSMessage = 0x04;

	if( ( *ppbTLSMessage = ( PBYTE ) malloc( *pcbTLSMessage ) ) )
	{
		pbTLSMessage = *ppbTLSMessage;
		cbTLSMessage = *pcbTLSMessage;

		memset( pbTLSMessage, 0, cbTLSMessage );

		//
		// ssl handshake header
		//
		pbTLSMessage[dwCursor++] = 0x0D;   // message type is server_done = 13

		// length of fragment is length of total message ( 0 )
		AA_HostToWireFormat24( 0x00 , &( pbTLSMessage[dwCursor] ) );
	}
	else
	{
		AA_TRACE( ( TEXT( "TLSMakeCertificateRequestMessage::could not allocate memory for pbTLSMessage" ) ) );

		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	AA_TRACE( ( TEXT( "TLSMakeCertificateRequestMessage::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSMakeServerHelloDoneMessage
// Description: This function will build the Server Hello Done Message
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
TLSMakeServerHelloDoneMessage(	IN PBYTE			*ppbTLSMessage,
								IN DWORD			*pcbTLSMessage )
{
	PBYTE		pbTLSMessage;
	DWORD		cbTLSMessage;
	DWORD		dwCursor = 0;
	DWORD		dwRet;

	AA_TRACE( ( TEXT( "TLSMakeServerHelloDoneMessage" ) ) );

	dwRet = NO_ERROR;

	*pcbTLSMessage = 0x04;

	if( ( *ppbTLSMessage = ( PBYTE ) malloc( *pcbTLSMessage ) ) )
	{
		pbTLSMessage = *ppbTLSMessage;
		cbTLSMessage = *pcbTLSMessage;

		memset( pbTLSMessage, 0, cbTLSMessage );

		//
		// ssl handshake header
		//
		pbTLSMessage[dwCursor++] = 0x0E;   // message type is server_done = 14

		// length of fragment is length of total message ( 0 )
		AA_HostToWireFormat24( 0x00 , &( pbTLSMessage[dwCursor] ) );
	}
	else
	{
		AA_TRACE( ( TEXT( "TLSMakeServerHelloDoneMessage::could not allocate memory for pbTLSMessage" ) ) );

		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	AA_TRACE( ( TEXT( "TLSMakeServerHelloDoneMessage::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSMakeChangeCipherSpecRecord
// Description: Adds a change cipher spec handshake record to the send message
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSMakeChangeCipherSpecRecord(	IN PBYTE			*ppbRecord,
								IN DWORD			*pcbRecord )
{
	PBYTE		pbRecord;
	DWORD		cbRecord;
	DWORD		dwCursor = 0;
	DWORD		dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSMakeChangeCipherSpecRecord" ) ) );

	*pcbRecord = 0x06;

	if( ( *ppbRecord = ( PBYTE ) malloc( *pcbRecord ) ) )
	{
		pbRecord = *ppbRecord;
		cbRecord = *pcbRecord;

		//
		// ssl record header
		//
		pbRecord[dwCursor++] = 0x14;			// ssl record type is change cipher spec = 20
		pbRecord[dwCursor++] = 0x03;			// ssl major version number
		pbRecord[dwCursor++] = 0x01;			// ssl minor version number

		AA_HostToWireFormat16( 0x01, &( pbRecord[dwCursor] ) ); // length of message

		dwCursor+=2;

		pbRecord[dwCursor++] = 0x01;	

		AA_TRACE( ( TEXT( "TLSMakeChangeCipherSpecRecord::pbRecord(%d): %s" ), cbRecord, AA_ByteToHex( ( PBYTE ) pbRecord, cbRecord ) ) );
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}

//
// Name: TLSMakeClientCertificateMessage
// Description: This function will build the Client Certificate Message
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
TLSMakeClientCertificateMessage( 	OUT PBYTE			*ppbTLSMessage,
									OUT DWORD			*pcbTLSMessage )
{
	PBYTE		pbTLSMessage;
	DWORD		cbTLSMessage;
	DWORD		dwCursor = 0;
	DWORD		dwRet;

	AA_TRACE( ( TEXT( "TLSMakeCertificateMessage" ) ) );

	dwRet = NO_ERROR;

	*pcbTLSMessage = 0x07;

	if( ( *ppbTLSMessage = ( PBYTE ) malloc( *pcbTLSMessage ) ) )
	{
		pbTLSMessage = *ppbTLSMessage;
		cbTLSMessage = *pcbTLSMessage;

		memset( pbTLSMessage, 0, cbTLSMessage );

		pbTLSMessage[dwCursor++] = 0x0B;   // message type is certificate

		AA_HostToWireFormat24( ( DWORD ) ( 0x03 ), &( pbTLSMessage[dwCursor] ) );

		dwCursor+=3;

		AA_HostToWireFormat24( ( DWORD ) ( 0x00 ), &( pbTLSMessage[dwCursor] ) );

		dwCursor+=3;

		AA_TRACE( ( TEXT( "TLSMakeCertificateMessage::pbTLSMessage(%d): %s" ), cbTLSMessage,  AA_ByteToHex( ( PBYTE ) pbTLSMessage, cbTLSMessage ) ) );
	}
	else
	{
		AA_TRACE( ( TEXT( "TLSMakeCertificateMessage::could not allocate memory for pbTLSMessage" ) ) );

		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	AA_TRACE( ( TEXT( "TLSMakeCertificateMessage::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSMakeServerCertificateMessage
// Description: This function will build the Server Certificate Message
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
TLSMakeServerCertificateMessage( 	IN PBYTE		pbServerCertSHA1,
									OUT PBYTE		*ppbTLSMessage,
									OUT DWORD		*pcbTLSMessage )
{
	PCCERT_CONTEXT	pCertContext = NULL;
	PCCERT_CONTEXT	pChainCertContext = NULL;
	PBYTE			pbTLSMessage;
	DWORD			cbTLSMessage;
	DWORD			dwCursor = 0;
	int				i = 0;
	DWORD			dwRet;

	AA_TRACE( ( TEXT( "TLSMakeServerCertificateMessage" ) ) );

	dwRet = NO_ERROR;

	//
	// First find certificate in local store ("MY")
	//
	if( ( dwRet = AA_GetCertificate( pbServerCertSHA1, &pCertContext ) ) == NO_ERROR )
	{
		//
		// Retrieve Certificate Hierarchy
		//
		CERT_CHAIN_PARA				ChainParams;
		PCCERT_CHAIN_CONTEXT		pChainContext;
		CERT_ENHKEY_USAGE			EnhkeyUsage;
		CERT_USAGE_MATCH			CertUsage;  
		DWORD						dwFlags;

		//
		// Initialize the certificate chain validation
		//
		EnhkeyUsage.cUsageIdentifier = 0;
		EnhkeyUsage.rgpszUsageIdentifier = NULL;

		CertUsage.dwType = USAGE_MATCH_TYPE_AND;
		CertUsage.Usage  = EnhkeyUsage;

		memset( &ChainParams, 0, sizeof( CERT_CHAIN_PARA ) );

		ChainParams.dwUrlRetrievalTimeout = 1;
		
		ChainParams.cbSize = sizeof( CERT_CHAIN_PARA );
		ChainParams.RequestedUsage = CertUsage;

		dwFlags =	CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL |
					CERT_CHAIN_CACHE_END_CERT;

		AA_TRACE( ( TEXT( "TLSMakeServerCertificateMessage::AA_GetCertificate returned certificate" ) ) );

		if( pCertContext )
		{
			//
			// Check the certificate chain
			// do not check urls as we do not have any IP connectivity
			//
			if( CertGetCertificateChain( HCCE_LOCAL_MACHINE, 
											pCertContext, 
											NULL,
											NULL,
											&ChainParams,
											0,
											NULL,
											&pChainContext ) )
			{
				AA_TRACE( ( TEXT( "TLSMakeServerCertificateMessage() ), Created pChainContext" ) ) );

				if( pChainContext->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR )
				{
					AA_TRACE( ( TEXT( "TLSMakeServerCertificateMessage::pChainContext:: size: %ld, number of chains: %ld" ), pChainContext->cbSize, pChainContext->cChain ) );

					if( pChainContext->rgpChain[0] )
					{
						DWORD	dwCertListLength = 0;

						AA_TRACE( ( TEXT( "TLSMakeServerCertificateMessage::pChainContext:: size: %ld, number of elements: %ld" ), pChainContext->rgpChain[0]->cbSize, pChainContext->rgpChain[0]->cElement ) );

						//
						// Have to determine length of message first
						//
						*pcbTLSMessage = 0;

						//
						// First retrieve total length of all certificates
						//
						for( i = 0; ( DWORD ) i < pChainContext->rgpChain[0]->cElement; i++ )
						{
							pChainCertContext = pChainContext->rgpChain[0]->rgpElement[i]->pCertContext;

							//
							// Length is current length + header(length:3) + certificate(pChainCertContext->cbCertEncoded:?)
							//
							dwCertListLength = dwCertListLength + 0x03 + pChainCertContext->cbCertEncoded;
						}

						AA_TRACE( ( TEXT( "TLSMakeServerCertificateMessage::total certificates length: %ld" ), dwCertListLength ) );

						//
						// Now add certificate message header(type:1+msg_length:3+certlistlength:3)
						//
						*pcbTLSMessage = dwCertListLength + 0x07;

						//
						// Built initial certificate message
						//
						if( ( *ppbTLSMessage = ( PBYTE ) malloc( *pcbTLSMessage ) ) )
						{
							pbTLSMessage = *ppbTLSMessage;
							cbTLSMessage = *pcbTLSMessage;

							memset( pbTLSMessage, 0, cbTLSMessage );

							pbTLSMessage[dwCursor++] = 0x0B;   // message type is certificate

							//
							// length of  set later, skip
							//
							AA_HostToWireFormat24( dwCertListLength + ( DWORD ) ( 0x03 ), &( pbTLSMessage[dwCursor] ) ); // length of message

							dwCursor+=3;

							//
							// Certificate list length is set later, skip
							//
							AA_HostToWireFormat24( dwCertListLength, &( pbTLSMessage[dwCursor] ) ); // list length

							dwCursor+=3;

							for( i = 0; ( DWORD ) i < pChainContext->rgpChain[0]->cElement; i++ )
							{
								pChainCertContext = pChainContext->rgpChain[0]->rgpElement[i]->pCertContext;

								//
								// Length of certificate
								//
								AA_HostToWireFormat24( pChainCertContext->cbCertEncoded, &( pbTLSMessage[dwCursor] ) ); // length of message

								dwCursor+=3;

								memcpy( &( pbTLSMessage[dwCursor] ), pChainCertContext->pbCertEncoded, pChainCertContext->cbCertEncoded );

								//
								// Certificate
								//
								dwCursor+=pChainCertContext->cbCertEncoded;
							}

							AA_TRACE( ( TEXT( "TLSMakeServerCertificateMessage::pbTLSMessage(%d): %s" ), cbTLSMessage,  AA_ByteToHex( ( PBYTE ) pbTLSMessage, cbTLSMessage ) ) );
						}
						else
						{
							AA_TRACE( ( TEXT( "TLSMakeServerCertificateMessage::could not allocate memory for pbTLSMessage" ) ) );

							dwRet = ERROR_NOT_ENOUGH_MEMORY;
						}
					}
				}
				else
				{
					AA_TRACE( ( TEXT( "TLSMakeServerCertificateMessage(), chain could not be validated( %x )" ), pChainContext->TrustStatus.dwErrorStatus ) );

					dwRet = ERROR_CANTOPEN;
				}


				AA_TRACE( ( TEXT( "TLSMakeServerCertificateMessage(), freeing pChainContext" ) ) );

			}
			else
				dwRet = ERROR_CANTOPEN;

			CertFreeCertificateChain( pChainContext );
		}
		else
		{
			AA_TRACE( ( TEXT( "TLSMakeServerCertificateMessage(), CertGetCertificateChain(), FAILED: %x" ), GetLastError() ) );

			dwRet = ERROR_INTERNAL_ERROR;
		}

        if( pCertContext )
			CertFreeCertificateContext( pCertContext );
	}

	AA_TRACE( ( TEXT( "TLSMakeServerCertificateMessage::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSMakeClientKeyExchangeMessage
// Description: This function will build the Client Key Exchange Message
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
TLSMakeClientKeyExchangeMessage( 	IN PBYTE				pbEncPMS,
									IN DWORD				cbEncPMS,
									OUT PBYTE				*ppbTLSMessage,
									OUT DWORD				*pcbTLSMessage )
{
	PBYTE		pbTLSMessage;
	DWORD		cbTLSMessage;
	PBYTE		pbSwapped;
	DWORD		dwCursor = 0;
	DWORD		dwRet;

	AA_TRACE( ( TEXT( "TLSMakeClientKeyExchangeMessage" ) ) );

	dwRet = NO_ERROR;

	*pcbTLSMessage = 0x06 + cbEncPMS;

	if( ( *ppbTLSMessage = ( PBYTE ) malloc( *pcbTLSMessage ) ) )
	{
		pbTLSMessage = *ppbTLSMessage;
		cbTLSMessage = *pcbTLSMessage;

		memset( pbTLSMessage, 0, cbTLSMessage );

		pbTLSMessage[dwCursor++] = 0x10;		// message type is client_exchange

		AA_HostToWireFormat24( ( WORD ) ( 0x02 + cbEncPMS ), &( pbTLSMessage[dwCursor] ) ); // length of message

		dwCursor+=3;

		//
		// cke header
		//
		AA_HostToWireFormat16( ( WORD ) cbEncPMS, &( pbTLSMessage[dwCursor] ) ); // length of encrypted data

		dwCursor+=2;

		//
		// Copy the encrypted block
		//	
		//
		// but first swap it because of big and little engines... or sumtin like dat... ;)
		//
		if( ( pbSwapped = ( PBYTE ) malloc( cbEncPMS ) ) )
		{				
			AA_SwapArray( pbEncPMS, pbSwapped, cbEncPMS );
			memcpy( &( pbTLSMessage[dwCursor] ), pbSwapped, cbEncPMS );

			//memcpy( &( pbTLSMessage[dwCursor] ), pbEncPMS, cbEncPMS );

			AA_TRACE( ( TEXT( "TLSMakeClientKeyExchangeMessage::pbTLSMessage(%d): %s" ), cbTLSMessage,  AA_ByteToHex( ( PBYTE ) pbTLSMessage, cbTLSMessage ) ) );

			free( pbSwapped );
		}
		else
		{
			free( *ppbTLSMessage );
			*pcbTLSMessage = 0;
		}
	}
	else
	{
		AA_TRACE( ( TEXT( "TLSMakeClientKeyExchangeMessage::could not allocate memory for pbTLSMessage" ) ) );

		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	AA_TRACE( ( TEXT( "TLSMakeClientKeyExchangeMessage::returning" ) ) );

	return dwRet;
}

//
// Name: TLSMakeFinishedMessage
// Description: This function will build the Finished Message
// Author: Tom Rixom
// Created: 11 August 2004
//
DWORD
TLSMakeFinishedMessage(	IN HCRYPTPROV		hCSP,
						IN DWORD			dwHandshakeMsgCount,
						IN PBYTE			pbHandshakeMsg[TLS_MAX_HS],
						IN DWORD			cbHandshakeMsg[TLS_MAX_HS],
						IN PCHAR			pcLabel,
						IN DWORD			ccLabel,
						IN PBYTE			pbMS,
						IN DWORD			cbMS,
						OUT PBYTE			*ppbTLSMessage,
						OUT DWORD			*pcbTLSMessage )
{
	BYTE				pbFinished[TLS_FINISH_SIZE];
	DWORD				cbFinished = sizeof( pbFinished );
	PBYTE				pbHash;
	DWORD				cbHash;
	PBYTE				pbMD5;
	DWORD				cbMD5;
	PBYTE				pbSHA1;
	DWORD				cbSHA1;
	PBYTE				pbData;
	DWORD				cbData;
	DWORD				dwOffset;
	DWORD				dwI = 0;
	int					i = 0;
	PBYTE				pbTLSMessage;
	DWORD				cbTLSMessage;
	DWORD				dwCursor = 0;
	DWORD				dwRet;

	AA_TRACE( ( TEXT( "TLSMakeFinishedMessage" ) ) );

	dwRet = NO_ERROR;

	*pcbTLSMessage = 0x04+TLS_FINISH_SIZE;

	if( ( *ppbTLSMessage = ( PBYTE ) malloc( *pcbTLSMessage ) ) )
	{
		pbTLSMessage = *ppbTLSMessage;
		cbTLSMessage = *pcbTLSMessage;

		memset( pbTLSMessage, 0, cbTLSMessage );

		pbTLSMessage[dwCursor++] = 0x14; // finish message

		AA_HostToWireFormat24( ( WORD ) TLS_FINISH_SIZE, &( pbTLSMessage[dwCursor] ) );

		dwCursor+=3;

		if( hCSP )
		{
			//
			// first calculate length of total handshake msg
			//
			cbData = 0;

			for( dwI=0; dwI < dwHandshakeMsgCount; dwI++ )
				cbData = cbData + cbHandshakeMsg[dwI];

			if( ( pbData = ( PBYTE ) malloc( cbData ) ) )
			{
				dwOffset = 0;

				for( dwI=0; dwI < dwHandshakeMsgCount; dwI++ )
				{
					AA_TRACE( ( TEXT( "TLSMakeFinishedMessage::offset(%d)" ), dwOffset ) );

					memcpy( &( pbData[dwOffset] ), pbHandshakeMsg[dwI], cbHandshakeMsg[dwI] );
					dwOffset = dwOffset+cbHandshakeMsg[dwI];
				}

				AA_TRACE( ( TEXT( "TLSMakeFinishedMessage::TLSMakeFinishedMessage(%d):%s" ), cbData, AA_ByteToHex( pbData, cbData) ) );

				if( ( TLSGetMD5( hCSP, pbData, cbData, &pbMD5, &cbMD5 ) ) == NO_ERROR )
				{
					if( ( TLSGetSHA1( hCSP, pbData, cbData, &pbSHA1, &cbSHA1 ) ) == NO_ERROR )
					{
						cbHash = cbMD5 + cbSHA1;

						if( ( pbHash = ( PBYTE ) malloc( cbHash ) ) )
						{
							memcpy( pbHash, pbMD5, cbMD5 );
							memcpy( &( pbHash[cbMD5] ), pbSHA1, cbSHA1 );

							AA_TRACE( ( TEXT( "TLSMakeFinishedMessage::HASH(%d):%s" ), cbHash, AA_ByteToHex( pbHash, cbHash ) ) );

							if( ( dwRet = TLS_PRF( hCSP, 
													pbMS, 
													cbMS, 
													( PBYTE ) pcLabel, 
													ccLabel, 
													pbHash, 
													cbHash, 
													pbFinished, 
													cbFinished ) ) == NO_ERROR )
							{
								memcpy( &( pbTLSMessage[dwCursor] ), pbFinished, cbFinished );

								dwCursor+=cbFinished;
							}

							free( pbHash );
						}
						else
						{
							AA_TRACE( ( TEXT( "TLSMakeFinishedMessage::ERROR:could not allocate memory for pbHash" ) ) );

							dwRet = dwRet = ERROR_NOT_ENOUGH_MEMORY;
						}

						free( pbSHA1 );
					}

					free( pbMD5 );
				}

				free( pbData );
			}
			else
			{
				AA_TRACE( ( TEXT( "TLSMakeFinishedMessage::ERROR:could not allocate memory for pbHandshakeMsg" ) ) );

				dwRet = dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
		{
			AA_TRACE( ( TEXT( "TLSMakeFinishedMessage::ERROR::no handle to help CSP" ) ) );

			dwRet = ERROR_ENCRYPTION_FAILED;
		}

		if( dwRet != NO_ERROR )
		{
			free( *ppbTLSMessage );
			*pcbTLSMessage = 0;
		}
	}
	else
	{
		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	AA_TRACE( ( TEXT( "TLSMakeFinishedMessage::returning error: %x" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSVerifyFinishedMessage
// Description: This function verifies the server finished message
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSVerifyFinishedMessage(	IN HCRYPTPROV		hCSP,
							IN DWORD			dwHandshakeMsgCount,
							IN PBYTE			pbHandshakeMsg[TLS_MAX_HS],
							IN DWORD			cbHandshakeMsg[TLS_MAX_HS],
							IN PCHAR			pcLabel,
							IN DWORD			ccLabel,
							IN PBYTE			pbMS,
							IN DWORD			cbMS,
							IN PBYTE			pbVerifyFinished,
							IN DWORD			cbVerifyFinished )
{
	PBYTE				pbHash;
	DWORD				cbHash;
	PBYTE				pbMD5;
	DWORD				cbMD5;
	PBYTE				pbSHA1;
	DWORD				cbSHA1;
	PBYTE				pbData;
	DWORD				cbData;
	DWORD				dwOffset;
	DWORD				dwI = 0;
	int					i = 0;
	PBYTE				pbFinished;
	DWORD				cbFinished;
	DWORD				dwCursor = 0;
	DWORD				dwRet;

	AA_TRACE( ( TEXT( "TLSVerifyFinished::pbVerifyFinished(%d):%s" ), cbVerifyFinished, AA_ByteToHex( pbVerifyFinished, cbVerifyFinished ) ) );	

	dwRet = NO_ERROR;

	cbFinished = TLS_FINISH_SIZE;

	if( cbFinished != cbVerifyFinished )
		return ERROR_ENCRYPTION_FAILED;

	if( ( pbFinished = ( PBYTE ) malloc( cbFinished ) ) )
	{
		memset( pbFinished, 0, cbFinished );

		if( hCSP )
		{
			//
			// first calculate length of total handshake msg
			//
			cbData = 0;

			for( dwI=0; dwI < dwHandshakeMsgCount; dwI++ )
				cbData = cbData + cbHandshakeMsg[dwI];

			if( ( pbData = ( PBYTE ) malloc( cbData ) ) )
			{
				dwOffset = 0;

				for( dwI=0; dwI < dwHandshakeMsgCount; dwI++ )
				{
					AA_TRACE( ( TEXT( "TLSVerifyFinished::offset(%d)" ), dwOffset ) );

					memcpy( &( pbData[dwOffset] ), pbHandshakeMsg[dwI], cbHandshakeMsg[dwI] );
					dwOffset = dwOffset+cbHandshakeMsg[dwI];
				}

				AA_TRACE( ( TEXT( "TLSVerifyFinished::HandshakeMsg(%d):%s" ), cbData, AA_ByteToHex( pbData, cbData) ) );

				if( ( TLSGetMD5( hCSP, pbData, cbData, &pbMD5, &cbMD5 ) ) == NO_ERROR )
				{
					if( ( TLSGetSHA1( hCSP, pbData, cbData, &pbSHA1, &cbSHA1 ) ) == NO_ERROR )
					{
						cbHash = cbMD5 + cbSHA1;

						if( ( pbHash = ( PBYTE ) malloc( cbHash ) ) )
						{
							memcpy( pbHash, pbMD5, cbMD5 );
							memcpy( &( pbHash[cbMD5] ), pbSHA1, cbSHA1 );

							AA_TRACE( ( TEXT( "TLSVerifyFinished::HASH(%d):%s" ), cbHash, AA_ByteToHex( pbHash, cbHash ) ) );	

							if( ( dwRet = TLS_PRF( hCSP, pbMS, cbMS, ( PBYTE ) pcLabel, ccLabel, pbHash, cbHash, pbFinished, cbFinished ) ) == NO_ERROR )
							{
								for( i=0; ( DWORD ) i < cbFinished; i++ )
								{
									if( pbFinished[i] != pbVerifyFinished[i] )
									{
										dwRet = ERROR_ENCRYPTION_FAILED;
										break;
									}
								}
							}

							free( pbHash );
						}
						else
						{
							AA_TRACE( ( TEXT( "TLSVerifyFinished::ERROR:could not allocate memory for pbHash" ) ) );

							dwRet = dwRet = ERROR_NOT_ENOUGH_MEMORY;
						}

						free( pbSHA1 );
					}

					free( pbMD5 );
				}

				free( pbData );
			}
			else
			{
				AA_TRACE( ( TEXT( "TLSVerifyFinished::ERROR:could not allocate memory for pbData" ) ) );

				dwRet = dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
		{
			AA_TRACE( ( TEXT( "TLSVerifyFinished::ERROR::no handle to help CSP" ) ) );

			dwRet = ERROR_ENCRYPTION_FAILED;
		}

		free( pbFinished );
	}
	else
	{
		AA_TRACE( ( TEXT( "TLSVerifyFinished::ERROR:could not allocate memory for pbFinished" ) ) );

		dwRet = dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	AA_TRACE( ( TEXT( "TLSVerifyFinished::returning error: %x" ), dwRet ) );

	return dwRet;
}
