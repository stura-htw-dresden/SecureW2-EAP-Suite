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
// Name: EAP.c
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

#include "../Main.h"

//
// Name: AuthHandleInnerEAPAuthentication
// Description: This function is called when the TLS tunnel has been setup and the inner authentication must be done
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
AuthHandleInnerEAPAuthentication( IN PSW2_SESSION_DATA	pSessionData,
							 OUT PPP_EAP_PACKET*    pSendPacket,
							 IN DWORD               cbSendPacket,
							 IN	PPP_EAP_INPUT		*pInput,
							 IN	PPP_EAP_OUTPUT		*pEapOutput )
{
	PPP_EAP_PACKET		*pInnerEapReceivePacket;
	PPP_EAP_PACKET		*pInnerEapSendPacket;
	DWORD				cbInnerEapSendPacket;
	PPP_EAP_OUTPUT		InnerEapOutput;
	BYTE				pbMA[] = { 0x00, 0x00, 0x00, 0x00, 
									0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00 };
	PBYTE				pbAVP;
	DWORD				cbAVP;
	PBYTE				pbMAAVP;
	DWORD				cbMAAVP;
	PBYTE				pbEAPAVP;
	DWORD				cbEAPAVP;
	PBYTE				pbStateAVP;
	DWORD				cbStateAVP;
	PBYTE				pbEAPAttribute;
	DWORD				cbEAPAttribute;
	PCHAR				pcInnerEapIdentity;
	DWORD				ccInnerEapIdentity;
	PBYTE				pbRecord;
	DWORD				cbRecord;
	DWORD				dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication" ) ) );

	//
	// Reset InteractiveUI every time we get a InnerMakeMessage
	//
	pSessionData->InnerSessionData.InnerEapInput.fDataReceivedFromInteractiveUI = FALSE;

	pSessionData->InnerSessionData.InnerEapInput.dwSizeOfDataFromInteractiveUI = 0;

	switch( pSessionData->InnerSessionData.InnerAuthState )
	{
		case INNER_AUTH_STATE_Start:

			AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::EAP::INNER_AUTH_STATE_Start" ) ) );

			//
			// Build the AVPS for EAP
			//
			ccInnerEapIdentity = ( DWORD ) wcslen( pSessionData->pUserData->InnerEapUserData.pwcIdentity );

			if( ( pcInnerEapIdentity = ( PCHAR ) malloc( ccInnerEapIdentity + 1 ) ) )
			{
				WideCharToMultiByte( CP_ACP, 0, pSessionData->pUserData->InnerEapUserData.pwcIdentity, -1, pcInnerEapIdentity, ccInnerEapIdentity + 1, NULL, NULL );
			}
			else
			{
				AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::EAP::not enough memory" ) ) );

				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}

			if( dwRet == NO_ERROR )
			{
				if( ( dwRet = AuthMakeEAPResponseAttribute( 0x01, 0x00, ( PBYTE ) pcInnerEapIdentity, ccInnerEapIdentity, &pbEAPAttribute, &cbEAPAttribute ) ) == NO_ERROR )
				{
					if( ( dwRet = AuthMakeDiameterAttribute( 0x4F, pbEAPAttribute, cbEAPAttribute, &pbEAPAVP, &cbEAPAVP ) ) == NO_ERROR )
					{
						//
						// Add empty message authenticator
						//
						if( ( dwRet = AuthMakeDiameterAttribute( 0x50, 
																pbMA, 
																sizeof( pbMA ), 
																&pbMAAVP, 
																&cbMAAVP ) ) == NO_ERROR )
						{
							cbAVP = cbEAPAVP + cbMAAVP;

							if( ( pbAVP = ( PBYTE ) malloc( cbAVP ) ) )
							{
								memcpy( pbAVP, pbEAPAVP, cbEAPAVP );
								memcpy( pbAVP + cbEAPAVP, pbMAAVP, cbMAAVP );

								if( ( dwRet = TLSMakeApplicationRecord( pSessionData->hCSP, 
																		pSessionData->hWriteKey,
																		pSessionData->dwMacKey,
																		pSessionData->dwMacKeySize,
																		pSessionData->pbWriteMAC,
																		&( pSessionData->dwSeqNum ),
																		pbAVP, 
																		cbAVP, 
																		&pbRecord, 
																		&cbRecord, 
																		pSessionData->bCipherSpec ) ) == NO_ERROR )
								{
									dwRet = TLSAddMessage(	pbRecord, 
															cbRecord, 
															cbRecord,
															pSendPacket, 
															cbSendPacket );

									pEapOutput->Action = EAPACTION_Send;

									pSessionData->InnerSessionData.InnerAuthState = INNER_AUTH_STATE_MakeMessage;

									free( pbRecord );
									cbRecord = 0;
								}

								free( pbAVP );
								cbAVP = 0;
							}
							else
								dwRet = ERROR_NOT_ENOUGH_MEMORY;

							free( pbMAAVP );
							cbMAAVP = 0;
						}


						free( pbEAPAVP );
						cbEAPAVP = 0;
					}

					AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::freeing pbEAPAttribute" ) ) );

					free( pbEAPAttribute );
					cbEAPAttribute = 0;
				}

				AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::freeing pcInnerEapIdentity" ) ) );

				free( pcInnerEapIdentity );
				ccInnerEapIdentity= 0;
			}

		break;

		case INNER_AUTH_STATE_InteractiveUI:

			AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::INNER_AUTH_STATE_InteractiveUI" ) ) );

			//
			// First check if we received any data from interactiveui
			//
			if( !pInput->fDataReceivedFromInteractiveUI )
			{
				AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::INNER_AUTH_STATE_InteractiveUI::User has not exited from VerifyCertificate dialog yet." ) ) );

				pEapOutput->Action = EAPACTION_NoAction;

				break;
			}
			else
			{
				AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::INNER_AUTH_STATE_InteractiveUI::copying %ld data" ), pInput->dwSizeOfDataFromInteractiveUI ) );

				//
				// Copy data received from interactive ui and call Inner MakeMessage
				//
				pSessionData->InnerSessionData.InnerEapInput.fDataReceivedFromInteractiveUI = TRUE;

				pSessionData->InnerSessionData.InnerEapInput.dwSizeOfDataFromInteractiveUI = pInput->dwSizeOfDataFromInteractiveUI;

				pSessionData->InnerSessionData.InnerEapInput.pDataFromInteractiveUI = pInput->pDataFromInteractiveUI;
			}

		case INNER_AUTH_STATE_MakeMessage:

			AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::EAP::INNER_AUTH_STATE_MakeMessage" ) ) );

			if( pSessionData->InnerSessionData.pbInnerEapMessage )
			{
				if( ( pInnerEapReceivePacket = ( PPP_EAP_PACKET *) pSessionData->InnerSessionData.pbInnerEapMessage ) )
				{
					AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::EAP::INNER_AUTH_STATE_MakeMessage:pInnerEapReceivePacket(%ld): %s" ), pSessionData->InnerSessionData.cbInnerEapMessage, AA_ByteToHex( ( PBYTE ) pInnerEapReceivePacket, pSessionData->InnerSessionData.cbInnerEapMessage ) ) );

					//
					// Let's see what is in the packet
					//
					switch( pInnerEapReceivePacket->Code )
					{
						case EAPCODE_Request:

							AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::INNER_AUTH_STATE_MakeMessage::EAPCODE_Request" ) ) );

						case EAPCODE_Success:

							AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::INNER_AUTH_STATE_MakeMessage::EAPCODE_Success" ) ) );

						case EAPCODE_Failure:
							
							AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::INNER_AUTH_STATE_MakeMessage::EAPCODE_Failure" ) ) );

							if( pInnerEapReceivePacket->Data[0] != 
															pSessionData->InnerSessionData.pInnerEapConfigData->dwEapType )
							{
								//
								// Not for our Inner EAP DLL so send NAK request for our auth type
								//
								AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::request for %x" ), pInnerEapReceivePacket->Data[0] ) );

								if( ( dwRet = AuthMakeEAPResponseAttribute( 0x03, 
											pInnerEapReceivePacket->Id, 
											( PBYTE ) &( pSessionData->InnerSessionData.pInnerEapConfigData->dwEapType ), 
											1, 
											&pbEAPAttribute, 
											&cbEAPAttribute ) ) == NO_ERROR )
								{
									//
									// Add EAP Message
									//
									if( ( dwRet = AuthMakeDiameterAttribute( 0x4F, pbEAPAttribute, cbEAPAttribute, &pbEAPAVP, &cbEAPAVP ) ) == NO_ERROR )
									{
										//
										// Add empty message authenticator
										//
										if( ( dwRet = AuthMakeDiameterAttribute( 0x50, 
																				pbMA, 
																				sizeof( pbMA ), 
																				&pbMAAVP, 
																				&cbMAAVP ) ) == NO_ERROR )
										{
											if( pSessionData->cbState > 0 )
											{
												//
												// Copy state attribute into response
												//
												if( ( dwRet = AuthMakeDiameterAttribute( 0x18, 
																				pSessionData->pbState, 
																				pSessionData->cbState, 
																				&pbStateAVP, 
																				&cbStateAVP ) ) == NO_ERROR )
												{
													cbAVP = cbEAPAVP + cbMAAVP + cbStateAVP;

													if( ( pbAVP = ( PBYTE ) malloc( cbAVP ) ) )
													{
														memcpy( pbAVP, pbEAPAVP, cbEAPAVP );
														memcpy( pbAVP + cbEAPAVP, pbMAAVP, cbMAAVP );
														memcpy( pbAVP + cbEAPAVP + cbMAAVP, pbStateAVP, cbStateAVP );
													}
													else
														dwRet = ERROR_NOT_ENOUGH_MEMORY;
												}
											}
											else
											{
												//
												// copy only EAP-MESSAGE and Message Authenticator
												//
												cbAVP = cbEAPAVP + cbMAAVP;

												if( ( pbAVP = ( PBYTE ) malloc( cbAVP ) ) )
												{
													memcpy( pbAVP, pbEAPAVP, cbEAPAVP );
													memcpy( pbAVP + cbEAPAVP, pbMAAVP, cbMAAVP );
												}
												else
													dwRet = ERROR_NOT_ENOUGH_MEMORY;
											}

											if( dwRet == NO_ERROR )
											{
												if( ( dwRet = TLSMakeApplicationRecord( pSessionData->hCSP, 
																						pSessionData->hWriteKey,
																						pSessionData->dwMacKey,
																						pSessionData->dwMacKeySize,
																						pSessionData->pbWriteMAC,
																						&( pSessionData->dwSeqNum ),
																						pbAVP, 
																						cbAVP, 
																						&pbRecord, 
																						&cbRecord, 
																						pSessionData->bCipherSpec ) ) == NO_ERROR )
												{
													dwRet = TLSAddMessage(	pbRecord, 
																			cbRecord, 
																			cbRecord,
																			pSendPacket, 
																			cbSendPacket );

													pEapOutput->Action = EAPACTION_Send;

													pSessionData->InnerSessionData.InnerAuthState = INNER_AUTH_STATE_MakeMessage;

													free( pbRecord );
													cbRecord = 0;
												}

												free( pbAVP );
												cbAVP = 0;
											}

											free( pbMAAVP );
											cbMAAVP = 0;
										}

										free( pbEAPAVP );
										cbEAPAVP = 0;
									}

									AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::freeing pbEAPAttribute" ) ) );

									free( pbEAPAttribute );
									cbEAPAttribute = 0;
								}
							}

						break;

						case EAPCODE_Response:

						default:

							dwRet  = ERROR_PPP_INVALID_PACKET;

						break;
					}
				}
				else
				{
					AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::could not allocate data for pInnerEapReceivePacket" ) ) );

					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}

			}
			else
				pInnerEapReceivePacket = NULL;

			//
			// If we haven't sent anything yet and no error has occured then continue
			//
			if( ( pEapOutput->Action != EAPACTION_Send ) && 
				( dwRet == NO_ERROR ) )
			{
				AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::building sendpacket" ) ) );

				//
				// InnerEapSendPacket must be Our cbSendPacket 
				// (1490) - 90 (header information needed to transport through ttls)
				//
				cbInnerEapSendPacket = 1400;

				if( ( pInnerEapSendPacket = ( PPP_EAP_PACKET * ) malloc( cbInnerEapSendPacket ) ) )
				{
					memset( pInnerEapSendPacket, 0, cbInnerEapSendPacket );

					memset( &InnerEapOutput, 0, sizeof( InnerEapOutput ) );

					AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::calling InnerEapMakeMessage" ) ) );

					if( ( dwRet = pSessionData->InnerSessionData.pInnerEapMakeMessage( 
											pSessionData->InnerSessionData.pbInnerEapSessionData,
											pInnerEapReceivePacket,
											pInnerEapSendPacket,
											cbInnerEapSendPacket,
											&InnerEapOutput,
											&( pSessionData->InnerSessionData.InnerEapInput ) ) ) == NO_ERROR )
					{
						AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::pInnerSendPacket(%d): %s" ), cbInnerEapSendPacket, AA_ByteToHex( ( PBYTE ) pInnerEapSendPacket, cbInnerEapSendPacket ) ) );

						//
						// Let's see what the module wants us to do
						//
						AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::InnerEapOutput.fSaveUserData: %ld" ), InnerEapOutput.fSaveUserData ) );

						if( InnerEapOutput.fSaveUserData )
						{
							AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::saving inner user data" ) ) );

							//
							// Save the EapOutPut.UserData
							//
							if( InnerEapOutput.dwSizeOfUserData <= EAP_MAX_INNER_DATA )
							{
								pSessionData->pUserData->InnerEapUserData.cbUserData = InnerEapOutput.dwSizeOfUserData;

								memcpy( pSessionData->pUserData->InnerEapUserData.pbUserData, InnerEapOutput.pUserData, InnerEapOutput.dwSizeOfUserData );
							}
							else
							{
								AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::WARNING not enough memory to store inner user data" ) ) );
							}
						}

						AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::InnerEapOutput.Action: %ld" ), InnerEapOutput.Action ) );

						pEapOutput->Action = InnerEapOutput.Action;

						if( InnerEapOutput.fInvokeInteractiveUI )
						{
							AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::InnerEapOutput.fInvokeInteractiveUI" ) ) );

							pEapOutput->fInvokeInteractiveUI = TRUE;

							pSessionData->bInteractiveUIType = UI_TYPE_INNER_EAP;

							pSessionData->InnerSessionData.InnerAuthState = INNER_AUTH_STATE_InteractiveUI;

							//
							// Copy Inner UI Context Data
							// 
							if( InnerEapOutput.dwSizeOfUIContextData <= EAP_MAX_INNER_UI_DATA )
							{
								pSessionData->dwInnerSizeOfUIContextData = InnerEapOutput.dwSizeOfUIContextData;

								memcpy( pSessionData->pbInnerUIContextData,
										InnerEapOutput.pUIContextData,
										pSessionData->dwInnerSizeOfUIContextData );

								pEapOutput->pUIContextData = ( PBYTE ) pSessionData;

								pEapOutput->dwSizeOfUIContextData = 
														sizeof( SW2_SESSION_DATA ) +
														sizeof( SW2_PROFILE_DATA ) +
														sizeof( SW2_USER_DATA );

								pEapOutput->Action = EAPACTION_NoAction;
							}
							else
								dwRet = ERROR_NOT_ENOUGH_MEMORY;
						}
						else 
						{
							switch( InnerEapOutput.Action )
							{
								case EAPACTION_NoAction:

									AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::EAPACTION_NoAction" ) ) );
								
								break;

								case EAPACTION_Authenticate:

									//
									// Not sure what to do now...
									//
									AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::EAPACTION_Authenticate" ) ) );

								break;

								case EAPACTION_Done:

									AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::EAPACTION_Done" ) ) );

									pEapOutput->dwAuthResultCode = InnerEapOutput.dwAuthResultCode;

								break;

								case EAPACTION_SendAndDone:

									AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::EAPACTION_SendAndDone" ) ) );

									pEapOutput->dwAuthResultCode = InnerEapOutput.dwAuthResultCode;

								case EAPACTION_Send:
								case EAPACTION_SendWithTimeout:
								case EAPACTION_SendWithTimeoutInteractive:

									//
									// Build response attribute
									//
									if( ( dwRet = AuthMakeDiameterAttribute( 0x4F, ( PBYTE ) pInnerEapSendPacket, AA_WireToHostFormat16( pInnerEapSendPacket->Length ), &pbEAPAVP, &cbEAPAVP ) ) == NO_ERROR )
									{
										//
										// Add empty message authenticator
										//
										if( ( dwRet = AuthMakeDiameterAttribute( 0x50, 
																				pbMA, 
																				sizeof( pbMA ), 
																				&pbMAAVP, 
																				&cbMAAVP ) ) == NO_ERROR )
										{
											if( pSessionData->cbState > 0 )
											{
												//
												// Copy state attribute into response
												//
												if( ( dwRet = AuthMakeDiameterAttribute( 0x18, 
																				pSessionData->pbState, 
																				pSessionData->cbState, 
																				&pbStateAVP, 
																				&cbStateAVP ) ) == NO_ERROR )
												{
													cbAVP = cbEAPAVP + cbMAAVP + cbStateAVP;

													if( ( pbAVP = ( PBYTE ) malloc( cbAVP ) ) )
													{
														memcpy( pbAVP, pbEAPAVP, cbEAPAVP );
														memcpy( pbAVP + cbEAPAVP, pbMAAVP, cbMAAVP );
														memcpy( pbAVP + cbEAPAVP + cbMAAVP, pbStateAVP, cbStateAVP );
													}
													else
														dwRet = ERROR_NOT_ENOUGH_MEMORY;
												}
											}
											else
											{
												//
												// copy only EAP-MESSAGE and Message Authenticator
												//
												cbAVP = cbEAPAVP + cbMAAVP;

												if( ( pbAVP = ( PBYTE ) malloc( cbAVP ) ) )
												{
													memcpy( pbAVP, pbEAPAVP, cbEAPAVP );
													memcpy( pbAVP + cbEAPAVP, pbMAAVP, cbMAAVP );
												}
												else
													dwRet = ERROR_NOT_ENOUGH_MEMORY;
											}

											if( dwRet == NO_ERROR )
											{
												if( ( dwRet = TLSMakeApplicationRecord( pSessionData->hCSP, 
																						pSessionData->hWriteKey,
																						pSessionData->dwMacKey,
																						pSessionData->dwMacKeySize,
																						pSessionData->pbWriteMAC,
																						&( pSessionData->dwSeqNum ),
																						pbAVP, 
																						cbAVP, 
																						&pbRecord, 
																						&cbRecord, 
																						pSessionData->bCipherSpec ) ) == NO_ERROR )
												{
													dwRet = TLSAddMessage(	pbRecord, 
																			cbRecord, 
																			cbRecord,
																			pSendPacket, 
																			cbSendPacket );

													pEapOutput->Action = EAPACTION_Send;

													pSessionData->InnerSessionData.InnerAuthState = INNER_AUTH_STATE_MakeMessage;

													free( pbRecord );
													cbRecord = 0;
												}

												free( pbAVP );
												cbAVP = 0;
											}

											free( pbMAAVP );
											cbMAAVP = 0;
										}

										free( pbEAPAVP );
										cbEAPAVP = 0;
									}

								default:
								break;
							}
						}
					}
					else
					{
						AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::pInnerEapMakeMessage FAILED: %ld" ), dwRet ) );
					}

					free( pInnerEapSendPacket );
				}
				else
				{
					AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::could not allocate data for pInnerEapSendPacket" ) ) );

					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
		break;

		case INNER_AUTH_STATE_Finished:

			AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::INNER_AUTH_STATE_Finished" ) ) );

			//
			// should never get here
			//
			dwRet = ERROR_PPP_INVALID_PACKET;

		break;

		default:

			AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::unknown inner authentication state" ) ) );

			dwRet = ERROR_PPP_INVALID_PACKET;

		break;
	}

	AA_TRACE( ( TEXT( "AuthHandleInnerEAPAuthentication::returning, action: %x, authcode: %x, error: %x" ), pEapOutput->Action, pEapOutput->dwAuthResultCode, dwRet ) );

	return dwRet;
}

//
// Name: AuthMakeEAPResponseAttribute
// Description: This function builds a EAP response attribute
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
AuthMakeEAPResponseAttribute(	IN BYTE bType,
								IN BYTE bPacketId,
								IN PBYTE pbData,
								IN DWORD cbData,
								OUT PBYTE *ppbEAPAttribute,
								OUT DWORD *pcbEAPAttribute )
{
	PBYTE	pbEAPAttribute;
	DWORD	cbEAPAttribute;
	DWORD	dwCursor;
	DWORD	dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "AuthMakeEAPResponseAttribute::pbData(%d):%s" ), cbData, AA_ByteToHex( pbData, cbData ) ) );

#ifdef EAP_USE_MS_PEAP
	*pcbEAPAttribute = 0x01 + cbData;
#else
	*pcbEAPAttribute = 0x05 + cbData;
#endif

	if( ( *ppbEAPAttribute = ( PBYTE ) malloc( *pcbEAPAttribute ) ) )
	{
		pbEAPAttribute = *ppbEAPAttribute;
		cbEAPAttribute = *pcbEAPAttribute;

		memset( pbEAPAttribute, 0, cbEAPAttribute );

		dwCursor = 0;

#ifndef EAP_USE_MS_PEAP
		//
		// Response
		//
		pbEAPAttribute[dwCursor++] = 0x02; // code
		pbEAPAttribute[dwCursor++] = bPacketId; // id

		AA_HostToWireFormat16( cbEAPAttribute, &( pbEAPAttribute[dwCursor] ) ); // total length of packet
		dwCursor+=2;
#endif

		pbEAPAttribute[dwCursor++] = bType; // type

		memcpy( &( pbEAPAttribute[dwCursor] ), pbData, cbData );
	}
	else
	{
		AA_TRACE( ( TEXT( "AuthMakeEAPResponseAttribute::not enough memory" ) ) );

		dwRet = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwRet;
}
