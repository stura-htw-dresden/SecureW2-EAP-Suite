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
// Name: Crypto.c
// Description: Contains the client crypto functionality for the module
// Author: Tom Rixom
// Created: 17 December 2002
// Version: 1.0
// Last revision: 12 May 2004
//
// ----------------------------- Revisions -------------------------------
//
// Revision - <Date of revision> <Version of file which has been revised> <Name of author>
// <Description of what has been revised>
//
// Only check for Enhanced key usage if configured - 21 April 2004 - Tom Rixom
//
// Added functionality to read out certificate CA list and add it to ComboBox - 12 May 2004 - Tom Rixom
//
#include "Main.h"

//
// Name: TLSGenRSAEncPMS
// Description: This Encrypt the PMS (Pre Master Secret) using RSA
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
TLSGenRSAEncPMS( IN PSW2_SESSION_DATA pSessionData, PBYTE *ppbEncPMS, DWORD *pcbEncPMS )
{
	PCCERT_CONTEXT		pCertContext;
	HCRYPTKEY			hPubKeyServer;
	DWORD				dwBufLen;
	DWORD				dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSGenRSAEncPMS" ) ) );

	if( pSessionData->hCSP )
	{
		AA_TRACE( ( TEXT( "TLSGenRSAEncPMS::Certificate dump(%d):\n%s" ), pSessionData->cbCertificate[0], AA_ByteToHex( pSessionData->pbCertificate[0], pSessionData->cbCertificate[0] ) ) );

		//
		// First decode the certificate so Windows can read it.
		//
		if( ( pCertContext = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
															pSessionData->pbCertificate[0], 
															pSessionData->cbCertificate[0] ) ) )
		{
			//
			// Import the public key
			//
			if( CryptImportPublicKeyInfo( pSessionData->hCSP,
											X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
											&pCertContext->pCertInfo->SubjectPublicKeyInfo,
											&hPubKeyServer ) )
			{
				//
				// First generate 48 bytes encrypted PMS
				//
				if( ( dwRet = TLSGenPMS( pSessionData->pbPMS ) ) == NO_ERROR )
				{
					*pcbEncPMS = TLS_PMS_SIZE;

					if( !CryptEncrypt( hPubKeyServer,
										0,
										TRUE,
										0,
										NULL,
										pcbEncPMS,
										0 ) )
					{
						dwRet = GetLastError();
					}

					AA_TRACE( ( TEXT( "TLSGenRSAEncPMS::CryptEncrypt1 returned %ld" ), dwRet ) );

					if( dwRet == NO_ERROR || dwRet == ERROR_MORE_DATA )
					{
						dwRet = NO_ERROR;

						AA_TRACE( ( TEXT( "TLSGenRSAEncPMS::pcbEncPMS: %ld" ), *pcbEncPMS ) );

						dwBufLen = *pcbEncPMS;

						if( ( *ppbEncPMS = ( PBYTE ) malloc( *pcbEncPMS ) ) )
						{
							AA_TRACE( ( TEXT( "TLSGenRSAEncPMS::encrypting: %s" ), AA_ByteToHex( pSessionData->pbPMS, TLS_PMS_SIZE ) ) );

							memcpy( *ppbEncPMS, pSessionData->pbPMS, TLS_PMS_SIZE );

							*pcbEncPMS = TLS_PMS_SIZE;

							if( CryptEncrypt( hPubKeyServer,
												0,
												TRUE,
												0,
												*ppbEncPMS,
												pcbEncPMS,
												dwBufLen ) )
							{
								AA_TRACE( ( TEXT( "TLSGenRSAEncPMS::pbEncPMS(%d):%s" ), *pcbEncPMS, AA_ByteToHex( *ppbEncPMS, *pcbEncPMS ) ) );
							}
							else
							{
								dwRet = ERROR_ENCRYPTION_FAILED;
							}

							if( dwRet != NO_ERROR )
								free( *ppbEncPMS );
						}
						else
						{
							dwRet = ERROR_NOT_ENOUGH_MEMORY;
						}
					}
				}

				CryptDestroyKey( hPubKeyServer );
			}
			else
			{
				AA_TRACE( ( TEXT( "TLSGenRSAEncPMS::CryptImportPublicKeyInfo:: FAILED (%d)" ), GetLastError() ) );

				dwRet = ERROR_ENCRYPTION_FAILED;
			}						
		}
		else
		{
			AA_TRACE( ( TEXT( "TLSGenRSAEncPMS::CertCreateCertificateContext:: FAILED (%d)" ), GetLastError() ) );

			dwRet = ERROR_ENCRYPTION_FAILED;
		}

		CertFreeCertificateContext( pCertContext );
	}
	else
	{
		AA_TRACE( ( TEXT( "TLSGenRSAEncPMS::ERROR::no handle to help CSP" ) ) );

		dwRet = ERROR_ENCRYPTION_FAILED;
	}

	AA_TRACE( ( TEXT( "TLSGenRSAEncPMS::returning: %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSDeriveKeys
// Description: Derives the required session keys and macs
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
TLSDeriveKeys( IN PSW2_SESSION_DATA pSessionData )
{
	HCRYPTKEY			hPubKey;
	CHAR				pcLabel[] = TLS_KEY_EXPANSION_LABEL;
	DWORD				ccLabel = sizeof( pcLabel ) - 1;
	BYTE				pbTemp[TLS_RANDOM_SIZE * 2];
	PBYTE				pbKeyMaterial;
	DWORD				cbKeyMaterial;
	DWORD				dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSDeriveKeys" ) ) );

	if( pSessionData->hCSP )
	{
		//
		// client_write_MAC_secret[SecurityParameters.hash_size]
		// server_write_MAC_secret[SecurityParameters.hash_size]
		// client_write_key[SecurityParameters.key_material_length]
		// server_write_key[SecurityParameters.key_material_length]
		// client_write_IV[SecurityParameters.IV_size]
		// server_write_IV[SecurityParameters.IV_size]
		//
		cbKeyMaterial = ( pSessionData->dwMacKeySize + pSessionData->dwEncKeySize + 8 ) * 2;

		if( ( pbKeyMaterial = ( PBYTE ) malloc( cbKeyMaterial ) ) )
		{
			//
			// key_block = PRF(SecurityParameters.master_secret,
			//                  "key expansion",
			//					SecurityParameters.server_random +
			//					SecurityParameters.client_random);

			memcpy( pbTemp, pSessionData->pbRandomServer, TLS_RANDOM_SIZE );
			memcpy( pbTemp + TLS_RANDOM_SIZE, pSessionData->pbRandomClient, TLS_RANDOM_SIZE );

			if( ( dwRet = TLS_PRF( pSessionData->hCSP, pSessionData->pUserData->pbMS, TLS_MS_SIZE, ( PBYTE ) pcLabel, ccLabel, pbTemp, sizeof( pbTemp ), pbKeyMaterial, cbKeyMaterial ) ) == NO_ERROR )
			{
				AA_TRACE( ( TEXT( "TLSDeriveKeys::pbKeyMaterial(%d): %s" ), cbKeyMaterial, AA_ByteToHex( pbKeyMaterial, cbKeyMaterial ) ) );

				//
				// WriteMAC key
				//
				memcpy( pSessionData->pbWriteMAC, pbKeyMaterial, pSessionData->dwMacKeySize );

				//
				// Read MAC key
				//
				memcpy( pSessionData->pbReadMAC, pbKeyMaterial+pSessionData->dwMacKeySize, pSessionData->dwMacKeySize );

				if( CreatePrivateExponentOneKey( pSessionData->hCSP,
													AT_KEYEXCHANGE,
													&hPubKey ) )
				{
					AA_TRACE( ( TEXT( "TLSDeriveKeys::importing write enc key" ) ) );
					AA_TRACE( ( TEXT( "TLSDeriveKeys::pbKeyMaterial(%d): %s" ), pSessionData->dwEncKeySize, AA_ByteToHex( pbKeyMaterial + ( pSessionData->dwMacKeySize * 2 ), pSessionData->dwEncKeySize ) ) );
					AA_TRACE( ( TEXT( "TLSDeriveKeys::IV(%d): %s" ), 8, AA_ByteToHex( pbKeyMaterial + ( ( pSessionData->dwMacKeySize + pSessionData->dwEncKeySize ) * 2 ), 8 ) ) );

					//
					// Write Enc Key
					//
					if( ImportPlainSessionBlob( pSessionData->hCSP, 
												hPubKey, 
												pSessionData->dwEncKey, 
												pbKeyMaterial + ( pSessionData->dwMacKeySize * 2 ), 
												pSessionData->dwEncKeySize,
												&pSessionData->hWriteKey ) )
					{
						//
						// IV
						//
						if( CryptSetKeyParam( pSessionData->hWriteKey,
												KP_IV,
												pbKeyMaterial + ( ( pSessionData->dwMacKeySize + pSessionData->dwEncKeySize ) * 2 ),
												0 ) )
						{
							AA_TRACE( ( TEXT( "TLSDeriveKeys::importing read enc key" ) ) );
							AA_TRACE( ( TEXT( "TLSDeriveKeys::pbKeyMaterial(%d): %s" ), pSessionData->dwEncKeySize, AA_ByteToHex( pbKeyMaterial + ( pSessionData->dwMacKeySize * 2 ) + pSessionData->dwEncKeySize, pSessionData->dwEncKeySize ) ) );
							AA_TRACE( ( TEXT( "TLSDeriveKeys::IV(%d): %s" ), 8, AA_ByteToHex( pbKeyMaterial + ( ( pSessionData->dwMacKeySize + pSessionData->dwEncKeySize ) * 2 ) + 8, 8 ) ) );

							//
							// Read Enc Key
							//
							if( ImportPlainSessionBlob( pSessionData->hCSP, 
														hPubKey, 
														pSessionData->dwEncKey, 
														pbKeyMaterial + ( pSessionData->dwMacKeySize * 2 ) + pSessionData->dwEncKeySize, 
														pSessionData->dwEncKeySize,
														&pSessionData->hReadKey ) )
							{
								//
								// IV
								//
								if( !CryptSetKeyParam( pSessionData->hReadKey,
														KP_IV,
														pbKeyMaterial + ( ( pSessionData->dwMacKeySize + pSessionData->dwEncKeySize ) * 2 ) + 8,
														0 ) )
								{
									dwRet = ERROR_ENCRYPTION_FAILED;
								}
							}
							else
							{
								dwRet = ERROR_ENCRYPTION_FAILED;
							}
						}
						else
						{
							dwRet = ERROR_ENCRYPTION_FAILED;
						}
					}

					CryptDestroyKey( hPubKey );
				}
				else
					dwRet = ERROR_ENCRYPTION_FAILED;
			}

			if( dwRet != NO_ERROR )
			{
				AA_TRACE( ( TEXT( "TLSDeriveKeys::ERROR::%ld" ), GetLastError() ) );
			}

			free( pbKeyMaterial );
		}
	}
	else
	{
		AA_TRACE( ( TEXT( "TLSDeriveKeys::ERROR::no handle to help CSP" ) ) );

		dwRet = ERROR_ENCRYPTION_FAILED;

	}

	AA_TRACE( ( TEXT( "TLSDeriveKeys::returning: %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: AA_VerifyCertificateChain
// Description: Verifies the certificate chain starting with pCertContext
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
AA_VerifyCertificateChain( IN PCCERT_CONTEXT pCertContext )
{
	CERT_CHAIN_PARA				ChainParams;
	PCCERT_CHAIN_CONTEXT		pChainContext;
	CERT_ENHKEY_USAGE			EnhkeyUsage;
	CERT_USAGE_MATCH			CertUsage;  
	DWORD						dwFlags;
	DWORD						dwRet;

	AA_TRACE( ( TEXT( "AA_VerifyCertificateChain()" ) ) );

	dwRet = NO_ERROR;

	//
	// Initialize the certificate chain validation
	//
	EnhkeyUsage.cUsageIdentifier = 0;
	EnhkeyUsage.rgpszUsageIdentifier = NULL;

	CertUsage.dwType = USAGE_MATCH_TYPE_AND;
	CertUsage.Usage  = EnhkeyUsage;

	// 
	// added 17 June 2003, Tom Rixom
	// Set all options to 0 but set the ChainParams.dwUrlRetrievalTimeout to 1
	// If ChainParams.dwUrlRetrievalTimeout is not set to 1 then url checking will take forever!
	// also set dwFlags to only check the cached URLS for revocation and chain checking
	//

	memset( &ChainParams, 0, sizeof( CERT_CHAIN_PARA ) );

#ifndef _WIN32_WCE
	ChainParams.dwUrlRetrievalTimeout = 1;
#endif
	
	ChainParams.cbSize = sizeof( CERT_CHAIN_PARA );
	ChainParams.RequestedUsage = CertUsage;

	dwFlags =	CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL |
				CERT_CHAIN_CACHE_END_CERT;
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
		AA_TRACE( ( TEXT( "AA_VerifyCertificateChain() ), Created pChainContext" ) ) );

		if( pChainContext->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR )
		{
			AA_TRACE( ( TEXT( "AA_VerifyCertificateChain(), chain could not be validated( %x )" ), pChainContext->TrustStatus.dwErrorStatus ) );

#ifdef _WIN32_WCE
		if( pChainContext->TrustStatus.dwErrorStatus != CERT_TRUST_IS_OFFLINE_REVOCATION )
			dwRet = SEC_E_UNTRUSTED_ROOT;
#else
			dwRet = SEC_E_UNTRUSTED_ROOT;
#endif // _WIN32_WCE
		}

		AA_TRACE( ( TEXT( "AA_VerifyCertificateChain(), freeing pChainContext" ) ) );

		CertFreeCertificateChain( pChainContext );
	}
	else
	{
		AA_TRACE( ( TEXT( "AA_VerifyCertificateChain(), CertGetCertificateChain(), FAILED: %x" ), GetLastError() ) );

		dwRet = ERROR_INTERNAL_ERROR;
	}

	AA_TRACE( ( TEXT( "AA_VerifyCertificateChain()::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: AA_VerifyCertificateInStore
// Description: Verifies if the certificate pCertContext is installed 
//				in the local computer store
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
AA_VerifyCertificateInStore( IN PCCERT_CONTEXT pCertContext )
{
	HCRYPTPROV		hCSP;
	HCERTSTORE		hCertStore;
	PCCERT_CONTEXT	pCertContext2;
	WCHAR			*pwcSubjectName, *pwcSubjectName2;
	DWORD			cwcSubjectName, cwcSubjectName2;
	PBYTE			pbMD5, pbMD52;
	DWORD			cbMD5, cbMD52;
	BOOL			bFoundCert;
	DWORD			dwType;
	int				i;
	DWORD			dwErr;
	DWORD			dwRet;

	AA_TRACE( ( TEXT( "AA_VerifyCertificateInStore()" ) ) );

	dwRet = NO_ERROR;

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
				AA_TRACE( ( TEXT( "AA_VerifyCertificateInStore::CryptAcquireContext(NEWKEYSET):: FAILED (%d)" ), GetLastError() ) );

				dwRet = ERROR_ENCRYPTION_FAILED;
			}
		}
		else
		{
			AA_TRACE( ( TEXT( "AA_VerifyCertificateInStore::CryptAcquireContext(0):: FAILED (%d)" ), GetLastError() ) );

			dwRet = ERROR_ENCRYPTION_FAILED;
		}
	}

	if( dwRet == NO_ERROR )
	{
		//
		// Retrieve Subject name of certificate
		//
		if( ( cwcSubjectName  = CertGetNameString( pCertContext,
													CERT_NAME_SIMPLE_DISPLAY_TYPE,
													0,
													&dwType,
													NULL,
													0 ) ) > 0 )
		{
			if( ( pwcSubjectName = ( WCHAR* ) malloc( cwcSubjectName * sizeof( WCHAR ) ) ) )
			{
				if( CertGetNameString( pCertContext,
										CERT_NAME_SIMPLE_DISPLAY_TYPE,
										0,
										&dwType,
										pwcSubjectName,
										cwcSubjectName ) > 0 )
				{
					//
					// Get HASH of certificate
					//
					if( ( dwRet = TLSGetMD5( hCSP, 
											pCertContext->pbCertEncoded, 
											pCertContext->cbCertEncoded, 
											&pbMD5, 
											&cbMD5 ) ) == NO_ERROR )
					{
						if( hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 
														X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
														( HCRYPTPROV ) NULL,
														CERT_SYSTEM_STORE_LOCAL_MACHINE,
														L"MY" ) )
						{
							pCertContext2 = NULL;

							bFoundCert = FALSE;

							while( !bFoundCert &&
									( pCertContext2 = CertEnumCertificatesInStore( hCertStore, pCertContext2 ) ) )
							{
								if( ( cwcSubjectName2  = CertGetNameString( pCertContext2,
																			CERT_NAME_SIMPLE_DISPLAY_TYPE,
																			0,
																			&dwType,
																			NULL,
																			0 ) ) > 0 )
								{
									if( ( pwcSubjectName2 = ( WCHAR* ) malloc( cwcSubjectName2 * sizeof( WCHAR ) ) ) )
									{
										if( CertGetNameString( pCertContext2,
																CERT_NAME_SIMPLE_DISPLAY_TYPE,
																0,
																&dwType,
																pwcSubjectName2,
																cwcSubjectName2 ) > 0 )
										{
											AA_TRACE( ( TEXT( "AA_VerifyCertificateInStore::subject: %ws" ), pwcSubjectName2 ) );

											if( wcscmp( pwcSubjectName, pwcSubjectName2 ) == 0 )
											{
												//
												// Verify HASH of certificate
												//
												if( ( dwRet = TLSGetMD5( hCSP, pCertContext2->pbCertEncoded, pCertContext2->cbCertEncoded, &pbMD52, &cbMD52 ) ) == NO_ERROR )
												{
													bFoundCert = TRUE;

													for( i=0; ( DWORD ) i < cbMD5; i++ )
													{
														if( pbMD5[i] != pbMD52[i] )
														{
															bFoundCert = FALSE;
															break;
														}
													}

													free( pbMD52 );
												}
												else
												{
													AA_TRACE( ( TEXT( "AA_VerifyCertificateInStore:: TLSGetMD52 FAILED: %ld" ), dwRet ) );
												}
											}
										}
										else
										{
											dwRet = ERROR_CANTOPEN;
										}

										free( pwcSubjectName2 );
										cwcSubjectName2 = 0;
									}
									else
									{
										dwRet = ERROR_NOT_ENOUGH_MEMORY;
									}
								}
								else
								{
									dwRet = ERROR_CANTOPEN;
								}
							}

							if( pCertContext2 )
								CertFreeCertificateContext( pCertContext2 );
							//
							// Did we find anything?
							//
							if( !bFoundCert )
								dwRet = ERROR_NO_DATA;

							CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );
						}
						else
						{
							dwRet = ERROR_CANTOPEN;
						}

						free( pbMD5 );
					}
					else
					{
						AA_TRACE( ( TEXT( "AA_VerifyCertificateInStore:: TLSGetMD5 FAILED: %ld" ), dwRet ) );
					}
				}
				else
					dwRet = ERROR_CANTOPEN;

				free( pwcSubjectName );
				cwcSubjectName = 0;
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		else
			dwRet = ERROR_CANTOPEN;

		CryptReleaseContext( hCSP, 0 );
	}

	AA_TRACE( ( TEXT( "AA_VerifyCertificateInStore()::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: AA_CertGetTrustedRootCAList
// Description: Fill list box with trusted (by SecureW2) root CA list
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
AA_CertGetTrustedRootCAList( HWND hWnd, 
							BYTE pbTrustedCAList[AA_MAX_CA][20], 
							DWORD dwNrOfTrustedRootCAInList )
{
	HCRYPTPROV		hCSP;
	HCERTSTORE		hCertStore;
	PCCERT_CONTEXT	pCertContext = NULL;
	WCHAR			*pwcSubjectName;
	DWORD			cwcSubjectName;
	DWORD			dwType;
	DWORD			dwSelected = 0;
	PBYTE			pbSHA;
	DWORD			cbSHA;
	DWORD			dwErr;
	DWORD			i = 1;
	DWORD			j = 0;
	DWORD			dwRet;

	AA_TRACE( ( TEXT( "AA_CertGetTrustedCAList()" ) ) );

	dwRet = NO_ERROR;

	SendMessage( hWnd, 
				LB_RESETCONTENT, 
				0, 
				0 ); 

	//
	// Nothing to display then return nothing
	//
	if( dwNrOfTrustedRootCAInList == 0 )
		return dwRet;

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
				AA_TRACE( ( TEXT( "AA_CertGetTrustedCAList::CryptAcquireContext(NEWKEYSET):: FAILED (%d)" ), GetLastError() ) );

				dwRet = ERROR_ENCRYPTION_FAILED;
			}
		}
		else
		{
			AA_TRACE( ( TEXT( "AA_CertGetTrustedCAList::CryptAcquireContext(0):: FAILED (%d)" ), GetLastError() ) );

			dwRet = ERROR_ENCRYPTION_FAILED;
		}
	}

	if( dwRet == NO_ERROR )
	{
		if( hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 
										X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
										( HCRYPTPROV ) NULL,
										CERT_SYSTEM_STORE_LOCAL_MACHINE,
										L"ROOT" ) )
		{
			while( ( pCertContext = CertEnumCertificatesInStore( hCertStore,
																pCertContext ) ) )
			{
				if( ( cwcSubjectName  = CertGetNameString( pCertContext,
															CERT_NAME_SIMPLE_DISPLAY_TYPE,
															0,
															&dwType,
															NULL,
															0 ) ) > 0 )
				{
					if( ( pwcSubjectName = ( WCHAR* ) malloc( cwcSubjectName * sizeof( WCHAR ) ) ) )
					{
						if( CertGetNameString( pCertContext,
												CERT_NAME_SIMPLE_DISPLAY_TYPE,
												0,
												&dwType,
												pwcSubjectName,
												cwcSubjectName ) > 0 )
						{
							AA_TRACE( ( TEXT( "AA_CertGetTrustedCAList::pwcSubjectName: %s" ), pwcSubjectName ) );

							//
							// Get HASH of certificate
							//
							if( ( dwRet = TLSGetSHA1( hCSP, 
														pCertContext->pbCertEncoded, 
														pCertContext->cbCertEncoded, 
														&pbSHA, &cbSHA ) ) == NO_ERROR )
							{
								//
								// Only add the certificates that we trust
								//
								AA_TRACE( ( TEXT( "AA_CertGetTrustedCAList::dwNrOfTrustedRootCAInList: %ld" ), dwNrOfTrustedRootCAInList ) );

								for( j=0; j < dwNrOfTrustedRootCAInList; j++ )
								{
									if( memcmp( pbTrustedCAList[j], pbSHA, sizeof( pbSHA ) ) == 0 )
									{
										//
										// Add certificate name
										//
										dwSelected = ( DWORD ) SendMessage( 
																hWnd, 
																LB_ADDSTRING, 
																0, 
																( LPARAM ) pwcSubjectName );

										//
										// Add list number
										//
										SendMessage( hWnd,
													LB_SETITEMDATA,
													dwSelected,
													( LPARAM ) i );

										j = dwNrOfTrustedRootCAInList;
									}
								}

								free( pbSHA );
							}
							else
							{
								AA_TRACE( ( TEXT( "AA_CertGetTrustedCAList:: TLSGetSHA1 FAILED: %ld" ), dwRet ) );
							}
						}
						else
						{
							dwRet = ERROR_CANTOPEN;
						}

						free( pwcSubjectName );
						cwcSubjectName = 0;
					}
					else
						dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}
				else
					dwRet = ERROR_CANTOPEN;

				i++;
			}

			if( pCertContext )
				CertFreeCertificateContext( pCertContext );

			CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );
		}
		else
			dwRet = ERROR_CANTOPEN;

		CryptReleaseContext( hCSP, 0 );
	}

	AA_TRACE( ( TEXT( "AA_CertGetTrustedCAList()::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: AA_CertGetRootCAList
// Description: Fill list box with windows root CA list
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
AA_CertGetRootCAList( IN HWND hWnd,
						IN BYTE pbTrustedRootCAList[AA_MAX_CA][20],
						IN DWORD dwNrOfTrustedRootCAInList )
{
	HCRYPTPROV		hCSP;
	HCERTSTORE		hCertStore;
	PCCERT_CONTEXT	pCertContext = NULL;
	WCHAR			*pwcSubjectName;
	DWORD			cwcSubjectName;
	DWORD			dwType;
	DWORD			dwSelected;
	PBYTE			pbSHA1;
	DWORD			cbSHA1;
	BOOL			bFoundCert;
	DWORD			i = 1;
	DWORD			j = 0;
	DWORD			dwErr;
	DWORD			dwRet;

	AA_TRACE( ( TEXT( "AA_CertGetRootCAList()" ) ) );

	dwRet = NO_ERROR;

	SendMessage( hWnd, 
				LB_RESETCONTENT, 
				0, 
				0 ); 

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
				AA_TRACE( ( TEXT( "AA_CertGetRootCAList::CryptAcquireContext(NEWKEYSET):: FAILED (%d)" ), GetLastError() ) );

				dwRet = ERROR_ENCRYPTION_FAILED;
			}
		}
		else
		{
			AA_TRACE( ( TEXT( "AA_CertGetRootCAList::CryptAcquireContext(0):: FAILED (%d)" ), GetLastError() ) );

			dwRet = ERROR_ENCRYPTION_FAILED;
		}
	}

	if( dwRet == NO_ERROR )
	{
		if( hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 
										X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
										( HCRYPTPROV ) NULL,
										CERT_SYSTEM_STORE_LOCAL_MACHINE,
										L"ROOT" ) )
		{
			while( ( pCertContext = CertEnumCertificatesInStore( hCertStore,
																pCertContext ) ) )
			{
				//
				// First check if we have already got this CA in our trusted list
				//
				if( ( dwRet = TLSGetSHA1( hCSP, 
											pCertContext->pbCertEncoded, 
											pCertContext->cbCertEncoded, 
											&pbSHA1, 
											&cbSHA1 ) ) == NO_ERROR )
				{
					bFoundCert = FALSE;

					for( j=0; j< dwNrOfTrustedRootCAInList; j++ )
					{
						if( memcmp( pbTrustedRootCAList[j], 
									pbSHA1, 
									sizeof( pbTrustedRootCAList[j] ) ) == 0 )
						{
							bFoundCert = TRUE;

							j = dwNrOfTrustedRootCAInList;
						}
					}

					if( !bFoundCert )
					{
						if( ( cwcSubjectName  = CertGetNameString( pCertContext,
																	CERT_NAME_SIMPLE_DISPLAY_TYPE,
																	0,
																	&dwType,
																	NULL,
																	0 ) ) > 0 )
						{
							if( ( pwcSubjectName = ( WCHAR* ) malloc( cwcSubjectName * sizeof( WCHAR ) ) ) )
							{
								if( CertGetNameString( pCertContext,
														CERT_NAME_SIMPLE_DISPLAY_TYPE,
														0,
														&dwType,
														pwcSubjectName,
														cwcSubjectName ) > 0 )
								{
									AA_TRACE( ( TEXT( "AA_CertGetRootCAList::pwcSubjectName: %s" ), pwcSubjectName ) );

									//
									// Add certificate name
									//
									dwSelected = ( DWORD ) SendMessage( hWnd, 
																LB_ADDSTRING, 
																0, 
																( LPARAM ) pwcSubjectName );

									SendMessage( hWnd,
												LB_SETITEMDATA,
												dwSelected,
												( LPARAM ) i );

									AA_TRACE( ( TEXT( "AA_CertGetRootCAList::LB_SETITEMDATA: %ld" ), i ) );
								}

								free( pwcSubjectName );
								cwcSubjectName = 0;
							}
							else
								dwRet = ERROR_NOT_ENOUGH_MEMORY;
						}
						else
							dwRet = ERROR_CANTOPEN;
					}

					i++;
				}
				else
				{
					AA_TRACE( ( TEXT( "AA_CertGetRootCAList:: TLSGetSHA1 FAILED: %ld" ), dwRet ) );
				}

				
			}

			if( pCertContext )
				CertFreeCertificateContext( pCertContext );

			CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );
		}
		else
			dwRet = ERROR_CANTOPEN;

		CryptReleaseContext( hCSP, 0 );
	}

	AA_TRACE( ( TEXT( "AA_CertGetRootCAList()::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: AA_CertGetRootCAList
// Description: Remove trusted Root CA from array
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
AA_CertRemoveTrustedRootCA( IN DWORD dwSelected, 
						IN OUT BYTE pbTrustedRootCA[AA_MAX_CA][20], 
						IN OUT DWORD *pdwNrOfTrustedCAInList )
{
	HCRYPTPROV		hCSP;
	HCERTSTORE		hCertStore;
	PCCERT_CONTEXT	pCertContext = NULL;
	PBYTE			pbSHA1;
	DWORD			cbSHA1;
	DWORD			dwErr;
	BOOL			bFoundCert;
	DWORD			i = 1;
	DWORD			j = 0;
	DWORD			dwRet;

	AA_TRACE( ( TEXT( "AA_CertRemoveTrustedRootCA()" ) ) );

	dwRet = NO_ERROR;

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
				AA_TRACE( ( TEXT( "AA_CertRemoveTrustedRootCA::CryptAcquireContext(NEWKEYSET):: FAILED (%d)" ), GetLastError() ) );

				dwRet = ERROR_ENCRYPTION_FAILED;
			}
		}
		else
		{
			AA_TRACE( ( TEXT( "AA_CertRemoveTrustedRootCA::CryptAcquireContext(0):: FAILED (%d)" ), GetLastError() ) );

			dwRet = ERROR_ENCRYPTION_FAILED;
		}
	}

	if( dwRet == NO_ERROR )
	{
		if( hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 
										X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
										( HCRYPTPROV ) NULL,
										CERT_SYSTEM_STORE_LOCAL_MACHINE,
										L"ROOT" ) )
		{
			AA_TRACE( ( TEXT( "AA_CertRemoveTrustedRootCA:: looking for %ld" ), dwSelected ) );

			while( ( pCertContext = CertEnumCertificatesInStore( hCertStore,
																pCertContext ) ) )
			{
				if( dwSelected == i )
				{
					//
					// Get HASH of certificate
					//
					if( ( dwRet = TLSGetSHA1( hCSP, 
												pCertContext->pbCertEncoded, 
												pCertContext->cbCertEncoded, 
												&pbSHA1, &cbSHA1 ) ) == NO_ERROR )
					{
						//
						// Look through list remove certificate and rebuild list
						//
						bFoundCert = FALSE;

						for( j = 0; j < *pdwNrOfTrustedCAInList; j++ )
						{
							AA_TRACE( ( TEXT( "AA_CertRemoveTrustedRootCA:: Certificate.%ld: %s" ), j, AA_ByteToHex( pbTrustedRootCA[j], 20 ) ) );

							if( bFoundCert )
							{
								//
								// Rebuild rest of list if necessary
								//
								AA_TRACE( ( TEXT( "AA_CertRemoveTrustedRootCA:: copying " ), j ) );

								memcpy( pbTrustedRootCA[j-1], pbTrustedRootCA[j], sizeof( pbTrustedRootCA[j-1] ) );
							}
							else if( memcmp( pbTrustedRootCA[j], pbSHA1, cbSHA1 ) == 0 )
							{
								AA_TRACE( ( TEXT( "AA_CertRemoveTrustedRootCA:: found certificate: %ld" ), j ) );

								bFoundCert = TRUE;
							}
							
							if( j == *pdwNrOfTrustedCAInList )
							{
								memset( pbTrustedRootCA[j], 0, 20 );
							}
						}

						if( bFoundCert )
							*pdwNrOfTrustedCAInList = *pdwNrOfTrustedCAInList - 1;

						AA_TRACE( ( TEXT( "AA_CertRemoveTrustedRootCA:: dwNrOfTrustedCAInList: %ld" ), *pdwNrOfTrustedCAInList ) );

						free( pbSHA1 );
					}
					else
					{
						AA_TRACE( ( TEXT( "AA_CertRemoveTrustedRootCA:: TLSGetSHA1 FAILED: %ld" ), dwRet ) );
					}
				}

				i++;
			}

			if( pCertContext )
				CertFreeCertificateContext( pCertContext );

			CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );
		}
		else
			dwRet = ERROR_CANTOPEN;

		CryptReleaseContext( hCSP, 0 );
	}

	AA_TRACE( ( TEXT( "AA_CertRemoveTrustedRootCA()::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: AA_CertGetRootCAList
// Description: Add trusted Root CA to array
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
AA_CertAddTrustedRootCA( IN DWORD dwSelected, 
						IN OUT BYTE pbTrustedRootCA[AA_MAX_CA][20], 
						IN OUT DWORD *pdwNrOfTrustedCAInList )
{
	HCRYPTPROV		hCSP;
	HCERTSTORE		hCertStore;
	PCCERT_CONTEXT	pCertContext = NULL;
	PBYTE			pbSHA1;
	DWORD			cbSHA1;
	DWORD			dwErr;
	DWORD			i = 1;
	DWORD			dwRet;

	AA_TRACE( ( TEXT( "AA_CertAddTrustedCA()" ) ) );

	dwRet = NO_ERROR;

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
		if( hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 
										X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
										( HCRYPTPROV ) NULL,
										CERT_SYSTEM_STORE_LOCAL_MACHINE,
										L"ROOT" ) )
		{
			AA_TRACE( ( TEXT( "AA_CertAddTrustedCA:: looking for %ld" ), dwSelected ) );

			while( ( pCertContext = CertEnumCertificatesInStore( hCertStore,
																pCertContext ) ) )
			{
				if( dwSelected == i )
				{
					//
					// Get HASH of certificate
					//
					if( ( dwRet = TLSGetSHA1( hCSP, 
												pCertContext->pbCertEncoded, 
												pCertContext->cbCertEncoded, 
												&pbSHA1, &cbSHA1 ) ) == NO_ERROR )
					{
						memcpy( pbTrustedRootCA[*pdwNrOfTrustedCAInList ], pbSHA1, cbSHA1 );

						*pdwNrOfTrustedCAInList = *pdwNrOfTrustedCAInList + 1;

						free( pbSHA1 );
					}
					else
					{
						AA_TRACE( ( TEXT( "AA_CertAddTrustedCA:: TLSGetMD5 FAILED: %ld" ), dwRet ) );
					}
				}

				i++;
			}

			if( pCertContext )
				CertFreeCertificateContext( pCertContext );

			CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );
		}
		else
			dwRet = ERROR_CANTOPEN;

		CryptReleaseContext( hCSP, 0 );
	}

	AA_TRACE( ( TEXT( "AA_CertAddTrustedCA()::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: AA_CertCheckEnhkeyUsage
// Description: Check the certificate pCertContext for the following OIDs:
//				EnhancedKeyUsage: ServerAuthentication("1.3.6.1.5.5.7.3.1"): szOID_PKIX_KP_SERVER_AUTH
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
AA_CertCheckEnhkeyUsage( PCCERT_CONTEXT pCertContext )
{
	PCERT_ENHKEY_USAGE	pbEnhkeyUsage;
	DWORD				cbEnhkeyUsage;
	int					i = 0;
	DWORD				dwRet;

	AA_TRACE( ( TEXT( "AA_CertCheckEnhkeyUsage()" ) ) );

	dwRet = NO_ERROR;

	//
	// Check for the EnhancedKeyUsage: ServerAuthentication("1.3.6.1.5.5.7.3.1"): szOID_PKIX_KP_SERVER_AUTH
	//
	cbEnhkeyUsage = 0;

	if( CertGetEnhancedKeyUsage( pCertContext,
								CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,
								NULL,
								&cbEnhkeyUsage ) )
	{
		if( ( pbEnhkeyUsage = ( PCERT_ENHKEY_USAGE ) malloc( cbEnhkeyUsage ) ) )
		{
			if( CertGetEnhancedKeyUsage( pCertContext,
										CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG ,
										pbEnhkeyUsage,
										&cbEnhkeyUsage ) )
			{
				dwRet = CERT_E_WRONG_USAGE;

				//
				// Found some enhanced key usages, loop through them to find the correct one
				//
				for( i = 0; i < ( int ) pbEnhkeyUsage->cUsageIdentifier; i++ )
				{
					if( strcmp( pbEnhkeyUsage->rgpszUsageIdentifier[i], szOID_PKIX_KP_SERVER_AUTH ) == 0 ) 
					{
						AA_TRACE( ( TEXT( "AA_CertCheckEnhkeyUsage(), certificate contains the correct Enhanced Key Usage" ) ) );

						dwRet = NO_ERROR;
					}
				}
			}
			else
			{
				AA_TRACE( ( TEXT( "AA_CertCheckEnhkeyUsage(), CertGetEnhancedKeyUsage2(), FAILED: %x" ), GetLastError() ) );

				dwRet = ERROR_INTERNAL_ERROR;
			}

			AA_TRACE( ( TEXT( "AA_CertCheckEnhkeyUsage(), freeing pbEnhkeyUsage" ) ) );

			free( pbEnhkeyUsage );
		}
		else
		{
			AA_TRACE( ( TEXT( "AA_CertCheckEnhkeyUsage(), could not allocate memory for pbEnhkeyUsage" ) ) );

			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
	}
	else
	{
		AA_TRACE( ( TEXT( "AA_CertCheckEnhkeyUsage(), CertGetEnhancedKeyUsage(), FAILED: %x" ), GetLastError() ) );

		dwRet = ERROR_INTERNAL_ERROR;
	}

	AA_TRACE( ( TEXT( "AA_CertCheckEnhkeyUsage(), returning %d" ), dwRet ) );

	return dwRet;
}

//
// Name: MakeMPPEKey
// Description: Creates the MPPE Keys needed for line encryption
// Author: Tom Rixom
// Created: 12 May 2004
//
DWORD
MakeMPPEKey(	IN HCRYPTPROV					hCSP,
				IN PBYTE						pbRandomClient,
				IN PBYTE						pbRandomServer,
				IN PBYTE						pbMS,
				IN OUT RAS_AUTH_ATTRIBUTE 		**ppUserAttributes )
{
	CHAR				pcLabel[] = EAP_KEYING_MATERIAL_LABEL;
	DWORD				ccLabel = sizeof( pcLabel ) - 1;
	PBYTE				pb;
	BYTE				pbClientServerRandom[TLS_RANDOM_SIZE*2];
	BYTE				pbKeyMaterial[TLS_RANDOM_SIZE*2];
	DWORD				cbKeyMaterial = sizeof( pbKeyMaterial );
	DWORD				dwRet;

	AA_TRACE( ( TEXT( "MakeMPPEKey" ) ) );

	dwRet = NO_ERROR;

	if( hCSP )
	{
		memset( pbClientServerRandom, 0, TLS_RANDOM_SIZE * 2 );
		memcpy( pbClientServerRandom, pbRandomClient, TLS_RANDOM_SIZE );
		memcpy( &( pbClientServerRandom[TLS_RANDOM_SIZE] ), pbRandomServer, TLS_RANDOM_SIZE );

		AA_TRACE( ( TEXT( "MakeMPPEKey::pbClientServerRandom(%d):%s" ), TLS_RANDOM_SIZE * 2, AA_ByteToHex( pbClientServerRandom, TLS_RANDOM_SIZE * 2 ) ) );

		AA_TRACE( ( TEXT( "MakeMPPEKey::pbMS(%d):%s" ), TLS_MS_SIZE, AA_ByteToHex( pbMS, TLS_MS_SIZE ) ) );

		if( ( dwRet = TLS_PRF( hCSP, 
								pbMS, 
								TLS_MS_SIZE, 
								pcLabel, 
								ccLabel, 
								pbClientServerRandom, 
								TLS_RANDOM_SIZE * 2, 
								pbKeyMaterial, 
								cbKeyMaterial ) ) == NO_ERROR )
		{
			AA_TRACE( ( TEXT( "MakeMPPEKey::pbKeyMaterial(%d):%s" ), cbKeyMaterial, AA_ByteToHex( pbKeyMaterial, cbKeyMaterial ) ) );

			//
			// Copy the Read and Write keys into the radus attributes
			//
			//
			// Create the MPPE Struct:
			if( ( *ppUserAttributes = ( RAS_AUTH_ATTRIBUTE * ) malloc( sizeof( RAS_AUTH_ATTRIBUTE ) * 3 ) ) )
			{
				//
				//
				// Bytes needed:
				//      4: Vendor-Id
				//      1: Vendor-Type
				//      1: Vendor-Length
				//      2: Salt
				//      1: Key-Length
				//     32: Key
				//     15: Padding
				//     -----------------
				//     56: Total
				//


				//
				// Copy MS-MPPE-Send-Key
				//
				if( ( ( *ppUserAttributes )[0].Value = ( PBYTE ) malloc( 56 ) ) )
				{
					memset( ( *ppUserAttributes )[0].Value, 0, 56 );

					pb = ( *ppUserAttributes )[0].Value;

					AA_HostToWireFormat32( 311, pb);	// Vendor-Id
					pb[4] = 16;							// Vendor-Type (MS-MPPE-Send-Key)
					pb[5] = 56 - 4;						// Vendor-Length (all except Vendor-Id)
					// pByte[6-7] is the zero-filled salt field
					pb[8] = 32;							// Key-Length

					memcpy(pb + 9, pbKeyMaterial, 32);

					// pByte[41-55] is the Padding (zero octets)

					( *ppUserAttributes )[0].dwLength = 56;
					( *ppUserAttributes )[0].raaType  = raatVendorSpecific;

					//
					// Copy MS-MPPE-Recv-Key
					//
					if( ( ( *ppUserAttributes )[1].Value = ( PBYTE ) malloc( 56 ) ) )
					{
						memset( ( *ppUserAttributes )[1].Value, 0, 56 );

						pb = ( *ppUserAttributes )[1].Value;

						AA_HostToWireFormat32(311, pb); // Vendor-Id
						pb[4] = 17;                  // Vendor-Type (MS-MPPE-Recv-Key)
						pb[5] = 56 - 4;              // Vendor-Length (all except Vendor-Id)
						// pByte[6-7] is the zero-filled salt field
						pb[8] = 32;                  // Key-Length

						memcpy( pb + 9, pbKeyMaterial+32, 32);

						// pByte[41-55] is the Padding (zero octets)

						( *ppUserAttributes )[1].dwLength = 56;
						( *ppUserAttributes )[1].raaType  = raatVendorSpecific;

						//
						// For Termination
						//
						( *ppUserAttributes )[2].raaType  = raatMinimum;
						( *ppUserAttributes )[2].dwLength = 0;
						( *ppUserAttributes )[2].Value    = NULL;
					}
					else
					{
						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}

					if( dwRet != NO_ERROR )
						free( ( *ppUserAttributes )[0].Value );
				}

				if( dwRet != NO_ERROR )
					free( *ppUserAttributes );
			}
			else
			{
				dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
	}
	else
	{
		AA_TRACE( ( TEXT( "MakeMPPEKey::ERROR::no handle to help CSP" ) ) );

		dwRet = ERROR_ENCRYPTION_FAILED;
	}

	AA_TRACE( ( TEXT( "MakeMPPEKey::returning error: %x" ), dwRet ) );

	return dwRet;
}

DWORD
AA_VerifyCertificateInList( IN PSW2_SESSION_DATA pSessionData, IN PBYTE pbSHA1 )
{
	DWORD	dwRet;
	DWORD	i;

	dwRet = NO_ERROR;

	dwRet = ERROR_INVALID_DOMAINNAME;

	AA_TRACE( ( TEXT( "AA_VerifyCertificateInList" ) ) );

	AA_TRACE( ( TEXT( "AA_VerifyCertificateInList:: nr of ca in list: %ld" ), pSessionData->pProfileData->dwNrOfTrustedRootCAInList ) );

	for( i=0; i < pSessionData->pProfileData->dwNrOfTrustedRootCAInList; i++ )
	{
		if( memcmp( pSessionData->pProfileData->pbTrustedRootCAList[i], 
					pbSHA1, 
					sizeof( pSessionData->pProfileData->pbTrustedRootCAList[i] ) ) == 0 )
		{
			dwRet = NO_ERROR;

			i = pSessionData->pProfileData->dwNrOfTrustedRootCAInList;
		}
	}

	AA_TRACE( ( TEXT( "AA_VerifyCertificateInList:: returning %ld" ), dwRet ) );

	return dwRet;
}