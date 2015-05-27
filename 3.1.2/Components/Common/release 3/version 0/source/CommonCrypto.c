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
// Name: CommonCrypto.c
// Description: Contains the common crypto functionality for the module
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
#include "Common.h"

//
// Name: AA_GenSecureRandom
// Description: Generate secure random data
// Author: Tom Rixom
// Created: 03 October 2005
//
DWORD
AA_GenSecureRandom( PBYTE pbRandom, DWORD cbRandom )
{
	DWORD		dwRet;
	HCRYPTPROV	hCSP;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "AA_GenSecureRandom(%d)" ), cbRandom ) );

	if( ( dwRet = AA_CryptAcquireContext( &hCSP, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL ) ) == NO_ERROR )
	{
		if( !CryptGenRandom( hCSP,
							cbRandom,
							pbRandom ) )
		{
			AA_TRACE( ( TEXT( "AA_GenSecureRandom::CryptGenRandom Failed: %ld, %ld" ), dwRet, GetLastError() ) );

			dwRet = ERROR_ENCRYPTION_FAILED;
		}

		CryptReleaseContext( hCSP, 0 );
	}

	return dwRet;
}

//
// Name: AA_CryptAcquireContext
// Description: Function used to acquire a connection to a CSP.
//				Also deals with the Microsoft Windows CE Bug that prevents 
//				keys from being used after an update
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
AA_CryptAcquireContext( HCRYPTPROV *phCSP, 
						WCHAR *pwcContainer,
						WCHAR *pwcCSPName, 
						DWORD dwType )
{
	DWORD	dwErr;
	DWORD	dwRet;

	dwRet = NO_ERROR;

	//
	// Connect to help CSP
	//
	if( !CryptAcquireContext( phCSP,
								pwcContainer,
								pwcCSPName,
								dwType,
								0 ) )
	{
		dwErr = GetLastError();

		if( dwErr == NTE_BAD_KEYSET )
		{
			//
			// Key is invalid, try to make a new one
			//
			if( !CryptAcquireContext( phCSP,
									pwcContainer,
									pwcCSPName,
									dwType,
									CRYPT_NEWKEYSET ) )
			{
				dwErr = GetLastError();

				if( dwErr == NTE_EXISTS )
				{
					//
					// Key is corrupt, silly microsoft...
					// Let's delete it and make a new one ;)
					//
					if( CryptAcquireContext( phCSP,
											pwcContainer,
											pwcCSPName,
											dwType,
											CRYPT_DELETEKEYSET ) )
					{
						if( !CryptAcquireContext( phCSP,
													pwcContainer,
													pwcCSPName,
													dwType,
													CRYPT_NEWKEYSET ) )
						{
							AA_TRACE( ( TEXT( "AA_CryptAcquireContext::CryptAcquireContext(NEWKEYSET):: FAILED (%d)" ), GetLastError() ) );

							dwRet = ERROR_ENCRYPTION_FAILED;
						}
					}
					else if( wcscmp( pwcContainer, L"SecureW2" ) == 0 )
					{
						dwRet = ERROR_ENCRYPTION_FAILED;
					}
					else
					{
						AA_TRACE( ( TEXT( "AA_CryptAcquireContext::CryptAcquireContext(CRYPT_DELETEKEYSET):: FAILED (%d)" ), GetLastError() ) );

						//
						// Let's try one more time with a different container 
						// and then throw an error
						//

						if( !pwcContainer )
							dwRet = AA_CryptAcquireContext( phCSP, L"SecureW2", pwcCSPName, dwType );
					}
				}
				else
				{
					AA_TRACE( ( TEXT( "AA_CryptAcquireContext::CryptAcquireContext(NEWKEYSET):: FAILED (%d)" ), dwErr ) );

					dwRet = ERROR_ENCRYPTION_FAILED;
				}
			}
		}
		else
		{
			AA_TRACE( ( TEXT( "AA_CryptAcquireContext::CryptAcquireContext(0):: FAILED (%d)" ), dwErr ) );

			dwRet = ERROR_ENCRYPTION_FAILED;
		}
	}

	return dwRet;
}

//
// Name: AA_CryptAcquireDefaultContext
// Description: Default function used to acquire a connection the MS Enh CSP.
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
AA_CryptAcquireDefaultContext( HCRYPTPROV *phCSP, WCHAR *pwcContainer )
{
	DWORD	dwRet;

	dwRet = NO_ERROR;

	dwRet = AA_CryptAcquireContext( phCSP, pwcContainer, MS_ENHANCED_PROV, PROV_RSA_FULL );

	return dwRet;
}

//
// Name: TLSDecBlock
// Description: Decrypt a encrypted SSL record
//				Padding is not implemented yet
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSDecBlock( 	IN HCRYPTPROV	hCSP,
				IN HCRYPTKEY	hReadKey,
				IN DWORD		dwMacKeySize,
				IN PBYTE		pbEncBlock,
				IN DWORD		cbEncBlock,
				OUT PBYTE		*ppbRecord,
				OUT DWORD		*pcbRecord )
{
	BYTE		bPadding;
	PBYTE		pbDecBlock;
	DWORD		cbDecBlock;
	DWORD		dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSDecBlock::pbEncBlock(%d): %s" ), cbEncBlock, AA_ByteToHex( pbEncBlock, cbEncBlock ) ) );

	if( hCSP )
	{
		cbDecBlock = cbEncBlock;

		if( ( pbDecBlock = ( PBYTE ) malloc( cbDecBlock ) ) )
		{
			AA_TRACE( ( TEXT( "TLSDecBlock::allocated %ld data for pbDecBlock" ), cbDecBlock ) );

			memcpy( pbDecBlock, pbEncBlock, cbDecBlock );

			AA_TRACE( ( TEXT( "TLSDecBlock::copied data for pbDecBlock" ) ) );

			if( CryptDecrypt( hReadKey,
								0,
								FALSE,
								0,
								pbDecBlock,
								&cbDecBlock ) )
			{
				AA_TRACE( ( TEXT( "TLSDecBlock::pbDecBlock(%d): %s" ), cbDecBlock, AA_ByteToHex( pbDecBlock, cbDecBlock ) ) );
				//
				// Strip MAC and padding
				//
				bPadding = ( BYTE ) pbDecBlock[cbDecBlock-1];

				AA_TRACE( ( TEXT( "TLSDecBlock::padding: %d" ), bPadding ) );

				*pcbRecord = cbDecBlock - dwMacKeySize - bPadding -1;

				AA_TRACE( ( TEXT( "TLSDecBlock::padding: %d" ), bPadding ) );

				if( *pcbRecord > 0 )
				{
					//
					// Check padding NOT IMPLEMENTED
					//
/*
#ifdef AA_TRACE
					AA_TRACE( ( TEXT( "TLSDecBlock::looping for %d", ( cbDecBlock - ( DWORD ) bPadding ) );
#endif

					for( i = cbDecBlock; ( DWORD ) i > ( cbDecBlock - ( DWORD ) bPadding ); i-- )
					{
#ifdef AA_TRACE
						AA_TRACE( ( TEXT( "TLSDecBlock::i:%d", i );
#endif

#ifdef AA_TRACE
						AA_TRACE( ( TEXT( "TLSDecBlock::%x", pbDecBlock[i] );
#endif

						if( pbDecBlock[i] != bPadding )
						{
#ifdef AA_TRACE
							AA_TRACE( ( TEXT( "TLSDecBlock::padding failed" );
#endif
							dwRet = ERROR_ENCRYPTION_FAILED;
							i = -1;
						}
					}
*/
					if( dwRet == NO_ERROR )
					{
						if( ( *ppbRecord = ( PBYTE ) malloc( *pcbRecord ) ) )
						{
							memcpy( *ppbRecord, pbDecBlock, *pcbRecord );
						}
						else
						{
							AA_TRACE( ( TEXT( "TLSDecBlock::could not allocate memory for pbDecBlock" ) ) );

							dwRet = ERROR_NOT_ENOUGH_MEMORY;
						}
					}
				}
				else
				{
					AA_TRACE( ( TEXT( "TLSDecBlock::incorrect padding" ) ) );
					
					//
					// padding failed but continue to parse rest of packets
					//
					dwRet = ERROR_PPP_INVALID_PACKET;
				}
			}
			else
			{
				AA_TRACE( ( TEXT( "TLSDecBlock::CryptDecrypt:: FAILED (%d)" ), GetLastError() ) );

				dwRet = ERROR_ENCRYPTION_FAILED;
			}

			free( pbDecBlock );
		}
		else
		{
			AA_TRACE( ( TEXT( "TLSDecBlock::could not allocate memory for pbDecBlock" ) ) );

			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}
	}
	else
	{
		AA_TRACE( ( TEXT( "TLSDecBlock::ERROR::no handle to help CSP" ) ) );

		dwRet = ERROR_ENCRYPTION_FAILED;
	}

		AA_TRACE( ( TEXT( "TLSDecBlock::returning %d" ), dwRet ) );
	
	return dwRet;
}

//
// Name: TLSEncBlock
// Description: Encrypts an SSL record using the specified Keys and MACs
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSEncBlock(	IN HCRYPTPROV	hCSP,
				IN HCRYPTKEY	hWriteKey,
				IN DWORD		dwMacKeySize,
				IN DWORD		dwMacKey,
				IN PBYTE		pbWriteMAC,
				IN OUT DWORD	*pdwSeqNum,
				IN PBYTE		pbData,
				IN DWORD		cbData,
				OUT PBYTE		*ppbEncBlock,
				OUT DWORD		*pcbEncBlock )
{
	CHAR				pbSeqNum[] = {0, 0, 0, 0, 0, 0, 0, 0 };
	PBYTE				pbTemp;
	DWORD				cbTemp;
	BYTE				pbHash[20];
	PBYTE				pbSwapped;
	PBYTE				pbEncBlock;
	DWORD				cbEncBlock;
	BYTE				bPadding;
	DWORD				dwDataLen;
	DWORD				dwRet;
	int					i;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSEncBlock::Data(%d): %s" ), cbData, AA_ByteToHex( pbData, cbData ) ) );

	if( hCSP )
	{
		//
		// Sequence number starts at -1
		// and is incremented before use
		//
		( *pdwSeqNum )++;

		//
		// Hash the seq_num
		//
		AA_HostToWireFormat32( *pdwSeqNum, &( pbSeqNum[4] ) );

		//
		// First calculate the HMAC
		//
		cbTemp = sizeof( pbSeqNum ) + cbData;

		if( ( pbTemp = ( PBYTE ) malloc( cbTemp ) ) )
		{
			memcpy( pbTemp, pbSeqNum, sizeof( pbSeqNum ) );
			memcpy( pbTemp + sizeof( pbSeqNum ), pbData, cbData );

			dwRet = TLS_HMAC( hCSP, 
								dwMacKey, 
								pbWriteMAC, 
								dwMacKeySize, 
								pbTemp, 
								cbTemp, 
								pbHash, 
								dwMacKeySize );

			free( pbTemp );
		}
		else
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
		}

		if( dwRet == NO_ERROR )
		{
			AA_TRACE( ( TEXT( "TLSEncBlock::MAC(%d): %s" ), dwMacKeySize, AA_ByteToHex( pbHash, dwMacKeySize ) ) );

			//
			// Calculate the padding needed
			//
			//
			// Length of block-ciphered struct before padding
			// Length of Content(21-5=16) + MAC + 1(length byte)
			//
			bPadding = ( BYTE ) ( cbData - 5 + dwMacKeySize + 1 ) % 8;

			if( ( int ) bPadding != 0 )
				bPadding = ( BYTE ) ( 8 - ( int ) bPadding );

			AA_TRACE( ( TEXT( "TLSEncBlock::padding(%d)" ), ( int ) bPadding ) );

			//
			// Total length of encrypted block is content(cbData) + MAC + Padding(2) +paddingLength(1)
			//
			cbEncBlock = cbData - 5 + dwMacKeySize + ( ( int ) bPadding ) + 1;

			if( ( pbEncBlock = ( PBYTE ) malloc( cbEncBlock ) ) )
			{
				//
				// Copy the content block
				//
				memcpy( pbEncBlock, pbData + 5, cbData - 5 );

				//
				// Copy the HMAC, swapped because of little endian big endian thing
				//
				if( ( pbSwapped = ( PBYTE ) malloc( dwMacKeySize ) ) )
				{
					AA_SwapArray( pbHash, pbSwapped, dwMacKeySize );

					memcpy( &( pbEncBlock[cbData-5] ), pbHash, dwMacKeySize );

					//
					// The padding
					//
					for( i=0; i < ( int ) bPadding; i++ )
						pbEncBlock[cbData-5+dwMacKeySize+i] = bPadding;

					//
					// Length of padding
					//
					pbEncBlock[cbData-5+dwMacKeySize+( int )bPadding] = bPadding;

					AA_TRACE( ( TEXT( "TLSEncBlock::block(%d): %s" ), cbEncBlock, AA_ByteToHex( pbEncBlock, cbEncBlock ) ) );

					dwDataLen = *pcbEncBlock = cbEncBlock;

					if( ( *ppbEncBlock = ( PBYTE ) malloc( *pcbEncBlock ) ) )
					{
						memcpy( *ppbEncBlock, pbEncBlock, cbEncBlock );

						if( CryptEncrypt( hWriteKey,
											0,
											FALSE,
											0,
											*ppbEncBlock,
											&dwDataLen,
											*pcbEncBlock ) )
						{
							AA_TRACE( ( TEXT( "TLSEncBlock::Encrypted Block(%d): %s" ), *pcbEncBlock, AA_ByteToHex( *ppbEncBlock, *pcbEncBlock ) ) );
						}
						else
						{
							AA_TRACE( ( TEXT( "TLSEncBlock::CryptEncrypt:: FAILED (%d)" ), GetLastError() ) );

							dwRet = ERROR_ENCRYPTION_FAILED;

							free( *ppbEncBlock );
						}
					}
					else
					{
						AA_TRACE( ( TEXT( "TLSEncBlock::ERROR::could not allocate memory for ppbEncPMS" ) ) );

						dwRet = ERROR_NOT_ENOUGH_MEMORY;
					}

					free( pbSwapped );
				}

				free( pbEncBlock );
			}
			else
			{
				AA_TRACE( ( TEXT( "TLSEncBlock::ERROR:could not allocate memory for pbEncBlock" ) ) );

				dwRet = dwRet = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
	}
	else
	{
		AA_TRACE( ( TEXT( "TLSEncBlock::ERROR::no handle to help CSP" ) ) );

		dwRet = ERROR_ENCRYPTION_FAILED;
	}

	AA_TRACE( ( TEXT( "TLSEncBlock::returning %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSGetSHA1
// Description: Creates SHA1 of a message
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSGetSHA1( IN HCRYPTPROV hCSP,
			IN PBYTE pbMsg, 
			IN DWORD cbMsg, 
			OUT PBYTE *ppbSHA1, 
			OUT DWORD *pcbSHA1 )
{
	HCRYPTHASH			hSHA1;
	DWORD				dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSGetSHA1" ) ) );

	if( CryptCreateHash( hCSP,
							CALG_SHA1,
							0,
							0,
							&hSHA1 ) )
	{
		if( CryptHashData( hSHA1,
							( PBYTE ) pbMsg,
							cbMsg,
							0 ) )
		{
			if( CryptGetHashParam( hSHA1, 
									HP_HASHVAL, 
									NULL, 
									pcbSHA1, 
									0 ) )
			{
				if( ( *ppbSHA1 = ( PBYTE ) malloc( *pcbSHA1 ) ) )
				{
					if( CryptGetHashParam( hSHA1, 
											HP_HASHVAL, 
											*ppbSHA1, 
											pcbSHA1, 
											0 ) )
					{
						AA_TRACE( ( TEXT( "TLSGetSHA1::SHA1(%d):%s" ), *pcbSHA1, AA_ByteToHex( *ppbSHA1, *pcbSHA1 ) ) );
					}
					else
					{
						AA_TRACE( ( TEXT( "TLSGetSHA1::CryptGetHashParam2:: FAILED (%d)" ), GetLastError() ) );

						dwRet = ERROR_ENCRYPTION_FAILED;

						free( *ppbSHA1 );
					}
				}
				else
				{
					AA_TRACE( ( TEXT( "TLSGetSHA1::ERROR::could not allocate memory for ppbMD5" ) ) );

					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
			else
			{
				AA_TRACE( ( TEXT( "TLSGetSHA1::CryptGetHashParam1:: FAILED (%d)" ), GetLastError() ) );

				dwRet = ERROR_ENCRYPTION_FAILED;
			}

		}
		else
		{
			AA_TRACE( ( TEXT( "TLSGetSHA1::CryptHashData:: FAILED (%d)" ), GetLastError() ) );

			dwRet = ERROR_ENCRYPTION_FAILED;
		}

		CryptDestroyHash( hSHA1 );
	}
	else
	{
			AA_TRACE( ( TEXT( "TLSGetSHA1::CryptCreateHash(CALG_SHA1):: FAILED (%d)" ), GetLastError() ) );

			dwRet = ERROR_ENCRYPTION_FAILED;
	}

	AA_TRACE( ( TEXT( "TLSGetSHA1::returning" ) ) );

	return dwRet;
}

//
// Name: TLSGetMD5
// Description: Creates MD5 of a message
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSGetMD5( IN HCRYPTPROV hCSP, IN PBYTE pbMsg, IN DWORD cbMsg, OUT PBYTE *ppbMD5, OUT DWORD *pcbMD5 )
{
	HCRYPTHASH			hMD5;
	DWORD				dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "TLSGetMD5" ) ) );

	if( CryptCreateHash( hCSP,
							CALG_MD5,
							0,
							0,
							&hMD5 ) )
	{
		if( CryptHashData( hMD5,
							( PBYTE ) pbMsg,
							cbMsg,
							0 ) )
		{
			if( CryptGetHashParam( hMD5, 
									HP_HASHVAL, 
									NULL, 
									pcbMD5, 
									0 ) )
			{
				if( ( *ppbMD5 = ( PBYTE ) malloc( *pcbMD5 ) ) )
				{
					if( CryptGetHashParam( hMD5, 
											HP_HASHVAL, 
											*ppbMD5, 
											pcbMD5, 
											0 ) )
					{
						AA_TRACE( ( TEXT( "TLSGetMD5::MD5(%d):%s" ), *pcbMD5, AA_ByteToHex( *ppbMD5, *pcbMD5 ) ) );
					}
					else
					{
						AA_TRACE( ( TEXT( "TLSGetMD5::CryptGetHashParam2:: FAILED (%d)" ), GetLastError() ) );

						dwRet = ERROR_ENCRYPTION_FAILED;

						free( *ppbMD5 );
					}
				}
				else
				{
					AA_TRACE( ( TEXT( "TLSGetMD5::ERROR::could not allocate memory for ppbMD5" ) ) );

					dwRet = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
			else
			{
				AA_TRACE( ( TEXT( "TLSGetMD5::CryptGetHashParam1:: FAILED (%d)" ), GetLastError() ) );

				dwRet = ERROR_ENCRYPTION_FAILED;
			}

		}
		else
		{
			AA_TRACE( ( TEXT( "TLSGetMD5::CryptHashData:: FAILED (%d)" ), GetLastError() ) );

			dwRet = ERROR_ENCRYPTION_FAILED;
		}

		CryptDestroyHash( hMD5 );
	}
	else
	{
			AA_TRACE( ( TEXT( "TLSGetMD5::CryptCreateHash(CALG_MD5):: FAILED (%d)" ), GetLastError() ) );

			dwRet = ERROR_ENCRYPTION_FAILED;
	}

	AA_TRACE( ( TEXT( "TLSGetMD5::returning: %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: TLSComputeMS
// Description: Compute the SSL Master Secret
//				Calling this function also removes the PMS from memory
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLSComputeMS(	IN HCRYPTPROV				hCSP,
				IN PBYTE					pbRandomClient,
				IN PBYTE					pbRandomServer,
				IN OUT PBYTE				pbPMS,
				IN OUT PBYTE				pbMS )
{
	CHAR	pcLabel[] = "master secret";
	DWORD	cbLabel = sizeof( pcLabel ) - 1;
	BYTE	pbTemp[TLS_RANDOM_SIZE*2];
	DWORD	dwRet;

	AA_TRACE( ( TEXT( "TLSComputeMS" ) ) );

	dwRet = NO_ERROR;

	memcpy( pbTemp, pbRandomClient, TLS_RANDOM_SIZE );
	memcpy( pbTemp+TLS_RANDOM_SIZE, pbRandomServer, TLS_RANDOM_SIZE );

	AA_TRACE( ( TEXT( "TLSComputeMS::PMS(%ld): %s" ), TLS_PMS_SIZE, AA_ByteToHex( pbPMS, TLS_PMS_SIZE ) ) );

	dwRet = TLS_PRF( hCSP, 
					pbPMS, 
					TLS_PMS_SIZE, 
					( PBYTE ) pcLabel, 
					cbLabel, 
					pbTemp, 
					sizeof( pbTemp ), 
					pbMS, 
					TLS_MS_SIZE );

	AA_TRACE( ( TEXT( "TLSComputeMS: MS(%ld): %s" ), 
				TLS_MS_SIZE, 
				AA_ByteToHex( pbMS, 
				TLS_MS_SIZE ) ) );

	//
	// Get rid of pre master secret
	//
	memset( pbPMS, 0, TLS_PMS_SIZE );

	AA_TRACE( ( TEXT( "TLSComputeMS:: returning: %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: CreatePrivateExponentOneKey
// Description: Helper function for importing the SSL session keys
//				Tricks MS into importing clear text PKCS blobs
// Author: Tom Rixom
// Created: 17 December 2002
//
BOOL 
CreatePrivateExponentOneKey( HCRYPTPROV hProv, 
								  DWORD dwKeySpec,
                                  HCRYPTKEY *hPrivateKey)
{
   BOOL fReturn = FALSE;
   BOOL fResult;
   int n;
   LPBYTE keyblob = NULL;
   DWORD dwkeyblob;
   DWORD dwBitLen;
   BYTE *ptr;

   __try
   {
      *hPrivateKey = 0;

      if ((dwKeySpec != AT_KEYEXCHANGE) && (dwKeySpec != AT_SIGNATURE))  __leave;

	  // Generate the private key
      fResult = CryptGenKey(hProv, dwKeySpec, CRYPT_EXPORTABLE, hPrivateKey);
      if (!fResult) __leave;

      // Export the private key, we'll convert it to a private
      // exponent of one key
      fResult = CryptExportKey(*hPrivateKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwkeyblob);
      if (!fResult) __leave;      

      keyblob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob);
      if (!keyblob) __leave;

      fResult = CryptExportKey(*hPrivateKey, 0, PRIVATEKEYBLOB, 0, keyblob, &dwkeyblob);
      if (!fResult) __leave;


      CryptDestroyKey(*hPrivateKey);
      *hPrivateKey = 0;

      // Get the bit length of the key
      memcpy(&dwBitLen, &keyblob[12], 4);      

      // Modify the Exponent in Key BLOB format
      // Key BLOB format is documented in SDK

      // Convert pubexp in rsapubkey to 1
      ptr = &keyblob[16];
      for (n = 0; n < 4; n++)
      {
         if (n == 0) ptr[n] = 1;
         else ptr[n] = 0;
      }

      // Skip pubexp
      ptr += 4;
      // Skip modulus, prime1, prime2
      ptr += (dwBitLen/8);
      ptr += (dwBitLen/16);
      ptr += (dwBitLen/16);

      // Convert exponent1 to 1
      for (n = 0; ( DWORD ) n < (dwBitLen/16); n++)
      {
         if (n == 0) ptr[n] = 1;
         else ptr[n] = 0;
      }

      // Skip exponent1
      ptr += (dwBitLen/16);

      // Convert exponent2 to 1
      for (n = 0; ( DWORD ) n < (dwBitLen/16); n++)
      {
         if (n == 0) ptr[n] = 1;
         else ptr[n] = 0;
      }

      // Skip exponent2, coefficient
      ptr += (dwBitLen/16);
      ptr += (dwBitLen/16);

      // Convert privateExponent to 1
      for (n = 0; ( DWORD ) n < (dwBitLen/8); n++)
      {
         if (n == 0) ptr[n] = 1;
         else ptr[n] = 0;
      }
      
      // Import the exponent-of-one private key.      
      if (!CryptImportKey(hProv, keyblob, dwkeyblob, 0, 0, hPrivateKey))
      {                 
         __leave;
      }

      fReturn = TRUE;
   }
   __finally
   {
      if (keyblob) LocalFree(keyblob);

      if (!fReturn)
      {
         if (*hPrivateKey) CryptDestroyKey(*hPrivateKey);
      }
   }

   return fReturn;
}

//
// Name: GenerateSessionKeyWithAlgorithm
// Description: Helper function for importing the SSL session keys
// Author: Tom Rixom
// Created: 17 December 2002
//
BOOL 
GenerateSessionKeyWithAlgorithm(HCRYPTPROV hProv, 
                                     ALG_ID Alg,
                                     HCRYPTKEY *hSessionKey)
{   
   BOOL fResult;

   *hSessionKey = 0;

   fResult = CryptGenKey(hProv, Alg, CRYPT_EXPORTABLE, hSessionKey);
   if (!fResult)
   {
      return FALSE;
   }
   
   return TRUE;   
}

//
// Name: DeriveSessionKeyWithAlgorithm
// Description: Helper function for importing the SSL session keys
// Author: Tom Rixom
// Created: 17 December 2002
//
BOOL 
DeriveSessionKeyWithAlgorithm(HCRYPTPROV hProv, 
                                   ALG_ID Alg,
                                   LPBYTE lpHashingData,
                                   DWORD dwHashingData,
                                   HCRYPTKEY *hSessionKey)
{
   BOOL fResult;
   BOOL fReturn = FALSE;
   HCRYPTHASH hHash = 0;

   __try
   {
      *hSessionKey = 0;

      fResult = CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);
      if (!fResult) __leave;

      fResult = CryptHashData(hHash, lpHashingData, dwHashingData, 0);
      if (!fResult) __leave;

      fResult = CryptDeriveKey(hProv, Alg, hHash, CRYPT_EXPORTABLE, hSessionKey);
      if (!fResult) __leave;

      fReturn = TRUE;
   }
   __finally
   {      
      if (hHash) CryptDestroyHash(hHash);
   }

   return fReturn;
}

//
// Name: ExportPlainSessionBlob
// Description: Helper function for exporting the SSL session key
// Author: Tom Rixom
// Created: 17 December 2002
//
BOOL 
ExportPlainSessionBlob(HCRYPTKEY hPublicKey,
                            HCRYPTKEY hSessionKey,
                            LPBYTE *pbKeyMaterial ,
                            DWORD *dwKeyMaterial )
{
   BOOL fReturn = FALSE;
   BOOL fResult;
   DWORD dwSize, n;
   LPBYTE pbSessionBlob = NULL;
   DWORD dwSessionBlob;
   LPBYTE pbPtr;

   __try
   {
      *pbKeyMaterial  = NULL;
      *dwKeyMaterial  = 0;

      fResult = CryptExportKey(hSessionKey, hPublicKey, SIMPLEBLOB,
                               0, NULL, &dwSessionBlob );
      if (!fResult) __leave;

      pbSessionBlob  = (LPBYTE)LocalAlloc(LPTR, dwSessionBlob );
      if (!pbSessionBlob) __leave;

      fResult = CryptExportKey(hSessionKey, hPublicKey, SIMPLEBLOB,
                               0, pbSessionBlob , &dwSessionBlob );
      if (!fResult) __leave;

      // Get session key size in bits
      dwSize = sizeof(DWORD);
      fResult = CryptGetKeyParam(hSessionKey, KP_KEYLEN, (LPBYTE)dwKeyMaterial, &dwSize, 0);
      if (!fResult) __leave;

      // Get the number of bytes and allocate buffer
      *dwKeyMaterial /= 8;
      *pbKeyMaterial = (LPBYTE)LocalAlloc(LPTR, *dwKeyMaterial);
      if (!*pbKeyMaterial) __leave;

      // Skip the header
      pbPtr = pbSessionBlob;
      pbPtr += sizeof(BLOBHEADER);
      pbPtr += sizeof(ALG_ID);

      // We are at the beginning of the key
      // but we need to start at the end since 
      // it's reversed
      pbPtr += (*dwKeyMaterial - 1);
      
      // Copy the raw key into our return buffer      
      for (n = 0; n < *dwKeyMaterial; n++)
      {
         (*pbKeyMaterial)[n] = *pbPtr;
         pbPtr--;
      }      
      
      fReturn = TRUE;
   }
   __finally
   {
      if (pbSessionBlob) LocalFree(pbSessionBlob);

      if ((!fReturn) && (*pbKeyMaterial ))
      {
         LocalFree(*pbKeyMaterial );
         *pbKeyMaterial  = NULL;
         *dwKeyMaterial  = 0;
      }
   }

   return fReturn;
}

//
// Name: ImportPlainSessionBlob
// Description: Helper function for importing the SSL session key
// Author: Tom Rixom
// Created: 17 December 2002
//
BOOL 
ImportPlainSessionBlob(HCRYPTPROV hProv,
                            HCRYPTKEY hPrivateKey,
                            ALG_ID dwAlgId,
                            LPBYTE pbKeyMaterial ,
                            DWORD dwKeyMaterial ,
                            HCRYPTKEY *hSessionKey)
{
	BOOL fResult;   
	BOOL fReturn = FALSE;
	BOOL fFound = FALSE;
	LPBYTE pbSessionBlob = NULL;
	DWORD dwSessionBlob, dwSize, n;
	DWORD dwPublicKeySize;
	DWORD dwProvSessionKeySize;
	ALG_ID dwPrivKeyAlg;
	LPBYTE pbPtr; 
	DWORD dwFlags = CRYPT_FIRST;
	PROV_ENUMALGS_EX ProvEnum;
	HCRYPTKEY hTempKey = 0;

	__try
	{
		// Double check to see if this provider supports this algorithm
		// and key size
		do
		{        
			AA_TRACE( ( TEXT( "CryptGetProvParam" ) ) );

			 dwSize = sizeof(ProvEnum);
			 fResult = CryptGetProvParam(hProv, PP_ENUMALGS_EX, (LPBYTE)&ProvEnum,
										 &dwSize, dwFlags);
			 if (!fResult) break;

			 dwFlags = 0;

			 AA_TRACE( ( TEXT( "dwAlgId:%ld, ProvEnum.aiAlgid: %ld" ), dwAlgId, ProvEnum.aiAlgid ) );

			 if (ProvEnum.aiAlgid == dwAlgId) fFound = TRUE;
                     
		} while (!fFound);

		if (!fFound) __leave;

		AA_TRACE( ( TEXT( "CryptGenKey" ) ) );

		// We have to get the key size(including padding)
		// from an HCRYPTKEY handle.  PP_ENUMALGS_EX contains
		// the key size without the padding so we can't use it.
		fResult = CryptGenKey(hProv, dwAlgId, 0, &hTempKey);

		if( !fResult ) 
			__leave;

		AA_TRACE( ( TEXT( "CryptGetKeyParam::KP_KEYLEN" ) ) );

		dwSize = sizeof(DWORD);

		fResult = CryptGetKeyParam( hTempKey, KP_KEYLEN, ( LPBYTE ) &dwProvSessionKeySize, &dwSize, 0);

		if (!fResult) __leave;      
			CryptDestroyKey(hTempKey);

		hTempKey = 0;

		AA_TRACE( ( TEXT( "dwKeyMaterial: %ld, dwProvSessionKeySize: %ld" ), dwKeyMaterial * 8, dwProvSessionKeySize ) );

		// Our key is too big, leave
		//if ((dwKeyMaterial * 8) > dwProvSessionKeySize) __leave;

		AA_TRACE( ( TEXT( "CryptGetKeyParam::KP_ALGID" ) ) );

		// Get private key's algorithm
		dwSize = sizeof(ALG_ID);
		fResult = CryptGetKeyParam(hPrivateKey, KP_ALGID, (LPBYTE)&dwPrivKeyAlg, &dwSize, 0);
		if (!fResult) __leave;

		AA_TRACE( ( TEXT( "CryptGetKeyParam::KP_KEYLEN" ) ) );

		// Get private key's length in bits
		dwSize = sizeof(DWORD);
		fResult = CryptGetKeyParam(hPrivateKey, KP_KEYLEN, (LPBYTE)&dwPublicKeySize, &dwSize, 0);
		if (!fResult) __leave;

		// calculate Simple blob's length
		dwSessionBlob = (dwPublicKeySize/8) + sizeof(ALG_ID) + sizeof(BLOBHEADER);

		// allocate simple blob buffer
		pbSessionBlob = (LPBYTE)LocalAlloc(LPTR, dwSessionBlob);
		if (!pbSessionBlob) __leave;

		pbPtr = pbSessionBlob;

		AA_TRACE( ( TEXT( "CryptGetKeyParam::SIMPLEBLOB" ) ) );

		// SIMPLEBLOB Format is documented in SDK
		// Copy header to buffer
		((BLOBHEADER *)pbPtr)->bType = SIMPLEBLOB;
		((BLOBHEADER *)pbPtr)->bVersion = 2;
		((BLOBHEADER *)pbPtr)->reserved = 0;
		((BLOBHEADER *)pbPtr)->aiKeyAlg = dwAlgId;
		pbPtr += sizeof(BLOBHEADER);

		// Copy private key algorithm to buffer
		*((DWORD *)pbPtr) = dwPrivKeyAlg;
		pbPtr += sizeof(ALG_ID);

		AA_TRACE( ( TEXT( "reversing" ) ) );

		// Place the key material in reverse order
		for( n = 0; n < dwKeyMaterial; n++ )
		{
			pbPtr[n] = pbKeyMaterial[dwKeyMaterial-n-1];
		}

		// 3 is for the first reserved byte after the key material + the 2 reserved bytes at the end.
		dwSize = dwSessionBlob - (sizeof(ALG_ID) + sizeof(BLOBHEADER) + dwKeyMaterial + 3);
		pbPtr += (dwKeyMaterial+1);

		// Generate random data for the rest of the buffer
		// (except that last two bytes)
		fResult = CryptGenRandom(hProv, dwSize, pbPtr);
		if (!fResult) __leave;

		for (n = 0; n < dwSize; n++)
		{
			if (pbPtr[n] == 0) pbPtr[n] = 1;
		}

		pbSessionBlob[dwSessionBlob - 2] = 2;

		AA_TRACE( ( TEXT( "going to CryptImportKey" ) ) );

		fResult = CryptImportKey(hProv, pbSessionBlob , dwSessionBlob, 
							   hPrivateKey, CRYPT_EXPORTABLE | CRYPT_NO_SALT, hSessionKey);
		if (!fResult) __leave;

		fReturn = TRUE;           
	}
	__finally
	{
		if (hTempKey) CryptDestroyKey(hTempKey);
		if (pbSessionBlob) LocalFree(pbSessionBlob);
	}
   
	return fReturn;
}

//
// Name: TLS_HMAC
// Description: Helper function for implementing TLS according to
//				http://www.ietf.org/rfc/rfc2104.txt
//				Functions are named to mirror function in RFC
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLS_HMAC( HCRYPTPROV hCSP,
			DWORD dwAlgID,
			IN PBYTE pbOrigKey, 
			IN DWORD cbOrigKey, 
			IN PBYTE pbSeed, 
			IN DWORD cbSeed, 
			PBYTE pbData, 
			DWORD cbData )
{
	HCRYPTHASH	hHash;
	PBYTE		pbKey;
	DWORD		cbKey;
	BYTE		pbK_ipad[64];    // inner padding - key XORd with ipad
	BYTE		pbK_opad[64];    // outer padding - key XORd with opad
	BYTE		pbTempKey[20];
	DWORD		cbTempKey;
	int			i;
	DWORD		dwRet;

	dwRet = NO_ERROR;

	if( dwAlgID == CALG_MD5 )
	{
		cbTempKey = 16;
	}
	else if( dwAlgID == CALG_SHA1 )
	{
		cbTempKey = 20;
	}
	else
		return ERROR_NOT_SUPPORTED;
	//
	// if key is longer than 64 bytes reset it to key=MD5(key)
	//
	AA_TRACE( ( TEXT( "TLS_HMAC::pbOrigKey(%ld): %s" ), cbOrigKey, AA_ByteToHex( pbOrigKey, cbOrigKey ) ) );
	AA_TRACE( ( TEXT( "TLS_HMAC::pbSeed(%ld): %s" ), cbSeed, AA_ByteToHex( pbSeed, cbSeed ) ) );

	memset( pbTempKey, 0, sizeof( pbTempKey ) );

	if( cbOrigKey > 64 )
	{
		if( CryptCreateHash( hCSP,
							dwAlgID,
							0,
							0,
							&hHash ) )
		{
			if( CryptHashData( hHash,
								pbOrigKey,
								cbOrigKey,
								0 ) )
			{
				if( CryptGetHashParam( hHash,
											HP_HASHVAL,
											pbTempKey,
											&cbTempKey,
											0 ) )
				{
					pbKey = pbTempKey;
					cbKey = cbTempKey;
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

			CryptDestroyHash( hHash );
		}
		else
		{
			dwRet = ERROR_ENCRYPTION_FAILED;
		}
	}
	else
	{
		pbKey = pbOrigKey;
		cbKey = cbOrigKey;
	}

	if( dwRet == NO_ERROR )
	{

		//
		// the HMAC_MD5 transform looks like:
		//
		// MD5(K XOR opad, MD5(K XOR ipad, text))
		//
		// where K is an n byte key
		// ipad is the byte 0x36 repeated 64 times
		// opad is the byte 0x5c repeated 64 times
		// and text is the data being protected
		//

		//
		// start out by storing key in pads
		//
		memset( pbK_ipad, 0, sizeof( pbK_ipad ) );
		memset( pbK_opad, 0, sizeof( pbK_opad ) );

		memcpy( pbK_ipad, pbKey, cbKey );
		memcpy( pbK_opad, pbKey, cbKey );

		//
		// XOR key with ipad and opad values
		//
		for( i=0; i<64; i++ ) 
		{
			pbK_ipad[i] ^= 0x36;
			pbK_opad[i] ^= 0x5c;
		}

		//
		// perform inner MD5
		//
		if( CryptCreateHash( hCSP,
							dwAlgID,
							0,
							0,
							&hHash ) )
		{
			if( CryptHashData( hHash,
								pbK_ipad,
								sizeof( pbK_ipad ),
								0 ) )
			{
				if( CryptHashData( hHash,
									pbSeed,
									cbSeed,
									0 ) )
				{
					if( !CryptGetHashParam( hHash,
												HP_HASHVAL,
												pbData,
												&cbData,
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

			CryptDestroyHash( hHash );
		}
		else
		{
			dwRet = ERROR_ENCRYPTION_FAILED;
		}

		if( dwRet == NO_ERROR )
		{
			//
			// perform outer MD5
			//
			if( CryptCreateHash( hCSP,
								dwAlgID,
								0,
								0,
								&hHash ) )
			{
				if( CryptHashData( hHash,
									pbK_opad,
									sizeof( pbK_opad ),
									0 ) )
				{
					if( CryptHashData( hHash,
										pbData,
										cbData,
										0 ) )
					{
						if( !CryptGetHashParam( hHash,
													HP_HASHVAL,
													pbData,
													&cbData,
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

				CryptDestroyHash( hHash );
			}
			else
			{
				dwRet = ERROR_ENCRYPTION_FAILED;
			}
		}
	}

	return dwRet;
}

//
// Name: TLS_P_hash
// Description: Helper function for implementing TLS according to
//				http://www.ietf.org/rfc/rfc2104.txt
//				Functions are named to mirror function in RFC
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLS_P_hash( IN HCRYPTPROV hCSP, 
			IN DWORD dwAlgID, 
			IN PBYTE pbSecret,
			IN DWORD cbSecret,
			IN PBYTE pbSeed,
			IN DWORD cbSeed,
			OUT PBYTE pbData, 
			IN DWORD cbData  )
{
	PBYTE		pbTemp;
	DWORD		cbTemp;
	BYTE		pbA[20];
	DWORD		cbA;
//	HCRYPTHASH	hHash;
//	HMAC_INFO	HMAC_Info;
	PBYTE		pbBuf;
	DWORD		cbBuf;
	DWORD		dwMAC;
	DWORD		dwIterations;
	int			i;
    DWORD		dwRet;

	AA_TRACE( ( TEXT( "TLS_P_hash" ) ) );

	dwRet = NO_ERROR;

	if( dwAlgID == CALG_MD5 )
	{
		AA_TRACE( ( TEXT( "TLS_P_hash::CALG_MD5" ) ) );

		dwMAC = 16;
	}
	else if( dwAlgID == CALG_SHA1 )
	{
		AA_TRACE( ( TEXT( "TLS_P_hash::CALG_SHA1" ) ) );

		dwMAC = 20;
	}
	else
		return ERROR_NOT_SUPPORTED;

	cbA = dwMAC;

	dwIterations = cbData / dwMAC;

	dwIterations = cbData % dwMAC == 0 ? dwIterations : dwIterations + 1;

	cbBuf = dwIterations * dwMAC;

	AA_TRACE( ( TEXT( "TLS_P_hash::Secret(%ld): %s" ), cbSecret, AA_ByteToHex( pbSecret, cbSecret ) ) );
	AA_TRACE( ( TEXT( "TLS_P_hash::Seed(%ld): %s" ), cbSeed, AA_ByteToHex( pbSeed, cbSeed ) ) );
	AA_TRACE( ( TEXT( "TLS_P_hash::iterating %ld times" ), dwIterations ) );
	AA_TRACE( ( TEXT( "TLS_P_hash::cbBuf: %ld" ), cbBuf ) );

	//
	// Create temporary buffer, must be at least big enough for dwMAC + cbSeed
	//
	cbTemp = dwMAC + cbSeed;

	if( ( pbTemp = ( PBYTE ) malloc( cbTemp ) ) )
	{
		//
		// Create buffer large enough for required material
		//
		if( ( pbBuf = ( PBYTE ) malloc( cbBuf ) ) )
		{
			memset( pbBuf, 0, cbBuf );

			//
			// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
			//						  HMAC_hash(secret, A(2) + seed) +
			//						  HMAC_hash(secret, A(3) + seed) + ...
			//
			// Where + indicates concatenation.
			//
			// A() is defined as:
			//		A(0) = seed
			//		A(i) = HMAC_hash(secret, A(i-1))
			//

			//
			// A(1) = P_MD5(secret, seed)
			//
			if( ( dwRet = TLS_HMAC( hCSP, dwAlgID, pbSecret, cbSecret, pbSeed, cbSeed, pbA, cbA ) ) == NO_ERROR )
			{
				for( i=0; ( DWORD ) i < dwIterations; i++ )
				{
					AA_TRACE( ( TEXT( "TLS_P_hash::pbA(%ld): %s" ), cbA, AA_ByteToHex( pbA, cbA ) ) );

					//
					// P_MD5(secret, A(i) + seed )
					//
					memset( pbTemp, 0, cbTemp );
					memcpy( pbTemp, pbA, cbA );
					memcpy( pbTemp + cbA, pbSeed, cbSeed );
					cbTemp = cbA + cbSeed;

					AA_TRACE( ( TEXT( "TLS_P_hash::a(0)+seed: %s" ), AA_ByteToHex( pbTemp, cbTemp ) ) );

					if( ( dwRet = TLS_HMAC( hCSP, dwAlgID, pbSecret, cbSecret, pbTemp, cbTemp, pbBuf + ( i * dwMAC ), dwMAC ) ) ==NO_ERROR )
					{
						AA_TRACE( ( TEXT( "TLS_P_hash::pbBuf:%s" ), AA_ByteToHex( pbBuf, cbBuf ) ) );

						//
						// A(i) = P_MD5(secret, a(i-1))
						//
						dwRet = TLS_HMAC( hCSP, dwAlgID, pbSecret, cbSecret, pbA, cbA, pbA, cbA );
					}
		
					if( dwRet != NO_ERROR )
						break;
				} // for

				AA_TRACE( ( TEXT( "TLS_P_hash::out of loop" ) ) );

				//
				// Copy required data
				//
				if( dwRet == NO_ERROR )
				{
					memcpy( pbData, pbBuf, cbData );
				}
			}

			free( pbBuf );
		}

		free( pbTemp );
	}

#ifdef AA_TRACE
	AA_TRACE( ( TEXT( "TLS_P_hash: returning %ld" ), dwRet ) );
#endif

	return dwRet;
}

//
// Name: TLS_PRF
// Description: Helper function for implementing TLS according to
//				http://www.ietf.org/rfc/rfc2104.txt
//				Functions are named to mirror function in RFC
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
TLS_PRF( IN HCRYPTPROV hCSP, 
		IN PBYTE pbSecret,
		IN DWORD cbSecret, 
		IN PBYTE pbLabel, 
		IN DWORD cbLabel, 
		IN PBYTE pbSeed,
		IN DWORD cbSeed,
		IN OUT PBYTE pbData,
		IN DWORD cbData )
{
//	HCRYPTKEY	hPubKey;
//	HCRYPTKEY	hKey1;
//	HCRYPTKEY	hKey2;
	PBYTE		S1, S2;
	DWORD		L_S1, L_S2;
	PBYTE		pbMD5;
	PBYTE		pbSHA1;
	PBYTE		pbTemp;
	DWORD		cbTemp;
	int			i;
	DWORD		dwRet;

	AA_TRACE( ( TEXT( "TLS_PRF" ) ) );

	dwRet = NO_ERROR;

	//
	// Split secret into two halves
	//
	if( cbSecret % 2 == 0 )
	{
		L_S1 = cbSecret / 2;
	}
	else 
	{
		L_S1 = cbSecret / 2 + 1;
	}

	L_S2 = L_S1;

	S1 = pbSecret;

	S2 = pbSecret + L_S1;

	AA_TRACE( ( TEXT( "TLS_PRF: S1(%ld): %s" ), L_S1, AA_ByteToHex( S1, L_S1 ) ) );
	AA_TRACE( ( TEXT( "TLS_PRF: S2(%ld): %s" ), L_S2, AA_ByteToHex( S2, L_S2 ) ) );

	//
	// Create clear exchange key
	//
	cbTemp = cbLabel + cbSeed;

	if( ( pbTemp = ( PBYTE ) malloc( cbTemp ) ) )
	{
		memcpy( pbTemp, pbLabel, cbLabel );
		memcpy( pbTemp + cbLabel, pbSeed, cbSeed );

		if( ( pbMD5 = ( PBYTE ) malloc( cbData ) ) )
		{
			if( ( dwRet = TLS_P_hash( hCSP, CALG_MD5, S1, L_S1, pbTemp, cbTemp, pbMD5, cbData ) ) == NO_ERROR )
			{
				if( ( pbSHA1 = ( PBYTE ) malloc( cbData ) ) )
				{
					if( ( dwRet = TLS_P_hash( hCSP, CALG_SHA1, S2, L_S2, pbTemp, cbTemp, pbSHA1, cbData ) ) == NO_ERROR )
					{
						//
						// Xor
						//
						for( i = 0; ( DWORD ) i < cbData; i ++ )
							pbData[i] = pbMD5[i] ^ pbSHA1[i];
					}

					free( pbSHA1 );
				}
			}

			free( pbMD5 );
		}

		free( pbTemp );
	}

	AA_TRACE( ( TEXT( "TLS_PRF: returning: %ld" ), dwRet ) );

	return dwRet;
}

//
// Name: AA_GetCertificate
// Description: Retreive certificate from store using SHA1 fingerprint
// Author: Tom Rixom
// Created: 17 December 2002
//
DWORD
AA_GetCertificate(	PBYTE pbServerCertSHA1, 
					OUT PCCERT_CONTEXT *ppCertContext )
{
	HCRYPTPROV		hCSP;
	HCERTSTORE		hCertStore;
	WCHAR			*pwcSubjectName;
	DWORD			cwcSubjectName;
	DWORD			dwType;
	PBYTE			pbSHA1;
	DWORD			cbSHA1;
	PCCERT_CONTEXT	pCertContext = NULL;
	DWORD			dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "AA_GetCertificate" ) ) );

	//
	// Connect to help CSP
	//
	if( ( dwRet = AA_CryptAcquireDefaultContext( &hCSP, NULL ) ) == NO_ERROR )
	{
		if( ( hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 
										X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
										( HCRYPTPROV ) NULL,
										CERT_SYSTEM_STORE_LOCAL_MACHINE,
										L"MY" ) ) )
		{
			BOOL	bFoundCert = FALSE;

			while( ( pCertContext = CertEnumCertificatesInStore( hCertStore,
																pCertContext ) ) &&
					bFoundCert == FALSE )
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
							//
							// Get HASH of certificate
							//
							if( ( dwRet = TLSGetSHA1( hCSP, 
														pCertContext->pbCertEncoded, 
														pCertContext->cbCertEncoded, 
														&pbSHA1, 
														&cbSHA1 ) ) == NO_ERROR )
							{
								if( memcmp( pbServerCertSHA1, pbSHA1, sizeof( pbSHA1 ) ) == 0 )
								{
									AA_TRACE( ( TEXT( "AA_GetCertificate::found certificate" ) ) );

									*ppCertContext = CertDuplicateCertificateContext( pCertContext );

									bFoundCert = TRUE;
								}

								free( pbSHA1 );
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
			}

			if( !bFoundCert )
				dwRet = ERROR_CANTOPEN;

			if( dwRet != NO_ERROR )
			{
				if( pCertContext )
					CertFreeCertificateContext( pCertContext );

			}
				
			CertCloseStore( hCertStore, CERT_CLOSE_STORE_CHECK_FLAG );
		}
		else
			dwRet = ERROR_CANTOPEN;

		CryptReleaseContext( hCSP, 0 );
	}

	AA_TRACE( ( TEXT( "AA_GetCertificate::returning %ld" ), dwRet ) );

	return dwRet;
}