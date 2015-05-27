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
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <stdio.h>

#include "WZCLib.h"
#include "..\..\..\..\Common\release 3\version 0\source\Common.h"

PAA_WZC_CONFIG_LIST_ITEM 
WZCConfigItemCreate( IN PAA_WZC_LIB_CONTEXT pWZCContext, IN WZC_WLAN_CONFIG WZCCfg, IN DWORD dwFlags )
{
	PAA_WZC_CONFIG_LIST_ITEM	pWZCConfigListItem;

	AA_TRACE( ( TEXT( "WZCConfigItemCreate::(%ld): %s" ), sizeof( WZC_WLAN_CONFIG ), AA_ByteToHex( ( PBYTE ) &WZCCfg, sizeof( WZC_WLAN_CONFIG ) ) ) );

	AA_TRACE( ( TEXT( "WZCConfigItemCreate::WZCCfg.Length: %ld" ), WZCCfg.Length ) );
	AA_TRACE( ( TEXT( "WZCConfigItemCreate::WZCCfg.dwCtlFlags: %ld" ), WZCCfg.dwCtlFlags ) );
	AA_TRACE( ( TEXT( "WZCConfigItemCreate::WZCCfg.MacAddress: %s" ), AA_ByteToHex( ( PBYTE ) &( WZCCfg.MacAddress ), sizeof( NDIS_802_11_MAC_ADDRESS ) ) ) );
	AA_TRACE( ( TEXT( "WZCConfigItemCreate::WZCCfg.Ssid: %s" ), AA_ByteToHex( ( PBYTE ) &( WZCCfg.Ssid ), sizeof( NDIS_802_11_SSID ) ) ) );
	AA_TRACE( ( TEXT( "WZCConfigItemCreate::WZCCfg.Privacy: %ld" ), WZCCfg.Privacy ) );
	AA_TRACE( ( TEXT( "WZCConfigItemCreate::WZCCfg.Rssi: %s" ), AA_ByteToHex( ( PBYTE ) &( WZCCfg.Rssi ), sizeof( NDIS_802_11_RSSI ) ) ) );
	AA_TRACE( ( TEXT( "WZCConfigItemCreate::WZCCfg.NetworkTypeInUse: %ld" ), WZCCfg.NetworkTypeInUse ) );
	AA_TRACE( ( TEXT( "WZCConfigItemCreate::WZCCfg.InfrastructureMode: %ld" ), WZCCfg.InfrastructureMode ) );
	AA_TRACE( ( TEXT( "WZCConfigItemCreate::WZCCfg.SupportedRates: %s" ), AA_ByteToHex( ( PBYTE ) &( WZCCfg.SupportedRates ), sizeof( NDIS_802_11_RATES ) ) ) );

	AA_TRACE( ( TEXT( "WZCConfigItemCreate::WZCCfg.KeyIndex: %ld" ), WZCCfg.KeyIndex ) );
	AA_TRACE( ( TEXT( "WZCConfigItemCreate::WZCCfg.KeyLength: %ld" ), WZCCfg.KeyLength ) );
	AA_TRACE( ( TEXT( "WZCConfigItemCreate::WZCCfg.KeyMaterial: %s" ), AA_ByteToHex( ( PBYTE ) WZCCfg.KeyMaterial, WZCCTL_MAX_WEPK_MATERIAL ) ) );
	AA_TRACE( ( TEXT( "WZCConfigItemCreate::WZCCfg.AuthenticationMode: %ld" ), WZCCfg.AuthenticationMode ) );

	AA_TRACE( ( TEXT( "WZCConfigItemCreate::WZCCfg.rdUserData: %s" ), AA_ByteToHex( ( PBYTE ) WZCCfg.rdUserData.pData, WZCCfg.rdUserData.dwDataLen ) ) );
	
 	if( ( pWZCConfigListItem = ( PAA_WZC_CONFIG_LIST_ITEM ) malloc( sizeof( AA_WZC_CONFIG_LIST_ITEM ) ) ) )
	{
		pWZCConfigListItem->pPrev = NULL;
		pWZCConfigListItem->pNext = NULL;
		pWZCConfigListItem->WZCConfig = WZCCfg;
		pWZCConfigListItem->dwFlags = dwFlags;

		if( pWZCContext->dwWZCSDllVersion >= WZCS_DLL_VERSION_5_1_2600_1106 )
		{
			if( WZCCfg.Privacy == 1 )
				pWZCConfigListItem->dwFlags |= AA_WZC_LIB_CONFIG_WEP;
		}
		else
		{
			if( WZCCfg.Privacy == 0 )
				pWZCConfigListItem->dwFlags |= AA_WZC_LIB_CONFIG_WEP;
		}
	}
	else
	{
		pWZCConfigListItem = NULL;
	}

	return pWZCConfigListItem;
}

VOID
WZCConfigItemDelete( IN PAA_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	PAA_WZC_CONFIG_LIST_ITEM pWZCConfigListItem = *ppWZCConfigListItem;

	if( pWZCConfigListItem->pNext )
		pWZCConfigListItem->pNext->pPrev = pWZCConfigListItem->pPrev;

	if( pWZCConfigListItem->pPrev )
		pWZCConfigListItem->pPrev->pNext = pWZCConfigListItem->pNext;

	free( *ppWZCConfigListItem );

	*ppWZCConfigListItem = NULL;
}

DWORD
WZCConfigItemPrePend( IN PAA_WZC_CONFIG_LIST_ITEM pWZCConfigListItem1, IN PAA_WZC_CONFIG_LIST_ITEM pWZCConfigListItem2 )
{
	DWORD	dwRet;

	dwRet = NO_ERROR;

	if( pWZCConfigListItem1 && pWZCConfigListItem2 )
	{
		pWZCConfigListItem1->pPrev = pWZCConfigListItem2;
		pWZCConfigListItem2->pNext = pWZCConfigListItem1;
	}
	else
	{
		dwRet = ERROR_NO_DATA;
	}

	return dwRet;
}

DWORD
WZCConfigItemAppend( IN PAA_WZC_CONFIG_LIST_ITEM pWZCConfigListItem1, 
						IN PAA_WZC_CONFIG_LIST_ITEM pWZCConfigListItem2 )
{
	DWORD	dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "WZCConfigItemAppend" ) ) );

	if( pWZCConfigListItem1 && pWZCConfigListItem2 )
	{
		if( pWZCConfigListItem1->pNext )
		{
			//
			// Item has a next item so insert the bugger
			//
			AA_TRACE( ( TEXT( "WZCConfigItemAppend::inserting" ) ) );

			WZCConfigItemInsert( pWZCConfigListItem1, pWZCConfigListItem1->pNext, pWZCConfigListItem2 );
		}
		else
		{
			AA_TRACE( ( TEXT( "WZCConfigItemAppend::appending" ) ) );

			pWZCConfigListItem1->pNext = pWZCConfigListItem2;
			pWZCConfigListItem2->pPrev = pWZCConfigListItem1;
		}
	}
	else
	{
		dwRet = ERROR_NO_DATA;
	}

	AA_TRACE( ( TEXT( "WZCConfigItemAppend::returning" ) ) );

	return dwRet;
}


DWORD
WZCConfigItemInsert( IN PAA_WZC_CONFIG_LIST_ITEM pWZCConfigListItemPrev, IN PAA_WZC_CONFIG_LIST_ITEM pWZCConfigListItemNext, IN PAA_WZC_CONFIG_LIST_ITEM pWZCConfigListItem )
{
	DWORD	dwRet;

	dwRet = NO_ERROR;

	AA_TRACE( ( TEXT( "WZCConfigItemInsert" ) ) );

	if( pWZCConfigListItemPrev && pWZCConfigListItemNext && pWZCConfigListItem )
	{
		AA_TRACE( ( TEXT( "WZCConfigItemInsert:: inserting" ) ) );

		pWZCConfigListItemPrev->pNext = pWZCConfigListItem;
		pWZCConfigListItemNext->pPrev = pWZCConfigListItem;

		pWZCConfigListItem->pPrev = pWZCConfigListItemPrev;
		pWZCConfigListItem->pNext = pWZCConfigListItemNext;
	}
	else
	{
		dwRet = ERROR_NO_DATA;
	}

	AA_TRACE( ( TEXT( "WZCConfigItemInsert:: returning" ) ) );

	return dwRet;
}

DWORD
WZCConfigItemGet( IN PAA_WZC_CONFIG_LIST_ITEM pWZCConfigListItemStart, IN PCHAR pcSSID, OUT PAA_WZC_CONFIG_LIST_ITEM *ppWZCConfigListItem )
{
	PAA_WZC_CONFIG_LIST_ITEM	p;
	DWORD						dwRet;

	dwRet = NO_ERROR;

	p = pWZCConfigListItemStart;

	while( p )
	{
		if( memcmp( p->WZCConfig.Ssid.Ssid, pcSSID, sizeof( NDIS_802_11_LENGTH_SSID ) ) == 0 )
		{
			*ppWZCConfigListItem = p;

			break;
		}
		else
		{
			p = p->pNext;
		}
	}

	if( !p )
		dwRet = ERROR_NO_DATA;

	return dwRet;
}