//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//
//
// Use of this source code is subject to the terms of the Microsoft end-user
// license agreement (EULA) under which you licensed this SOFTWARE PRODUCT.
// If you did not accept the terms of the EULA, you are not authorized to use
// this source code. For a copy of the EULA, please see the LICENSE.RTF on your
// install media.
//
/*++
THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Module Name:  

    wzcsapi.h
    
Abstract:
    API for Wireless Zero Configuration interface.

Notes: 


--*/
#ifndef _WZCAPI_H_
#define _WZCAPI_H_

#ifdef UNDER_CE
#ifdef MIDL_PASS
#undef MIDL_PASS
#endif
#endif

#pragma once

# ifdef     __cplusplus
extern "C" {
# endif

#ifndef UNDER_CE
//PVOID
//MIDL_user_allocate(size_t NumBytes);

//VOID
//MIDL_user_free(void * MemPointer);
#endif	//	UNDER_CE

//---------------------------------------
// Macros for handling additional attributes on WZC_WLAN_CONFIG structures
// Coding of additional attributes in the Reserved bytes of WZC_WLAN_CONFIG objects:
// Reserved
// [1]      [0]
// ---SSSAA CCCCCCCC
// SSS = [0-7; used: 0-6] selection set category, one of VPI, VI, PI, VPA, VA, PA, N
// AA  = [0-3; used: 0-3] authentication mode, NDIS_802_11_AUTHENTICATION_MODE value
// CCCCCCCC = [0-255] retry counter for this object.
//
#define NWB_AUTHMODE_MASK       0x03
#define NWB_SELCATEG_MASK       0x1C

#ifndef UNDER_CE

#define NWB_SET_AUTHMODE(pNWB, nAM)     (pNWB)->Reserved[1] = (((pNWB)->Reserved[1] & ~NWB_AUTHMODE_MASK) | ((nAM) & NWB_AUTHMODE_MASK))
#define NWB_GET_AUTHMODE(pNWB)          ((pNWB)->Reserved[1] & NWB_AUTHMODE_MASK)
#define NWB_SET_SELCATEG(pNWB, nSC)     (pNWB)->Reserved[1] = (((pNWB)->Reserved[1] & ~NWB_SELCATEG_MASK) | (((nSC)<<2) & NWB_SELCATEG_MASK))
#define NWB_GET_SELCATEG(pNWB)          (((pNWB)->Reserved[1] & NWB_SELCATEG_MASK)>>2)

#else

#define NWB_SET_AUTHMODE(pNWB, nAM)     (pNWB)->Reserved[1] = (UCHAR)(((pNWB)->Reserved[1] & ~NWB_AUTHMODE_MASK) | ((nAM) & NWB_AUTHMODE_MASK))
#define NWB_GET_AUTHMODE(pNWB)          ((pNWB)->Reserved[1] & NWB_AUTHMODE_MASK)
#define NWB_SET_SELCATEG(pNWB, nSC)     (pNWB)->Reserved[1] = (UCHAR)(((pNWB)->Reserved[1] & ~NWB_SELCATEG_MASK) | (((nSC)<<2) & NWB_SELCATEG_MASK))
#define NWB_GET_SELCATEG(pNWB)          (((pNWB)->Reserved[1] & NWB_SELCATEG_MASK)>>2)

#endif


//---------------------------------------
// [P]RAW_DATA: generic description of a BLOB
typedef struct
{
    DWORD   dwDataLen;
#if defined(MIDL_PASS)
    [unique, size_is(dwDataLen)] LPBYTE pData;
#else
    LPBYTE  pData;
#endif
} RAW_DATA, *PRAW_DATA;

#if !defined(MIDL_PASS)

#include <ntddndis.h>


#ifdef UNDER_CE
typedef struct _WZC_EAPOL_PARAMS
{
	BOOL	bEnable8021x;
    DWORD   dwEapFlags;
    DWORD   dwEapType;    
    DWORD   dwAuthDataLen;				
    BYTE    *pbAuthData;				   // Pointer to provider specific config blob

}	WZC_EAPOL_PARAMS, *PWZC_EAPOL_PARAMS;


typedef struct _EAP_EXTENSIONS
{
	DWORD					dwNumOfExtension;
	PEAP_EXTENSION_INFO		pEapExtensionInfo;

}	EAP_EXTENSIONS, *PEAP_EXTENSIONS;

#endif


#define WZCCTL_MAX_WEPK_MATERIAL   32
#define WZCCTL_WEPK_PRESENT        0x0001  // specifies whether the configuration includes or not a WEP key
#define WZCCTL_WEPK_XFORMAT        0x0002  // the WEP Key material (if any) is entered as hexadecimal digits
#define WZCCTL_WEPK_40BLEN         0x0004  // the WEP Key material (if any) should be 40bit length

//---------------------------------------
// [P]WZC_WLAN_CONFIG: like NDIS_WLAN_BSSID, but contains all the additional
// data that defines a [Preferred] Wireless Zero Configuration
typedef struct
{
    ULONG                               Length;             // Length of this structure
    DWORD                               dwCtlFlags;         // control flags (NON-NDIS) see WZC_WEPK* constants
    // fields from the NDIS_WLAN_BSSID structure
    NDIS_802_11_MAC_ADDRESS             MacAddress;         // BSSID
    UCHAR                               Reserved[2];
    NDIS_802_11_SSID                    Ssid;               // SSID
    ULONG                               Privacy;            // WEP encryption requirement
    NDIS_802_11_RSSI                    Rssi;               // receive signal strength in dBm
    NDIS_802_11_NETWORK_TYPE            NetworkTypeInUse;
    NDIS_802_11_CONFIGURATION           Configuration;
    NDIS_802_11_NETWORK_INFRASTRUCTURE  InfrastructureMode;
    NDIS_802_11_RATES                   SupportedRates;
    // fields from NDIS_802_11_WEP structure
    ULONG   KeyIndex;                               // 0 is the per-client key, 1-N are the global keys
    ULONG   KeyLength;                              // length of key in bytes
    UCHAR   KeyMaterial[WZCCTL_MAX_WEPK_MATERIAL];  // variable length depending on above field
    // aditional field for the Authentication mode
    NDIS_802_11_AUTHENTICATION_MODE     AuthenticationMode;
    RAW_DATA                            rdUserData;         // upper level buffer, attached to this config

#ifdef UNDER_CE
    WZC_EAPOL_PARAMS                    EapolParams;		// 802.1x parameters
#endif

} WZC_WLAN_CONFIG, *PWZC_WLAN_CONFIG;

//---------------------------------------
// [P]WZC_802_11_CONFIG_LIST: like NDIS_802_11_BSSID_LIST but indexes a
// set of [Preferred] Wireless Zero Configurations
typedef struct
{
    ULONG           NumberOfItems;  // number of elements in the array below
    ULONG           Index;          // [start] index in the array below
    WZC_WLAN_CONFIG Config[1];      // array of WZC_WLAN_CONFIGs
} WZC_802_11_CONFIG_LIST, *PWZC_802_11_CONFIG_LIST;

// WZC dialog codes have the 16th bit set to 1. This is what quickly sepparates them from EAPOL signals.
#define WZCDLG_IS_WZC(x)         (((x) & 0x00010000) == 0x00010000)
#define WZCDLG_FAILED            0x00010001     // 802.11 automatic configuration failed

// Dialog BLOB passed through the UI pipe to netman and wzcdlg
typedef struct _WZCDLG_DATA
{
    DWORD       dwCode;
    DWORD       lParam; // long numeric data
} WZCDLG_DATA, *PWZCDLG_DATA;

#endif

//---------------------------------------
// [P]INTF_ENTRY: describes the key info for one interface
// this is used in conjunction with [P]INTFS_KEY_TABLE and WZCEnumInterfaces
typedef struct
{
#if defined(MIDL_PASS)
    [unique, string] LPWSTR wszGuid;
#else
    LPWSTR wszGuid;
#endif
} INTF_KEY_ENTRY, *PINTF_KEY_ENTRY;

//---------------------------------------
// [P]INTFS_KEY_TABLE: describes the table of key info for all interfaces
// this is used in conjunction with [P]INTF_KEY_ENTRY and WZCEnumInterfaces
typedef struct
{
    DWORD dwNumIntfs;
#if defined(MIDL_PASS)
    [size_is(dwNumIntfs)] PINTF_KEY_ENTRY pIntfs;
#else
    PINTF_KEY_ENTRY pIntfs;
#endif
} INTFS_KEY_TABLE, *PINTFS_KEY_TABLE;

//---------------------------------------
// Bits used in conjunction with INTF_ENTRY, WZCQueryInterface
// and WZCSetInterface. They point to the relevant information
// that is requested from the service or to the relevant information
// to be set down to the interface. On the output, they point to
// the information that was processed (queried/set) successfully.
#define INTF_ALL            0x000fffff
#define INTF_DESCR          0x00000001
#define INTF_MEDIASTATE     0x00000002
#define INTF_MEDIATYPE      0x00000004
#define INTF_PHYSMEDIATYPE  0x00000008
#define INTF_CTLFLAGS       0x00000010
#define INTF_STSSIDLIST     0x00000020

#define INTF_ALL_OIDS       0x000fff00
#define INTF_HANDLE         0x00000100
#define INTF_INFRAMODE      0x00000200
#define INTF_AUTHMODE       0x00000400
#define INTF_WEPSTATUS      0x00000800
#define INTF_SSID           0x00001000
#define INTF_BSSID          0x00002000
#define INTF_BSSIDLIST      0x00004000
#define INTF_LIST_SCAN      0x00008000
#define INTF_ADDWEPKEY      0x00010000
#define INTF_REMWEPKEY      0x00020000
#define INTF_LDDEFWKEY      0x00040000  // reload the default WEP_KEY

//---------------------------------------
// Bits used to specify particular control options for the interface
// entry
#define INTFCTL_CM_MASK     0x0007   // mask for the configuration mode (NDIS_802_11_NETWORK_INFRASTRUCTURE value)
#define INTFCTL_ENABLED     0x8000   // zero conf enabled for this interface
#define INTFCTL_FALLBACK    0x4000   // attempt to connect to visible non-preferred networks also
#define INTFCTL_OIDSSUPP    0x2000   // 802.11 OIDs are supported by the driver/firmware

#ifdef UNDER_CE
#define INTFCTL_8021XSUPP   0x1000   // 802.1x support enabled
#endif

//---------------------------------------
// [P]INTF_ENTRY: contains everything an RPC client needs to know
// about an interface. It is used in conjunction with RpcQueryInterface.
// Flags below are to be used to specify what info is queried for the
// interface. Guid field is not covered since this is the key of the
// structure so it has to be specified eather way.
typedef struct
{    
#if defined(MIDL_PASS)
    [string] LPWSTR wszGuid;
#else
    LPWSTR          wszGuid;
#endif
#if defined(MIDL_PASS)
    [string] LPWSTR wszDescr;
#else
    LPWSTR          wszDescr;
#endif
    ULONG           ulMediaState;
    ULONG           ulMediaType;
    ULONG           ulPhysicalMediaType;
    INT             nInfraMode;
    INT             nAuthMode;
    INT             nWepStatus;
    DWORD           dwCtlFlags;     // control flags (see INTFCTL_* defines)
    RAW_DATA        rdSSID;         // encapsulates the SSID raw binary
    RAW_DATA        rdBSSID;        // encapsulates the BSSID raw binary
    RAW_DATA        rdBSSIDList;    // encapsulates one WZC_802_11_CONFIG_LIST structure
    RAW_DATA        rdStSSIDList;   // encapsulates one WZC_802_11_CONFIG_LIST structure
    RAW_DATA        rdCtrlData;     // data for various control actions on the interface

    BOOL            bInitialized;   //  To track caller that freeing
                                    //  the same structure more than one time..
} INTF_ENTRY, *PINTF_ENTRY;

//---------------------------------------
// Utility Rpc memory management routines
#define RpcCAlloc(nBytes)   MIDL_user_allocate(nBytes)
#define RpcFree(pMem)       MIDL_user_free(pMem)




//---------------------------------------
// WZCDeleteIntfObj: cleans an INTF_ENTRY object that is
// allocated within any RPC call.
// 
// Parameters
// pIntf
//     [in] pointer to the INTF_ENTRY object to delete
VOID
WZCDeleteIntfObj(
    PINTF_ENTRY pIntf);


#ifdef UNDER_CE

//
//	Only in CE..
//	This function enumerates all the EAP extensions currently installed	
//	in the system..
//

DWORD
WZCEnumEapExtensions(
	DWORD				*pdwNumOfExtensions,
	PEAP_EXTENSION_INFO	*pEapExtensions);

#endif

//---------------------------------------
// WZCEnumInterfaces: provides the table of key
// information for all the interfaces that are managed.
// For all subsequent calls the clients need to identify
// the Interface it operates on by providing the respective
// key info.
//
// Parameters:
//   pSrvAddr
//     [in] WZC Server to contact
//   pIntf
//     [out] table of key info for all interfaces
// Returned value:
//     Win32 error code 
DWORD
WZCEnumInterfaces(
    LPWSTR           pSrvAddr,
    PINTFS_KEY_TABLE pIntfs);


//---------------------------------------
// WZCQueryIterface: provides detailed information for a
// given interface.
// 
// Parameters:
//   pSrvAddr:
//     [in]  WZC Server to contact
//   dwInFlags:
//     [in]  Fields to be queried (bitmask of INTF_*)
//   pIntf:
//     [in]  Key of the interface to query
//     [out] Requested data from the interface.
//   pdwOutFlags
//     [out] Fields successfully retrieved (bitmask of INTF_*)
//
// Returned value:
//     Win32 error code 
DWORD
WZCQueryInterface(
    LPWSTR              pSrvAddr,
    DWORD               dwInFlags,
    PINTF_ENTRY         pIntf,
    LPDWORD             pdwOutFlags);

//---------------------------------------
// WZCSetIterface: sets specific information on the interface
// 
// Parameters:
//   pSrvAddr:
//     [in]  WZC Server to contact
//   dwInFlags:
//     [in]  Fields to be set (bitmask of INTF_*)
//   pIntf:
//     [in]  Key of the interface to query and data to be set
//   pdwOutFlags:
//     [out] Fields successfully set (bitmask of INTF_*)
//
// Returned value:
//     Win32 error code 
DWORD
WZCSetInterface(
    LPWSTR              pSrvAddr,
    DWORD               dwInFlags,
    PINTF_ENTRY         pIntf,
    LPDWORD             pdwOutFlags);

//---------------------------------------
// WZCRefreshInterface: refreshes specific information for the interface
// 
// Parameters:
//   pSrvAddr:
//     [in]  WZC Server to contact
//   dwInFlags:
//     [in]  Fields to be refreshed and specific refresh actions to be
//           taken (bitmask of INTF_*)
//   pIntf:
//     [in]  Key of the interface to be refreshed
//   pdwOutFlags:
//     [out] Fields successfully refreshed (bitmask of INTF_*)
//
// Returned value:
//     Win32 error code 
DWORD
WZCRefreshInterface(
    LPWSTR              pSrvAddr,
    DWORD               dwInFlags,
    PINTF_ENTRY         pIntf,
    LPDWORD             pdwOutFlags);




//
// EAPOL-related definitions (not used in CE).
//

#define EAPOL_DISABLED                  0
#define EAPOL_ENABLED                   0x80000000

#define EAPOL_MACHINE_AUTH_DISABLED     0
#define EAPOL_MACHINE_AUTH_ENABLED      0x40000000

#define EAPOL_GUEST_AUTH_DISABLED       0
#define EAPOL_GUEST_AUTH_ENABLED        0x20000000

#define DEFAULT_EAP_TYPE                13      // EAP-TLS
#define DEFAULT_EAPOL_STATE             EAPOL_ENABLED
#define DEFAULT_MACHINE_AUTH_STATE      EAPOL_MACHINE_AUTH_ENABLED
#define DEFAULT_GUEST_AUTH_STATE        EAPOL_GUEST_AUTH_DISABLED

#define DEFAULT_EAP_STATE               (DEFAULT_EAPOL_STATE | DEFAULT_MACHINE_AUTH_STATE | DEFAULT_GUEST_AUTH_STATE)

#define IS_EAPOL_ENABLED(x) \
    ((x & EAPOL_ENABLED)?1:0)
#define IS_MACHINE_AUTH_ENABLED(x) \
    ((x & EAPOL_MACHINE_AUTH_ENABLED)?1:0)
#define IS_GUEST_AUTH_ENABLED(x) \
    ((x & EAPOL_GUEST_AUTH_ENABLED)?1:0)

// Supplicant modes of operation depending on network state and 
// administrator decision

#define     SUPPLICANT_MODE_0       0
#define     SUPPLICANT_MODE_1       1
#define     SUPPLICANT_MODE_2       2
#define     SUPPLICANT_MODE_3       3
#define     NUM_SUPPLICANT_MODES    3
#define     EAPOL_DEFAULT_SUPPLICANT_MODE   SUPPLICANT_MODE_2


// Double-threaded linked list node control block.  There is one node for each
// entry in a list.
//
// Applications should not access this structure directly.
//
typedef struct
_DTLNODE
{
    struct _DTLNODE* pdtlnodePrev; // Address of previous node or NULL if none
    struct _DTLNODE* pdtlnodeNext; // Address of next node or NULL if none
    VOID*    pData;        // Address of user's data
    LONG_PTR lNodeId;      // User-defined node identification code
}
DTLNODE;


//
// Double-threaded linked list control block.  There is one for each list.
//
// Applications should not access this structure directly.
//

typedef struct
_DTLLIST
{
    struct _DTLNODE* pdtlnodeFirst; // Address of first node or NULL if none
    struct _DTLNODE* pdtlnodeLast;  // Address of last node or NULL if none
    LONG     lNodes;        // Number of nodes in list
    LONG_PTR lListId;       // User-defined list identification code
}
DTLLIST;


// List node free function.  See FreeList.
//
typedef VOID (*PDESTROYNODE)( IN DTLNODE* );

#define DtlGetFirstNode( pdtllist )   ((pdtllist)->pdtlnodeFirst)
#define DtlGetNextNode( pdtlnode )    ((pdtlnode)->pdtlnodeNext)
#define DtlGetData( pdtlnode )        ((pdtlnode)->pData)

// EAP configuration DLL entrypoints.  These definitions must match the
// raseapif.h prototypes for RasEapInvokeConfigUI and RasEapFreeUserData.

typedef DWORD (APIENTRY * RASEAPFREE)( PBYTE );
typedef DWORD (APIENTRY * RASEAPINVOKECONFIGUI)( DWORD, HWND, DWORD, PBYTE, DWORD, PBYTE*, DWORD*);
typedef DWORD (APIENTRY * RASEAPGETIDENTITY)( DWORD, HWND, DWORD, const WCHAR*, const WCHAR*, PBYTE, DWORD, PBYTE, DWORD, PBYTE*, DWORD*, WCHAR** );
typedef DWORD (APIENTRY * RASEAPINVOKEINTERACTIVEUI)( DWORD, HWND, PBYTE, DWORD, PBYTE*, DWORD* );


// Flags

#define EAPCFG_FLAG_RequireUsername   0x1
#define EAPCFG_FLAG_RequirePassword   0x2

// EAP configuration package definition.

typedef struct
_EAPCFG
{
    // The package's unique EAP algorithm code.
    //
    DWORD dwKey;

    // The friendly name of the package suitable for display to the user.
    //
    TCHAR* pszFriendlyName;

    // The SystemRoot-relative path to the package's configuration DLL.  May
    // be NULL indicating there is none.
    //
    TCHAR* pszConfigDll;

    // The SystemRoot-relative path to the package's identity DLL.  May
    // be NULL indicating there is none.
    //
    TCHAR* pszIdentityDll;

    // Flags that specify what standard credentials are required at dial
    // time.
    //
    DWORD dwStdCredentialFlags;

    // True if user is to be forced to run the configuration API for the
    // package, i.e. defaults are not sufficient.
    //
    BOOL fForceConfig;

    // True if the package provides MPPE encryption keys, false if not.
    //
    BOOL fProvidesMppeKeys;

    // The package's default configuration blob, which can be overwritten by
    // the configuration DLL.  May be NULL and 0 indicating there is none.
    //
    BYTE* pData;
    DWORD cbData;

    // EAP per user data to be stored in HKCU. This data is returned from
    // the EapInvokeConfigUI entrypoint in the eap dll.
    //    
    BYTE* pUserData;
    DWORD cbUserData;

    // Set when the configuration DLL has been called on the package.  This is
    // not a registry setting.  It is provided for the convenience of the UI
    // only.
    //
    BOOL fConfigDllCalled;

    // Specifies the class ID of the configuration UI for remote machines.
    // Not used
    GUID guidConfigCLSID;
} EAPCFG;

VOID     DtlDestroyList( DTLLIST*, PDESTROYNODE );

DTLNODE *
CreateEapcfgNode(
    void);

VOID
DestroyEapcfgNode(
    IN OUT DTLNODE* pNode);

DTLNODE*
EapcfgNodeFromKey(
    IN DTLLIST* pList,
    IN DWORD dwKey);

DTLLIST*
ReadEapcfgList();

#define MAX_SSID_LEN    32

//
// Structure : EAPOL_INTF_PARAMS
//

typedef struct _EAPOL_INTF_PARAMS
{
    DWORD   dwVersion;
    DWORD   dwReserved2;
    DWORD   dwEapFlags;
    DWORD   dwEapType;
    DWORD   dwSizeOfSSID;
    BYTE    bSSID[MAX_SSID_LEN];
} EAPOL_INTF_PARAMS, *PEAPOL_INTF_PARAMS;


#define     EAPOL_VERSION_1             1

#define     EAPOL_CURRENT_VERSION       EAPOL_VERSION_1


//
// Structure : EAPOL_AUTH_DATA
//
typedef struct _EAPOL_AUTH_DATA
{
    DWORD   dwEapType;
    DWORD   dwSize;
    BYTE    bData[1];
} EAPOL_AUTH_DATA, *PEAPOL_AUTH_DATA;

DWORD
WZCGetEapUserInfo (
        IN  WCHAR           *pwszGUID,
        IN  DWORD           dwEapTypeId,
        IN  DWORD           dwSizOfSSID,
        IN  BYTE            *pbSSID,
        IN  OUT PBYTE       pbUserInfo,
        IN  OUT DWORD       *pdwInfoSize
        );

// Structure used to define the UI Response.
// Currently it contains upto 3 blobs.
// If more are required, add to the structure

#define NUM_RESP_BLOBS 3

typedef struct _EAPOLUI_RESP
{
    RAW_DATA    rdData0;
    RAW_DATA    rdData1;
    RAW_DATA    rdData2;
} EAPOLUI_RESP, *PEAPOLUI_RESP;


#if !defined(MIDL_PASS)

//---------------------------------------
// WZCEapolGetCustomAuthData: Get EAP-specific configuration data for interface
// 
// Parameters:
//   pSrvAddr:
//     [in]  WZC Server to contact
//   pwszGuid:
//     [in]  Interface GUID
//   dwEapTypeId:
//     [in]  EAP type Id
//   dwSizeOfSSID:
//     [in]  Size of SSID for which data is to be stored
//   pbSSID:
//     [in]  SSID for which data is to be stored
//   pbConnInfo:
//     [in out]  Connection EAP info
//   pdwInfoSize:
//     [in out]  Size of pbConnInfo
//
// Returned value:
//     Win32 error code 
DWORD
WZCEapolGetCustomAuthData (
    IN  LPWSTR        pSrvAddr,
    IN  PWCHAR        pwszGuid,
    IN  DWORD         dwEapTypeId,
    IN  DWORD         dwSizeOfSSID,
    IN  BYTE          *pbSSID,
    IN OUT PBYTE      pbConnInfo,
    IN OUT PDWORD     pdwInfoSize
    );

//---------------------------------------
// WZCEapolSetCustomAuthData: Set EAP-specific configuration data for interface
// 
// Parameters:
//   pSrvAddr:
//     [in]  WZC Server to contact
//   pwszGuid:
//     [in]  Interface GUID
//   dwEapTypeId:
//     [in]  EAP type Id
//   dwSizeOfSSID:
//     [in]  Size of SSID for which data is to be stored
//   pbSSID:
//     [in]  SSID for which data is to be stored
//   pbConnInfo:
//     [in]  Connection EAP info
//   pdwInfoSize:
//     [in]  Size of pbConnInfo
//
// Returned value:
//     Win32 error code 
DWORD
WZCEapolSetCustomAuthData (
    IN  LPWSTR        pSrvAddr,
    IN  PWCHAR        pwszGuid,
    IN  DWORD         dwEapTypeId,
    IN  DWORD         dwSizeOfSSID,
    IN  BYTE          *pbSSID,
    IN  PBYTE         pbConnInfo,
    IN  DWORD         dwInfoSize
    );

//---------------------------------------
// WZCEapolGetInterfaceParams: Get configuration parameters for interface
// 
// Parameters:
//   pSrvAddr:
//     [in]  WZC Server to contact
//   pwszGuid:
//     [in]  Interface GUID
//   pIntfParams:
//     [in out]  Interface Parameters
//
// Returned value:
//     Win32 error code 
DWORD
WZCEapolGetInterfaceParams (
    IN  LPWSTR          pSrvAddr,
    IN  PWCHAR          pwszGuid,
    IN OUT EAPOL_INTF_PARAMS   *pIntfParams
    );

//---------------------------------------
// WZCEapolSetInterfaceParams: Set configuration parameters for interface
// 
// Parameters:
//   pSrvAddr:
//     [in]  WZC Server to contact
//   pwszGuid:
//     [in]  Interface GUID
//   pIntfParams:
//     [in]  Interface parameters
// Returned value:
//     Win32 error code 
DWORD
WZCEapolSetInterfaceParams (
    IN  LPWSTR        pSrvAddr,
    IN  PWCHAR        pwszGuid,
    IN  EAPOL_INTF_PARAMS   *pIntfParams
    );

#endif // MIDL_PASS

//
// Structure: EAPOL_EAP_UI_CONTEXT
//

typedef struct _EAPOL_EAP_UI_CONTEXT
{
    DWORD       dwEAPOLUIMsgType;
    WCHAR       wszGUID[39];
    DWORD       dwSessionId;
    DWORD       dwContextId;
    DWORD       dwEapId;
    DWORD       dwEapTypeId;
    DWORD       dwEapFlags;
    WCHAR       wszSSID[MAX_SSID_LEN+1];
    DWORD       dwSizeOfSSID;
    BYTE        bSSID[MAX_SSID_LEN];
    DWORD       dwEAPOLState;
    DWORD       dwRetCode;
    DWORD       dwSizeOfEapUIData;
    BYTE        bEapUIData[1];
} EAPOL_EAP_UI_CONTEXT, *PEAPOL_EAP_UI_CONTEXT;

//
// Defines for messaging between Service and Dialog DLL
//

#define     EAPOLUI_GET_USERIDENTITY            0x00000001
#define     EAPOLUI_GET_USERNAMEPASSWORD        0x00000002
#define     EAPOLUI_INVOKEINTERACTIVEUI         0x00000004
#define     EAPOLUI_EAP_NOTIFICATION            0x00000008
#define     EAPOLUI_REAUTHENTICATE              0x00000010
#define     EAPOLUI_CREATEBALLOON               0x00000020
#define     EAPOLUI_CLEANUP                     0x00000040
#define     EAPOLUI_DUMMY                       0x00000080

#define     NUM_EAPOL_DLG_MSGS      8



//---------------------------------------
// WZCEapolUIResponse: Send Dlg response to Service
// 
// Parameters:
//   pSrvAddr:
//     [in]  WZC Server to contact
//   EapolUIContext:
//     [in]  EAPOLUI Context data
//   EapolUI:
//     [in]  EAPOLUI response data
//
// Returned value:
//     Win32 error code 
DWORD
WZCEapolUIResponse (
    IN  LPWSTR                  pSrvAddr,
    IN  EAPOL_EAP_UI_CONTEXT    EapolUIContext,
    IN  EAPOLUI_RESP            EapolUIResp
    );

#ifdef NETMAN
//---------------------------------------
// WZCQueryGUIDNCSState: Callback from netman to query GUID state
// 
// Parameters:
//   pGuidConn:
//     [in]  Interface GUID
//   pncs:
//     [in]  Netcon Status of GUID
//
// Returned value:
//     HRESULT 
//      S_FALSE - If GUID is not under 802.1X control
//      S_OK - If GUID under 802.1X control. Status is returned in pncs
//

HRESULT
WZCQueryGUIDNCSState (
        IN      GUID            * pGuidConn,
        OUT     NETCON_STATUS   * pncs
        );
#endif



//
//	In CE, CreateFile(ZEROCONFIG_DEVICE_NAME) then IOCTL to it..
//

#define	ZEROCONFIG_DEVICE_NAME		TEXT("ZCF1:")

#define FSCTL_ZC_BASE				FILE_DEVICE_NETWORK

#define _ZC_CTL_CODE(_Function, _Method, _Access)  \
            CTL_CODE(FSCTL_ZC_BASE, _Function, _Method, _Access)


#define	IOCTL_ZC_ENUM_INTERFACES					\
			_ZC_CTL_CODE(0x300, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	IOCTL_ZC_QUERY_INTERFACE					\
			_ZC_CTL_CODE(0x301, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	IOCTL_ZC_SET_INTERFACE						\
			_ZC_CTL_CODE(0x302, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	IOCTL_ZC_REFRESH_INTERFACE					\
			_ZC_CTL_CODE(0x303, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	IOCTL_ZC_ENUM_EAP_EXTENSIONS				\
			_ZC_CTL_CODE(0x304, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	IOCTL_ZC_EAPOL_GET_CUSTOM_AUTH_DATA			\
			_ZC_CTL_CODE(0x305, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	IOCTL_ZC_EAPOL_SET_CUSTOM_AUTH_DATA			\
			_ZC_CTL_CODE(0x306, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	IOCTL_ZC_EAPOL_GET_INTERFACE_PARAMS			\
			_ZC_CTL_CODE(0x307, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	IOCTL_ZC_EAPOL_SET_INTERFACE_PARAMS			\
			_ZC_CTL_CODE(0x308, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	IOCTL_ZC_EAPOL_UI_RESPONSE					\
			_ZC_CTL_CODE(0x309, METHOD_BUFFERED, FILE_ANY_ACCESS)


typedef struct
{
    DWORD	dwNumIntfs;
	DWORD	dwBufferSize;    
    PBYTE	pbBuffer;

}	CE_ENUM_INTERFACE, *PCE_ENUM_INTERFACE;


typedef struct
{
    DWORD               dwInFlags;
	DWORD	            dwOutFlags;
	LPWSTR				wszGuid;
	DWORD				dwBufferSize;    
	PBYTE				pbBuffer;    
	
}	CE_QUERY_INTERFACE, *PCE_QUERY_INTERFACE;


typedef struct
{
    DWORD               dwInFlags;    
    DWORD				dwOutFlags;
	PINTF_ENTRY         pIntf;
	
}	CE_SET_INTERFACE, *PCE_SET_INTERFACE;


typedef struct
{
    DWORD               dwInFlags;
	DWORD				dwOutFlags;
    PINTF_ENTRY         pIntf;    
	
}	CE_REFRESH_INTERFACE, *PCE_REFRESH_INTERFACE;


typedef struct
{
    DWORD	dwNumExtensions;
	DWORD	dwBufferSize;    
    PBYTE	pbBuffer;

}	CE_ENUM_EAP_EXTENSIONS, *PCE_ENUM_EAP_EXTENSIONS;


typedef struct
{
	PWCHAR				pwszGuid;
	DWORD				dwEapTypeId;
	RAW_DATA			rdSSID;
	RAW_DATA			rdConnInfo;

}	CE_EAPOL_CUSTOM_AUTH_DATA, *PCE_EAPOL_CUSTOM_AUTH_DATA;


typedef struct
{
	PWCHAR				pwszGuid;
	EAPOL_INTF_PARAMS	*pIntfParams;

}	CE_EAPOL_INTERFACE_PARAMS, *PCE_EAPOL_INTERFACE_PARAMS;


typedef struct
{
	EAPOL_EAP_UI_CONTEXT	*pEapolUIContext;
	EAPOLUI_RESP            *pEapolUIResp;

}	CE_EAPOL_UI_RESPONSE, *PCE_EAPOL_UI_RESPONSE;


# ifdef     __cplusplus
}
# endif


#endif	//	_WZCAPI_H_

