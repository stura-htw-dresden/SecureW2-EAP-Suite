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

#ifndef _WIRELESS_
#define _WIRELESS_


#ifdef __cplusplus
extern "C" {
#endif


typedef struct _WL_ASSOCIATION {
    DWORD dwReserved;
} WL_ASSOCIATION, * PWL_ASSOCIATION;


typedef struct _DOT11_ADAPTER {
    GUID gAdapterId;
    LPWSTR pszDescription;
    DOT11_CURRENT_OPERATION_MODE Dot11CurrentOpMode;
} DOT11_ADAPTER, * PDOT11_ADAPTER;


#define MAX_DOT11_ADAPTER_ENUM_COUNT 100


typedef struct _DOT11_PHY_LIST {
    ULONG uNumOfEntries;
#ifdef __midl
    [size_is(uNumOfEntries)] PDOT11_PHY_TYPE pDot11PHYType;
#else
    PDOT11_PHY_TYPE pDot11PHYType;
#endif
} DOT11_PHY_LIST, * PDOT11_PHY_LIST;


typedef struct _DOT11_STA_POWER_MGMT_MODE {
    DOT11_POWER_MODE dot11PowerMode;
    ULONG uPowerSaveLevel;
    BOOL bReceiveDTIMs;
} DOT11_STA_POWER_MGMT_MODE, * PDOT11_STA_POWER_MGMT_MODE;


typedef struct _DOT11_REG_DOMAINS_LIST {
    ULONG uNumOfEntries;
#ifdef __midl
    [size_is(uNumOfEntries)] PDOT11_REG_DOMAIN_VALUE pDot11RegDomainValue;
#else
    PDOT11_REG_DOMAIN_VALUE pDot11RegDomainValue;
#endif
} DOT11_REG_DOMAINS_LIST, * PDOT11_REG_DOMAINS_LIST;


typedef struct _DOT11_ANTENNA_LIST {
    ULONG uNumOfEntries;
#ifdef __midl
    [size_is(uNumOfEntries)] PDOT11_SUPPORTED_ANTENNA pDot11SupportedAntenna;
#else
    PDOT11_SUPPORTED_ANTENNA pDot11SupportedAntenna;
#endif
} DOT11_ANTENNA_LIST, * PDOT11_ANTENNA_LIST;


typedef struct _DOT11_DIV_SELECT_RX_LIST {
    ULONG uNumOfEntries;
#ifdef __midl
    [size_is(uNumOfEntries)] PDOT11_DIVERSITY_SELECTION_RX pDot11DivSelectRx;
#else
    PDOT11_DIVERSITY_SELECTION_RX pDot11DivSelectRx;
#endif
} DOT11_DIV_SELECT_RX_LIST, * PDOT11_DIV_SELECT_RX_LIST;


typedef enum _DOT11_SMT_NOTIFY_TYPE {
    dot11_smt_notify_type_dissassociate = 1,
    dot11_smt_notify_type_deauthenticate = 2,
    dot11_smt_notify_type_authenticate_fail = 3
} DOT11_SMT_NOTIFY_TYPE, * PDOT11_SMT_NOTIFY_TYPE;


typedef struct _DOT11_DISCONNECTED_PEER {
    ULONG uReason;
    DOT11_MAC_ADDRESS dot11Station;
} DOT11_DISCONNECTED_PEER, * PDOT11_DISCONNECTED_PEER;


typedef enum _DOT11_INTEGRITY_FAIL_TYPE {
    dot11_integrity_fail_type_unicast_key = 1,
    dot11_integrity_fail_type_default_key = 2
} DOT11_INTEGRITY_FAIL_TYPE, *PDOT11_INTEGRITY_FAIL_TYPE;


typedef struct _DOT11_INTEGRITY_FAIL {
    DOT11_INTEGRITY_FAIL_TYPE dot11IntegrityFailType;
    DOT11_MAC_ADDRESS dot11PeerMacAddress;
} DOT11_INTEGRITY_FAIL, *PDOT11_INTEGRITY_FAIL;



typedef enum _DOT11_ROW_STATUS {
    dot11_row_status_unknown = 0,
    dot11_row_status_active = 1,
    dot11_row_status_notInService = 2,
    dot11_row_status_notReady = 3,
    dot11_row_status_createAndGo = 4,
    dot11_row_status_createAndWait = 5,
    dot11_row_status_destroy = 6
} DOT11_ROW_STATUS, * PDOT11_ROW_STATUS;


typedef struct _DOT11_GROUP_ADDRESS {
    ULONG uAddressesIndex;
    DOT11_MAC_ADDRESS dot11MacAddress;
    DOT11_ROW_STATUS GroupAddressesStatus;
} DOT11_GROUP_ADDRESS, * PDOT11_GROUP_ADDRESS;


#define MIN_WEP_KEY_MAPPING_LENGTH              10
#define MAX_NUM_OF_GROUP_ADDRESSES              20
#define MAX_NUM_OF_AUTH_ALGOS                   10


#define DOT11_AUTH_ALGORITHM_OPEN_SYSTEM        0x00000001
#define DOT11_AUTH_ALGORITHM_SHARED_KEY         0x00000002
#define DOT11_AUTH_ALGORITHM_SSN                0x00000003
#define DOT11_AUTH_ALGORITHM_SSN_PSK            0x00000004
#define DOT11_AUTH_ALGORITHM_SSN_NONE           0x00000005


#define DOT11_ALGO_WEP_RC4_40                   0x00000001
#define DOT11_ALGO_TKIP_MIC                     0x00000002
#define DOT11_ALGO_WEP_RC4_104                  0x00000005
#define DOT11_ALGO_WEP_RC4                      DOT11_ALGO_WEP_RC4_40  // BUGBUG: to be removed later!

typedef struct _DOT11_AUTH_ALGO {
    ULONG uAuthAlgoIndex;
    ULONG uAuthAlgo;
    BOOL bAuthAlgoEnabled;
} DOT11_AUTH_ALGO, * PDOT11_AUTH_ALGO;


typedef struct _DOT11_AUTH_LIST {
    ULONG uNumOfEntries;
#ifdef __midl
    [size_is(uNumOfEntries)] PDOT11_AUTH_ALGO pDot11AuthAlgo;
#else
    PDOT11_AUTH_ALGO pDot11AuthAlgo;
#endif
} DOT11_AUTH_LIST, * PDOT11_AUTH_LIST;


#define MAX_WEP_KEY_INDEX                       4
#define MAX_WEP_KEY_LENGTH                      1024 // Bytes


typedef struct _DOT11_KEY_ALGO_TKIP_MIC {
    DOT11_IV48_COUNTER dot11IV48Counter;
    ULONG ulTKIPKeyLength;
    ULONG ulMICKeyLength;
    UCHAR ucTKIPMICKeys[1];                     // Must be the last field.
} DOT11_KEY_ALGO_TKIP_MIC, * PDOT11_KEY_ALGO_TKIP_MIC;


typedef struct _DOT11_WEP_KEY_DATA {
    ULONG uKeyLength;
#ifdef __midl
    [size_is(uKeyLength)] PUCHAR pucKey;
#else
    PUCHAR pucKey;
#endif
} DOT11_WEP_KEY_DATA, * PDOT11_WEP_KEY_DATA;


typedef struct _DOT11_WEP_KEY_ENTRY {
    BOOL bPersist;
    ULONG uWEPKeyIndex;
    DWORD dwAlgorithm;
    DOT11_ROW_STATUS WEPKeyStatus;
    PDOT11_WEP_KEY_DATA pDot11WEPKeyData;
} DOT11_WEP_KEY_ENTRY, * PDOT11_WEP_KEY_ENTRY;


typedef struct _DOT11_WEP_KEY_MAPPING_ENTRY {
    ULONG uWEPKeyMappingIndex;
    DOT11_MAC_ADDRESS WEPKeyMappingAddress;
    DWORD dwAlgorithm;
    BOOL bWEPRowIsOutbound;
    BOOL bStaticWEPKey;
    DOT11_ROW_STATUS WEPKeyMappingStatus;
    PDOT11_WEP_KEY_DATA pDot11WEPKeyMappingData;
} DOT11_WEP_KEY_MAPPING_ENTRY, * PDOT11_WEP_KEY_MAPPING_ENTRY;


typedef struct _DOT11_BSS_LIST {
    ULONG uNumOfBytes;
#ifdef __midl
    [size_is(uNumOfBytes)] PUCHAR pucBuffer;
#else
    PUCHAR pucBuffer;
#endif
} DOT11_BSS_LIST, * PDOT11_BSS_LIST;


typedef struct _DOT11_SEND_8021X_PKT {
    GUID gAdapterId;
    DOT11_MAC_ADDRESS PeerMacAddress;
    ULONG uContext;
    ULONG uBufferLength;
#ifdef __midl
    [size_is(uBufferLength)] UCHAR ucBuffer[];
#else
    UCHAR ucBuffer[1];                         // Must be the last parameter.
#endif
} DOT11_SEND_8021X_PKT, * PDOT11_SEND_8021X_PKT;


//
// 802.1X Filtering -
// On receive path, use the source mac address which can only be unicast.
// On send path, use the destination mac address only if it is an unicast address.
//

typedef struct _DOT11_8021X_FILTER {
    DOT11_MAC_ADDRESS PeerMacAddress; // Unicast mac address of the peer
    BOOL bIsPortControlled;           // TRUE, if the port is controlled by 802.1X
    BOOL bIsPortAuthorized;           // TRUE, if the port is authorized for data packets
} DOT11_8021X_FILTER, * PDOT11_8021X_FILTER;


typedef enum _DOT11_ASSOCIATION_STATE {
    dot11_assoc_state_zero = 0,
    dot11_assoc_state_unauth_unassoc = 1,
    dot11_assoc_state_auth_unassoc = 2,
    dot11_assoc_state_auth_assoc = 3
} DOT11_ASSOCIATION_STATE, * PDOT11_ASSOCIATION_STATE;

#define MAX_NUM_SUPPORTED_RATES                 8

typedef struct _DOT11_ASSOCIATION_INFO {
    DOT11_MAC_ADDRESS PeerMacAddress;
    USHORT usCapabilityInformation;
    USHORT usListenInterval;
    UCHAR ucPeerSupportedRates[MAX_NUM_SUPPORTED_RATES];
    USHORT usAssociationID;
    DOT11_ASSOCIATION_STATE dot11AssociationState;
    LARGE_INTEGER liAssociationUpTime;
    ULONGLONG ulNumOfTxPacketSuccesses;
    ULONGLONG ulNumOfTxPacketFailures;
    ULONGLONG ulNumOfRxPacketSuccesses;
    ULONGLONG ulNumOfRxPacketFailures;
} DOT11_ASSOCIATION_INFO, * PDOT11_ASSOCIATION_INFO;


#define MAX_DOT11_ASSOC_INFO_ENUM_COUNT         20

typedef enum _DOT11_ASSOC_UPCALL_INFO_TYPE {
    dot11_assoc_upcall_info_type_default_key_value,
    dot11_assoc_upcall_info_type_negotiated_ie,
    dot11_assoc_upcall_info_type_offered_ie,
    dot11_assoc_upcall_info_type_last_tx_tsc
} DOT11_ASSOC_UPCALL_INFO_TYPE, * PDOT11_ASSOC_UPCALL_INFO_TYPE;

typedef struct _DOT11_ASSOC_INDICATION_UPCALL {
    DOT11_MAC_ADDRESS PeerMacAddress;
    USHORT usAID;
    USHORT usDefaultKeyID;
} DOT11_ASSOC_INDICATION_UPCALL, *PDOT11_ASSOC_INDICATION_UPCALL;

typedef struct _DOT11_UPCALL_TLV {
    ULONG uType;
    ULONG uLength;
    UCHAR ucValue[1];       // must be the last field
} DOT11_UPCALL_TLV, *PDOT11_UPCALL_TLV;

#define MAX_RECEIVE_UPCALL_BUFFER_SIZE          sizeof(DOT11_MAC_ADDRESS)+1500

#define DOT11_UPCALL_OP_MODE_STATION            0x00000001
#define DOT11_UPCALL_OP_MODE_AP                 0x00000002
#define DOT11_UPCALL_OP_MODE_REPEATER_AP        0x00000003

typedef struct _DOT11_RECEIVE_UPCALL {
    GUID gAdapterId;
    ULONG uUpcallType;
    ULONG uCurOpMode;
    ULONG uActualBufferLength;
    UCHAR ucBuffer[MAX_RECEIVE_UPCALL_BUFFER_SIZE];
} DOT11_RECEIVE_UPCALL, * PDOT11_RECEIVE_UPCALL;


typedef struct _DOT11_DISASSOCIATE_REQUEST {
    USHORT  AID;
    DOT11_MAC_ADDRESS   PeerMacAddress;
    USHORT  usReason;
} DOT11_DISASSOCIATE_REQUEST, *PDOT11_DISASSOCIATE_REQUEST;


typedef struct _DOT11_CIPHER_ALGO {
    ULONG uCipherAlgoIndex;
    ULONG uCipherAlgo;
    BOOL bCipherAlgoEnabled;
} DOT11_CIPHER_ALGO, * PDOT11_CIPHER_ALGO;


typedef struct _DOT11_CIPHER_LIST {
    ULONG uNumOfEntries;
#ifdef __midl
    [size_is(uNumOfEntries)] PDOT11_CIPHER_ALGO pDot11CipherAlgo;
#else
    PDOT11_CIPHER_ALGO pDot11CipherAlgo;
#endif
} DOT11_CIPHER_LIST, * PDOT11_CIPHER_LIST;


typedef struct _DOT11_NIC_SPECIFIC_EXTN_LIST {
    ULONG uNumOfBytes;
#ifdef __midl
    [size_is(uNumOfBytes)] PUCHAR pucBuffer;
#else
    PUCHAR pucBuffer;
#endif
} DOT11_NIC_SPECIFIC_EXTN_LIST, * PDOT11_NIC_SPECIFIC_EXTN_LIST;


//
// Wireless windows APIs.
//

DWORD
WINAPI
WLAllocateBuffer(
    DWORD dwByteCount,
    LPVOID * ppvBuffer
    );

VOID
WINAPI
WLFreeBuffer(
    LPVOID pvBuffer
    );

DWORD
WINAPI
OpenWLAssociationHandle(
    LPWSTR pServerName,
    DWORD dwVersion,
    PWL_ASSOCIATION pWLAssociation,
    LPVOID pvReserved,
    PHANDLE phAssociation
    );

DWORD
WINAPI
CloseWLAssociationHandle(
    HANDLE hAssociation
    );

DWORD
WINAPI
DeleteWLAssociation(
    HANDLE hAssociation
    );

DWORD
WINAPI
SetWLAssociation(
    HANDLE hAssociation,
    DWORD dwVersion,
    PWL_ASSOCIATION pWLAssociation,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetWLAssociation(
    HANDLE hAssociation,
    DWORD dwVersion,
    PWL_ASSOCIATION * ppWLAssociation,
    LPVOID pvReserved
    );

DWORD
WINAPI
EnumWLAssociations(
    LPWSTR pServerName,
    DWORD dwVersion,
    PWL_ASSOCIATION pTemplateWLAssociation,
    DWORD dwPreferredNumEntries,
    PWL_ASSOCIATION * ppWLAssociations,
    LPDWORD pdwNumAssociations,
    LPDWORD pdwResumeHandle,
    LPVOID pvReserved
    );

DWORD
WINAPI
EnumDot11Adapters(
    LPWSTR pServerName,
    DWORD dwVersion,
    PDOT11_ADAPTER pTemplateDot11Adapter,
    DWORD dwPreferredNumEntries,
    PDOT11_ADAPTER * ppDot11Adapters,
    LPDWORD pdwNumAdapters,
    LPDWORD pdwTotalNumAdapters,
    LPDWORD pdwResumeHandle,
    LPVOID pvReserved
    );

DWORD
WINAPI
OpenDot11AdapterHandle(
    LPWSTR pServerName,
    DWORD dwVersion,
    PDOT11_ADAPTER pDot11Adapter,
    LPVOID pvReserved,
    PHANDLE phAdapter
    );

DWORD
WINAPI
CloseDot11AdapterHandle(
    HANDLE hAdapter
    );

DWORD
WINAPI
GetDot11OpModeCapability(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_OPERATION_MODE_CAPABILITY pDot11OpModeCap,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11CurrentOpMode(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_CURRENT_OPERATION_MODE pDot11CurrentOpMode,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11CurrentOpMode(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_CURRENT_OPERATION_MODE pDot11CurrentOpMode,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11OffloadCapability(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_OFFLOAD_CAPABILITY pDot11OffloadCap,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11CurrentOffloadCapability(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_CURRENT_OFFLOAD_CAPABILITY pDot11CurrentOffloadCap,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11CurrentOffloadCapability(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_CURRENT_OFFLOAD_CAPABILITY pDot11CurrentOffloadCap,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11MPDUMaxLength(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11MPDUMaxLength,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11ATIMWindow(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11ATIMWindow,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11ATIMWindow(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11ATIMWindow,
    LPVOID pvReserved
    );

DWORD
WINAPI
PerformDot11ScanRequest(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_SCAN_REQUEST pDot11ScanRequest,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11CurrentPhyType(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_PHY_TYPE pDot11CurrentPhyType,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11CurrentPhyType(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_PHY_TYPE pDot11CurrentPhyType,
    LPVOID pvReserved
    );

DWORD
WINAPI
PerformDot11ResetRequest(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_RESET_REQUEST pDot11ResetRequest,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11OptionalCapability(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_OPTIONAL_CAPABILITY pDot11OptionalCap,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11CurrentOptionalCapability(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_CURRENT_OPTIONAL_CAPABILITY pDot11CurrentOptionalCap,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11CurrentOptionalCapability(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_CURRENT_OPTIONAL_CAPABILITY pDot11CurrentOptionalCap,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11StationID(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_MAC_ADDRESS pDot11StationID,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11StationID(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_MAC_ADDRESS pDot11StationID,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11MediumOccupancyLimit(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11MediumOccupancyLimit,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11MediumOccupancyLimit(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11MediumOccupancyLimit,
    LPVOID pvReserved
    );

DWORD
WINAPI
IsDot11CFPollable(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbIsDot11CFPollable,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11CFPPeriod(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11CFPPeriod,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11CFPPeriod(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11CFPPeriod,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11CFPMaxDuration(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11CFPMaxDuration,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11CFPMaxDuration(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11CFPMaxDuration,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11PowerMgmtMode(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_STA_POWER_MGMT_MODE pDot11PowerMgmtMode,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11PowerMgmtMode(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_STA_POWER_MGMT_MODE pDot11PowerMgmtMode,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11OpRateSet(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_RATE_SET pDot11OpRateSet,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11OpRateSet(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_RATE_SET pDot11OpRateSet,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11BeaconPeriod(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11BeaconPeriod,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11BeaconPeriod(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11BeaconPeriod,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11DTIMPeriod(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11DTIMPeriod,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11DTIMPeriod(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11DTIMPeriod,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11WEPICVErrorCount(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11WEPICVErrorCount,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11MacAddress(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_MAC_ADDRESS pDot11MacAddress,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11RTSThreshold(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11RTSThreshold,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11RTSThreshold(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11RTSThreshold,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11RetryLimit(
    HANDLE hAdapter,
    DWORD dwVersion,
    BOOL bIsShortRetryLimit,
    PULONG puDot11RetryLimit,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11RetryLimit(
    HANDLE hAdapter,
    DWORD dwVersion,
    BOOL bIsShortRetryLimit,
    PULONG puDot11RetryLimit,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11FragmentationThreshold(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11FragmentationThreshold,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11FragmentationThreshold(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11FragmentationThreshold,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11MaxMSDULifetime(
    HANDLE hAdapter,
    DWORD dwVersion,
    BOOL bIsTransmit,
    PULONG puDot11MaxMSDULifetime,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11MaxMSDULifetime(
    HANDLE hAdapter,
    DWORD dwVersion,
    BOOL bIsTransmit,
    PULONG puDot11MaxMSDULifetime,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11Counters(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_COUNTERS_ENTRY pDot11Counters,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11SupportedPhyList(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_PHY_LIST * ppDot11PhyList,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11CurRegDomain(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11CurRegDomain,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11CurRegDomain(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11CurRegDomain,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11TempType(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_TEMP_TYPE pDot11TempType,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11CurAntenna(
    HANDLE hAdapter,
    DWORD dwVersion,
    BOOL bIsTransmit,
    PULONG puDot11CurAntenna,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11CurAntenna(
    HANDLE hAdapter,
    DWORD dwVersion,
    BOOL bIsTransmit,
    PULONG puDot11CurAntenna,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11DiversitySupport(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_DIVERSITY_SUPPORT pDot11DiversitySupport,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11SupportedPowerLevels(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_SUPPORTED_POWER_LEVELS pDot11SupportedPowerLevels,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11CurTxPowerLevel(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11CurTxPowerLevel,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11CurTxPowerLevel(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11CurTxPowerLevel,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11FHSSHopTime(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11HopTime,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11FHSSCurChannelNum(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11FHSSCurChannelNum,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11FHSSCurChannelNum(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11FHSSCurChannelNum,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11FHSSMaxDwellTime(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11FHSSMaxDwellTime,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11FHSSCurDwellTime(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11FHSSCurDwellTime,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11FHSSCurDwellTime(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11FHSSCurDwellTime,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11FHSSCurSet(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11FHSSCurSet,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11FHSSCurSet(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11FHSSCurSet,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11FHSSCurPattern(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11FHSSCurPattern,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11FHSSCurPattern(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11FHSSCurPattern,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11FHSSCurIndex(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11FHSSCurIndex,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11FHSSCurIndex(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11FHSSCurIndex,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11DSSSCurChannel(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11DSSSCurChannel,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11DSSSCurChannel(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11DSSSCurChannel,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11DSSSCCAModeSupported(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11DSSSCCAModeSupported,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11DSSSCurCCAMode(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11DSSSCurCCAMode,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11DSSSCurCCAMode(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11DSSSCurCCAMode,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11DSSSEDThreshold(
    HANDLE hAdapter,
    DWORD dwVersion,
    PLONG plDot11DSSSEDThreshold,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11DSSSEDThreshold(
    HANDLE hAdapter,
    DWORD dwVersion,
    PLONG plDot11DSSSEDThreshold,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11IRCCAWatchDogMaxTimer(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11IRCCAWDMaxTimer,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11IRCCAWatchDogMaxTimer(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11IRCCAWDMaxTimer,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11IRCCAWatchDogMaxCount(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11IRCCAWDMaxCount,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11IRCCAWatchDogMaxCount(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11IRCCAWDMaxCount,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11IRCCAWatchDogMinTimer(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11IRCCAWDMinTimer,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11IRCCAWatchDogMinTimer(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11IRCCAWDMinTimer,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11IRCCAWatchDogMinCount(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11IRCCAWDMinCount,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11IRCCAWatchDogMinCount(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11IRCCAWDMinCount,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11SupportedRegDomainsList(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_REG_DOMAINS_LIST * ppDot11RegDomainsList,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11AntennaList(
    HANDLE hAdapter,
    DWORD dwVersion,
    BOOL bIsTransmit,
    PDOT11_ANTENNA_LIST pDot11AntennaList,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11AntennaList(
    HANDLE hAdapter,
    DWORD dwVersion,
    BOOL bIsTransmit,
    PDOT11_ANTENNA_LIST * ppDot11AntennaList,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11DiversitySelectionRxList(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_DIV_SELECT_RX_LIST pDot11DivSelectRxList,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11DiversitySelectionRxList(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_DIV_SELECT_RX_LIST * ppDot11DivSelectRxList,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11SupportedDataRates(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_SUPPORTED_DATA_RATES_VALUE pDot11SupportedDataRates,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11SMTNotification(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_SMT_NOTIFY_TYPE pDot11SMTNotifyType,
    PBOOL pbDot11SMTNotification,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11SMTNotification(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_SMT_NOTIFY_TYPE pDot11SMTNotifyType,
    PBOOL pbDot11SMTNotification,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11DisconnectedPeer(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_SMT_NOTIFY_TYPE pDot11SMTNotifyType,
    PDOT11_DISCONNECTED_PEER pDot11DisconnectedPeer,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11PrivacyInvoked(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11PrivacyInvoked,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11PrivacyInvoked(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11PrivacyInvoked,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11CurrentBSSID(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_MAC_ADDRESS pDot11CurrentBSSID,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11DesiredBSSID(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_MAC_ADDRESS pDot11DesiredBSSID,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11DesiredBSSID(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_MAC_ADDRESS pDot11DesiredBSSID,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11CurrentSSID(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_SSID pDot11CurrentSSID,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11DesiredSSID(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_SSID pDot11DesiredSSID,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11DesiredSSID(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_SSID pDot11DesiredSSID,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11CurrentBSSType(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_BSS_TYPE pDot11CurrentBSSType,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11DesiredBSSType(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_BSS_TYPE pDot11DesiredBSSType,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11DesiredBSSType(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_BSS_TYPE pDot11DesiredBSSType,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11Exclude8021X(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11Exclude8021X,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11Exclude8021X(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11Exclude8021X,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11Associate(
    HANDLE hAdapter,
    DWORD dwVersion,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11Disassociate(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_DISASSOCIATE_REQUEST pDot11DisassociateRequest,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11AuthResponseTimeOut(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11AuthResponseTimeOut,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11AuthResponseTimeOut(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11AuthResponseTimeOut,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11PrivacyOptionImplemented(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11PrivacyOptionImplemented,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11AssociationResponseTimeOut(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11AssociationResponseTimeOut,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11AssociationResponseTimeOut(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11AssociationResponseTimeOut,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11WEPDefaultKeyID(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11WEPDefaultKeyID,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11WEPDefaultKeyID(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11WEPDefaultKeyID,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11WEPKeyMappingLength(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11WEPKeyMappingLength,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11WEPKeyMappingLength(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11WEPKeyMappingLength,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11ExcludeUnencrypted(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11ExcludeUnencrypted,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11ExcludeUnencrypted(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11ExcludeUnencrypted,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11WEPExcludedCount(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11WEPExcludedCount,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11WEPUndecryptableCount(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11WEPUndecryptableCount,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11GroupAddress(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_GROUP_ADDRESS pDot11GroupAddress,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11GroupAddresses(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_GROUP_ADDRESS * ppDot11GroupAddresses,
    PDWORD pdwNumOfEntries,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11AuthAlgoList(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_AUTH_LIST pDot11AuthList,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11AuthAlgoList(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_AUTH_LIST * ppDot11AuthList,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11WEPDefaultKeyValue(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_WEP_KEY_ENTRY pDot11WEPKeyEntry,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11TKIPSequenceCounter(
    HANDLE hAdapter,
    DWORD dwVersion,
    DWORD dwIndex,
    PDOT11_IV48_COUNTER pDot11TKIPSequenceCounter,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11WEPKeyMappingEntry(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_WEP_KEY_MAPPING_ENTRY pDot11WEPKeyMEntry,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11WEPKeyMappingEntries(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_WEP_KEY_MAPPING_ENTRY * ppDot11WEPKeyMEntries,
    PDWORD pdwNumOfEntries,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11BSSDescriptionList(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_BSS_LIST * ppDot11BSSList,
    LPVOID pvReserved
    );

DWORD
WINAPI
Dot11Send8021XPacket(
    LPWSTR pServerName,
    DWORD dwVersion,
    PDOT11_SEND_8021X_PKT pDot11Send8021XPkt,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot118021XState(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot118021XState,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot118021XState(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot118021XState,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot118021XFilter(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_8021X_FILTER pDot118021XFilter,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot118021XFilters(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_8021X_FILTER * ppDot118021XFilters,
    PDWORD pdwNumOfEntries,
    LPVOID pvReserved
    );

DWORD
WINAPI
EnumDot11AssociationInfo(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_ASSOCIATION_INFO pTemplateDot11AssocInfo,
    DWORD dwPreferredNumEntries,
    PDOT11_ASSOCIATION_INFO * ppDot11AssocInfo,
    LPDWORD pdwNumAssocInfo,
    LPDWORD pdwTotalNumAssocInfo,
    LPDWORD pdwResumeHandle,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11OFDMCurrentFrequency(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11OFDMCurrentFrequency,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11OFDMCurrentFrequency(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11OFDMCurrentFrequency,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11OFDMTIThreshold(
    HANDLE hAdapter,
    DWORD dwVersion,
    PLONG plDot11OFDMTIThreshold,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11OFDMTIThreshold(
    HANDLE hAdapter,
    DWORD dwVersion,
    PLONG plDot11OFDMTIThreshold,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11OFDMFreqBandsSupported(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11OFDMFreqBandsSupported,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11HRDSSSShortPreambleOptImp(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11HRDSSSShortPreambleOptImp,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11HRDSSSPBCCOptionImplemented(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11HRDSSSPBCCOptionImplemented,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11HRDSSSChannelAgilityPresent(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11HRDSSSChannelAgilityPresent,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11HRDSSSChannelAgilityEnabled(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11HRDSSSChannelAgilityEnabled,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11HRDSSSChannelAgilityEnabled(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11HRDSSSChannelAgilityEnabled,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11HRCCAModeSupported(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11HRCCAModeSupported,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11WEPDefaultMulticastKeyID(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11WEPDefaultMulticastKeyID,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11WEPDefaultMulticastKeyID(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11WEPDefaultMulticastKeyID,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11MultiDomainCapabilityImp(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11MultiDomainCapabilityImp,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11MultiDomainCapabilityEnabled(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11MultiDomainCapabilityEnabled,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11MultiDomainCapabilityEnabled(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11MultiDomainCapabilityEnabled,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11CountryString(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_COUNTRY_STRING pDot11CountryString,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11CountryString(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_COUNTRY_STRING pDot11CountryString,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11MultiDomainCapability(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_MULTI_DOMAIN_CAPABILITY_ENTRY pDot11MultiDomainCapability,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11MultiDomainCapabilities(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_MULTI_DOMAIN_CAPABILITY_ENTRY * ppDot11MultiDomainCapabilities,
    PDWORD pdwNumOfEntries,
    LPVOID pvReserved
    );


DWORD
WINAPI
SetDot11EHCCPrimeRadix(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11EHCCPrimeRadix,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11EHCCPrimeRadix(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11EHCCPrimeRadix,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11EHCCNumOfChannelsFamilyIndex(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11EHCCNumOfChannelsFamilyIndex,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11EHCCNumOfChannelsFamilyIndex(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11EHCCNumOfChannelsFamilyIndex,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11EHCCCapabilityImp(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11EHCCCapabilityImp,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11EHCCCapabilityEnabled(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11EHCCCapabilityEnabled,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11EHCCCapabilityEnabled(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11EHCCCapabilityEnabled,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11HopAlgoAdopted(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_HOP_ALGO_ADOPTED pDot11HopAlgoAdopted,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11HopAlgoAdopted(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_HOP_ALGO_ADOPTED pDot11HopAlgoAdopted,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11RandomTableFlag(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11RandomTableFlag,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11RandomTableFlag(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11RandomTableFlag,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11NumberOfHoppingSets(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11NumberOfHoppingSets,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11HopModulus(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11HopModulus,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11HopOffset(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11HopOffset,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11HoppingPatternEntry(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_HOPPING_PATTERN_ENTRY pDot11HoppingPatternEntry,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11HoppingPatternEntries(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_HOPPING_PATTERN_ENTRY * ppDot11HoppingPatternEntries,
    PDWORD pdwNumOfEntries,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11AssociationIdleTimeout(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11AssociationIdleTimeout,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11AssociationIdleTimeout(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11AssociationIdleTimeout,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11WPAUnicastCipherAlgoList(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_CIPHER_LIST pDot11CipherList,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11WPAUnicastCipherAlgoList(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_CIPHER_LIST * ppDot11CipherList,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11WPAMulticastCipherAlgoList(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_CIPHER_LIST pDot11CipherList,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11WPAMulticastCipherAlgoList(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_CIPHER_LIST * ppDot11CipherList,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11RepeaterAP(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11RepeaterAP,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11RepeaterAP(
    HANDLE hAdapter,
    DWORD dwVersion,
    PBOOL pbDot11RepeaterAP,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11RepeaterWEPDefaultKeyID(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11RepeaterWEPDefaultKeyID,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11RepeaterWEPDefaultKeyID(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11RepeaterWEPDefaultKeyID,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11RepeaterWEPDefaultMulticastKeyID(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11RepeaterWEPDefaultMulticastKeyID,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11RepeaterWEPDefaultMulticastKeyID(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11RepeaterWEPDefaultMulticastKeyID,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11RepeaterWEPDefaultKeyValue(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_WEP_KEY_ENTRY pDot11WEPKeyEntry,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11RepeaterAuthAlgoList(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_AUTH_LIST pDot11AuthList,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11RepeaterAuthAlgoList(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_AUTH_LIST * ppDot11AuthList,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11NICSpecificExtensionList(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_NIC_SPECIFIC_EXTN_LIST pDot11NICSpecificExtnList,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11NICSpecificExtensionList(
    HANDLE hAdapter,
    DWORD dwVersion,
    PDOT11_NIC_SPECIFIC_EXTN_LIST * ppDot11NICSpecificExtnList,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11RSSI(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11RSSI,
    LPVOID pvReserved
    );

DWORD
WINAPI
SetDot11MaxAssociations(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11MaxAssociations,
    LPVOID pvReserved
    );

DWORD
WINAPI
GetDot11MaxAssociations(
    HANDLE hAdapter,
    DWORD dwVersion,
    PULONG puDot11MaxAssociations,
    LPVOID pvReserved
    );

#ifdef __cplusplus
}
#endif


#endif // _WIRELESS_

