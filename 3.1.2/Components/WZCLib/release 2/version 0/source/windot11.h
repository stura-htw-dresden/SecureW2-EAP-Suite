/*++

    Copyright (C) 2002  Microsoft Corporation

Module Name:

    windot11.h

Abstract:

    External header file for 802.11 NIC specifications.

--*/

#ifndef __WINDOT11_H__
#define __WINDOT11_H__


//
// Max size of an 802.11 PDU, including the MAC header, frame body and FCS.
//
#define DOT11_MAX_PDU_SIZE                          2346

//
// Min size of an 802.11 PDU, including the MAC header, frame body and FCS.
//
#define DOT11_MIN_PDU_SIZE                          (256)

#define DOT11_MAX_NUM_DEFAULT_KEY                   4

#define OID_DOT11_NDIS_START                        0x0D010300

//
// Offload Capability OIDs
//

#define OID_DOT11_OFFLOAD_CAPABILITY                (OID_DOT11_NDIS_START + 0)
    // Capability flags
    #define DOT11_HW_WEP_SUPPORTED_TX               0x00000001
    #define DOT11_HW_WEP_SUPPORTED_RX               0x00000002
    #define DOT11_HW_FRAGMENTATION_SUPPORTED        0x00000004
    #define DOT11_HW_DEFRAGMENTATION_SUPPORTED      0x00000008
    #define DOT11_HW_MSDU_AUTH_SUPPORTED_TX         0x00000010
    #define DOT11_HW_MSDU_AUTH_SUPPORTED_RX         0x00000020
    // WEP Algorithm flags
    #define DOT11_CONF_ALGO_WEP_RC4                 0x00000001  // WEP RC4
    #define DOT11_CONF_ALGO_TKIP                    0x00000002  // BUGBUG: Remove after Review! TKIP RC4
    // Integrity Algorithm flags
    #define DOT11_AUTH_ALGO_MICHAEL                 0x00000001  // Michael
    typedef struct _DOT11_OFFLOAD_CAPABILITY {
        ULONG uReserved;
        ULONG uFlags;
        ULONG uSupportedWEPAlgorithms;
        ULONG uNumOfReplayWindows;
        ULONG uMaxWEPKeyMappingLength;
        ULONG uSupportedAuthAlgorithms;
        ULONG uMaxAuthKeyMappingLength;
    } DOT11_OFFLOAD_CAPABILITY, * PDOT11_OFFLOAD_CAPABILITY;

#define OID_DOT11_CURRENT_OFFLOAD_CAPABILITY        (OID_DOT11_NDIS_START + 1)
    typedef struct _DOT11_CURRENT_OFFLOAD_CAPABILITY {
        ULONG uReserved;
        ULONG uFlags;
    } DOT11_CURRENT_OFFLOAD_CAPABILITY, * PDOT11_CURRENT_OFFLOAD_CAPABILITY;


//
// WEP Offload
//

#define OID_DOT11_WEP_OFFLOAD                       (OID_DOT11_NDIS_START + 2)
    typedef enum _DOT11_OFFLOAD_TYPE {
        dot11_offload_type_wep = 1,
        dot11_offload_type_auth = 2
    } DOT11_OFFLOAD_TYPE, * PDOT11_OFFLOAD_TYPE;
    typedef struct _DOT11_IV48_COUNTER {
        ULONG uIV32Counter;
        USHORT usIV16Counter;
    } DOT11_IV48_COUNTER, * PDOT11_IV48_COUNTER;
    typedef struct _DOT11_WEP_OFFLOAD {
        ULONG uReserved;
        HANDLE hOffloadContext;
        HANDLE hOffload;
        DOT11_OFFLOAD_TYPE dot11OffloadType;
        DWORD dwAlgorithm;
        BOOL bRowIsOutbound;
        BOOL bUseDefault;
        ULONG uFlags;
        UCHAR ucMacAddress[6];
        ULONG uNumOfRWsOnPeer;
        ULONG uNumOfRWsOnMe;
        DOT11_IV48_COUNTER dot11IV48Counters[16];
        USHORT usDot11RWBitMaps[16];
        USHORT usKeyLength;
        UCHAR ucKey[1];             // Must be the last field.
    } DOT11_WEP_OFFLOAD, * PDOT11_WEP_OFFLOAD;

#define OID_DOT11_WEP_UPLOAD                        (OID_DOT11_NDIS_START + 3)
    typedef struct _DOT11_WEP_UPLOAD {
        ULONG uReserved;
        DOT11_OFFLOAD_TYPE dot11OffloadType;
        HANDLE hOffload;
        ULONG uNumOfRWsUsed;
        DOT11_IV48_COUNTER dot11IV48Counters[16];
        USHORT usDot11RWBitMaps[16];
    } DOT11_WEP_UPLOAD, * PDOT11_WEP_UPLOAD;

#define OID_DOT11_DEFAULT_WEP_OFFLOAD               (OID_DOT11_NDIS_START + 4)
    typedef enum _DOT11_KEY_DIRECTION {
        dot11_key_direction_both = 1,
        dot11_key_direction_inbound = 2,
        dot11_key_direction_outbound = 3
    } DOT11_KEY_DIRECTION, * PDOT11_KEY_DIRECTION;
    typedef struct _DOT11_DEFAULT_WEP_OFFLOAD {
        ULONG uReserved;
        HANDLE hOffloadContext;
        HANDLE hOffload;
        DWORD dwIndex;
        DOT11_OFFLOAD_TYPE dot11OffloadType;
        DWORD dwAlgorithm;
        ULONG uFlags;
        DOT11_KEY_DIRECTION dot11KeyDirection;
        UCHAR ucMacAddress[6];
        ULONG uNumOfRWsOnMe;
        DOT11_IV48_COUNTER dot11IV48Counters[16];
        USHORT usDot11RWBitMaps[16];
        USHORT usKeyLength;
        UCHAR ucKey[1];             // Must be the last field.
    } DOT11_DEFAULT_WEP_OFFLOAD, * PDOT11_DEFAULT_WEP_OFFLOAD;

#define OID_DOT11_DEFAULT_WEP_UPLOAD                (OID_DOT11_NDIS_START + 5)
    typedef struct _DOT11_DEFAULT_WEP_UPLOAD {
        ULONG uReserved;
        DOT11_OFFLOAD_TYPE dot11OffloadType;
        HANDLE hOffload;
        ULONG uNumOfRWsUsed;
        DOT11_IV48_COUNTER dot11IV48Counters[16];
        USHORT usDot11RWBitMaps[16];
    } DOT11_DEFAULT_WEP_UPLOAD, * PDOT11_DEFAULT_WEP_UPLOAD;

//
// Fragmentation/Defragmentation Offload
//

#define OID_DOT11_MPDU_MAX_LENGTH                   (OID_DOT11_NDIS_START + 6)
    // ULONG (in bytes)

//
// 802.11 Configuration OIDs
//

//
// OIDs for Mandatory Functions
//

#define OID_DOT11_OPERATION_MODE_CAPABILITY         (OID_DOT11_NDIS_START + 7)
    #define DOT11_OPERATION_MODE_UNKNOWN            0x00000000
    #define DOT11_OPERATION_MODE_STATION            0x00000001
    #define DOT11_OPERATION_MODE_AP                 0x00000002
    typedef struct _DOT11_OPERATION_MODE_CAPABILITY {
        ULONG uReserved;
        ULONG uMajorVersion;
        ULONG uMinorVersion;
        ULONG uNumOfTXBuffers;
        ULONG uNumOfRXBuffers;
        ULONG uOpModeCapability;
    } DOT11_OPERATION_MODE_CAPABILITY, * PDOT11_OPERATION_MODE_CAPABILITY;

#define OID_DOT11_CURRENT_OPERATION_MODE            (OID_DOT11_NDIS_START + 8)
    typedef struct _DOT11_CURRENT_OPERATION_MODE {
        ULONG uReserved;
        ULONG uCurrentOpMode;
    } DOT11_CURRENT_OPERATION_MODE, * PDOT11_CURRENT_OPERATION_MODE;

#define OID_DOT11_CURRENT_PACKET_FILTER             (OID_DOT11_NDIS_START + 9)
    #define DOT11_PACKET_TYPE_DIRECTED_CTRL         0x00000001
    // Indicate all 802.11 unicast control packets.
    #define DOT11_PACKET_TYPE_DIRECTED_MGMT         0x00000002
    // Indicate all 802.11 unicast management packets.
    #define DOT11_PACKET_TYPE_DIRECTED_DATA         0x00000004
    // Indicate all 802.11 unicast data packets.
    #define DOT11_PACKET_TYPE_MULTICAST_CTRL        0x00000008
    // Indicate all 802.11 multicast control packets.
    #define DOT11_PACKET_TYPE_MULTICAST_MGMT        0x00000010
    // Indicate all 802.11 multicast management packets.
    #define DOT11_PACKET_TYPE_MULTICAST_DATA        0x00000020
    // Indicate all 802.11 multicast data packets.
    #define DOT11_PACKET_TYPE_BROADCAST_CTRL        0x00000040
    // Indicate all 802.11 broadcast control packets.
    #define DOT11_PACKET_TYPE_BROADCAST_MGMT        0x00000080
    // Indicate all 802.11 broadcast management packets.
    #define DOT11_PACKET_TYPE_BROADCAST_DATA        0x00000100
    // Indicate all 802.11 broadcast data packets.
    #define DOT11_PACKET_TYPE_PROMISCUOUS_CTRL      0x00000200
    // Move into promiscuous mode and indicate all 802.11 control packets.
    #define DOT11_PACKET_TYPE_PROMISCUOUS_MGMT      0x00000400
    // Move into promiscuous mode and indicate all 802.11 control packets.
    #define DOT11_PACKET_TYPE_PROMISCUOUS_DATA      0x00000800
    // Move into promiscuous mode and indicate all 802.11 control packets.
    #define DOT11_PACKET_TYPE_ALL_MULTICAST_CTRL    0x00001000
    // Indicate all 802.11 multicast control packets.
    #define DOT11_PACKET_TYPE_ALL_MULTICAST_MGMT    0x00002000
    // Indicate all 802.11 multicast management packets.
    #define DOT11_PACKET_TYPE_ALL_MULTICAST_DATA    0x00004000
    // Indicate all 802.11 multicast data packets.
    #define DOT11_PACKET_TYPE_RESERVED  (~(             \
                DOT11_PACKET_TYPE_DIRECTED_CTRL |       \
                DOT11_PACKET_TYPE_DIRECTED_MGMT |       \
                DOT11_PACKET_TYPE_DIRECTED_DATA |       \
                DOT11_PACKET_TYPE_MULTICAST_CTRL |      \
                DOT11_PACKET_TYPE_MULTICAST_MGMT |      \
                DOT11_PACKET_TYPE_MULTICAST_DATA |      \
                DOT11_PACKET_TYPE_BROADCAST_CTRL |      \
                DOT11_PACKET_TYPE_BROADCAST_MGMT |      \
                DOT11_PACKET_TYPE_BROADCAST_DATA |      \
                DOT11_PACKET_TYPE_PROMISCUOUS_CTRL |    \
                DOT11_PACKET_TYPE_PROMISCUOUS_MGMT |    \
                DOT11_PACKET_TYPE_PROMISCUOUS_DATA |    \
                DOT11_PACKET_TYPE_ALL_MULTICAST_CTRL |  \
                DOT11_PACKET_TYPE_ALL_MULTICAST_MGMT |  \
                DOT11_PACKET_TYPE_ALL_MULTICAST_DATA |  \
                0                                       \
                ))
    // All the reserved bits

#define OID_DOT11_ATIM_WINDOW                       (OID_DOT11_NDIS_START + 10)
    // ULONG (in TUs)

#define OID_DOT11_SCAN_REQUEST                      (OID_DOT11_NDIS_START + 11)
    typedef enum _DOT11_BSS_TYPE {
        dot11_BSS_type_infrastructure = 1,
        dot11_BSS_type_independent = 2,
        dot11_BSS_type_any = 3
    } DOT11_BSS_TYPE, * PDOT11_BSS_TYPE;

#ifdef __midl
    typedef struct _DOT11_MAC_ADDRESS {
        UCHAR ucDot11MacAddress[6];
    } DOT11_MAC_ADDRESS, * PDOT11_MAC_ADDRESS;
#else
    typedef UCHAR DOT11_MAC_ADDRESS[6];
    typedef DOT11_MAC_ADDRESS * PDOT11_MAC_ADDRESS;
#endif

    #define DOT11_SSID_MAX_LENGTH   32
    typedef struct _DOT11_SSID {
        ULONG uSSIDLength;
        UCHAR ucSSID[DOT11_SSID_MAX_LENGTH];
    } DOT11_SSID, * PDOT11_SSID;
    typedef enum _DOT11_SCAN_TYPE {
        dot11_scan_type_active = 1,
        dot11_scan_type_passive = 2
    } DOT11_SCAN_TYPE, * PDOT11_SCAN_TYPE;
    typedef struct _DOT11_SCAN_REQUEST {
        DOT11_BSS_TYPE dot11BSSType;
        DOT11_MAC_ADDRESS dot11BSSID;
        DOT11_SSID dot11SSID;
        DOT11_SCAN_TYPE dot11ScanType;
        BOOL bRestrictedScan;
        BOOL bUseRequestIE;
        ULONG uRequestIDsOffset;
        ULONG uNumOfRequestIDs;
        ULONG uPhyTypesOffset;
        ULONG uNumOfPhyTypes;
        ULONG uIEsOffset;
        ULONG uIEsLength;
        UCHAR ucBuffer[1];
    } DOT11_SCAN_REQUEST, * PDOT11_SCAN_REQUEST;

#define OID_DOT11_CURRENT_PHY_TYPE                  (OID_DOT11_NDIS_START + 12)
    typedef enum _DOT11_PHY_TYPE {
        dot11_phy_type_unknown = 0,
        dot11_phy_type_fhss = 1,
        dot11_phy_type_dsss = 2,
        dot11_phy_type_irbaseband = 3,
        dot11_phy_type_ofdm = 4,
        dot11_phy_type_hrdsss = 5
    } DOT11_PHY_TYPE, * PDOT11_PHY_TYPE;

#define OID_DOT11_JOIN_REQUEST                      (OID_DOT11_NDIS_START + 13)
    #define DOT11_RATE_SET_MAX_LENGTH               126
    typedef struct _DOT11_RATE_SET {
        ULONG uRateSetLength;
        UCHAR ucRateSet[DOT11_RATE_SET_MAX_LENGTH];
    } DOT11_RATE_SET, * PDOT11_RATE_SET;
    // Capability Information Flags - Exactly maps to the bit positions
    // in the Capability Information field of the beacon and probe response frames.
    #define DOT11_CAPABILITY_INFO_ESS               0x0001
    #define DOT11_CAPABILITY_INFO_IBSS              0x0002
    #define DOT11_CAPABILITY_INFO_CF_POLLABLE       0x0004
    #define DOT11_CAPABILITY_INFO_CF_POLL_REQ       0x0008
    #define DOT11_CAPABILITY_INFO_PRIVACY           0x0010
    #define DOT11_CAPABILITY_SHORT_PREAMBLE         0x0020
    #define DOT11_CAPABILITY_PBCC                   0x0040
    #define DOT11_CAPABILITY_CHANNEL_AGILITY        0x0080

    typedef struct _DOT11_BSS_DESCRIPTION {
        ULONG uReserved;                        // Passed-in as 0 and must be ignored for now.
        DOT11_MAC_ADDRESS dot11BSSID;
        DOT11_BSS_TYPE dot11BSSType;
        USHORT usBeaconPeriod;
        ULONGLONG ullTimestamp;
        USHORT usCapabilityInformation;
        ULONG uBufferLength;
        UCHAR ucBuffer[1];              // Must be the last field.
    } DOT11_BSS_DESCRIPTION, * PDOT11_BSS_DESCRIPTION;
    typedef struct _DOT11_JOIN_REQUEST {
        ULONG uJoinFailureTimeout;
        DOT11_RATE_SET OperationalRateSet;
        ULONG uChCenterFrequency;
        DOT11_BSS_DESCRIPTION dot11BSSDescription;  // Must be the last field.
    } DOT11_JOIN_REQUEST, * PDOT11_JOIN_REQUEST;

#define OID_DOT11_START_REQUEST                     (OID_DOT11_NDIS_START + 14)
    typedef struct _DOT11_START_REQUEST {
        ULONG uStartFailureTimeout;
        DOT11_RATE_SET OperationalRateSet;
        ULONG uChCenterFrequency;
        DOT11_BSS_DESCRIPTION dot11BSSDescription;  // Must be the last field.
    } DOT11_START_REQUEST, * PDOT11_START_REQUEST;

#define OID_DOT11_UPDATE_IE                         (OID_DOT11_NDIS_START + 15)
typedef enum _DOT11_UPDATE_IE_OP {
    dot11_update_ie_op_create_replace = 1,
    dot11_update_ie_op_delete = 2,
} DOT11_UPDATE_IE_OP, * PDOT11_UPDATE_IE_OP;

typedef struct _DOT11_UPDATE_IE {
    DOT11_UPDATE_IE_OP dot11UpdateIEOp;
    ULONG uBufferLength;
    UCHAR ucBuffer[1];          // Must be the last field.
} DOT11_UPDATE_IE, * PDOT11_UPDATE_IE;

#define OID_DOT11_RESET_REQUEST                     (OID_DOT11_NDIS_START + 16)
    typedef enum _DOT11_RESET_TYPE {
        dot11_reset_type_phy = 1,
        dot11_reset_type_mac = 2,
        dot11_reset_type_phy_and_mac = 3
    } DOT11_RESET_TYPE, * PDOT11_RESET_TYPE;
    typedef struct _DOT11_RESET_REQUEST {
        DOT11_RESET_TYPE dot11ResetType;
        DOT11_MAC_ADDRESS dot11MacAddress;
        BOOL bSetDefaultMIB;
    } DOT11_RESET_REQUEST, * PDOT11_RESET_REQUEST;

#define OID_DOT11_NIC_POWER_STATE                   (OID_DOT11_NDIS_START + 17)
    // BOOL

typedef UCHAR DOT11_COUNTRY_STRING[3];
typedef DOT11_COUNTRY_STRING * PDOT11_COUNTRY_STRING;

//
// OIDs for Optional Functions
//

#define OID_DOT11_OPTIONAL_CAPABILITY               (OID_DOT11_NDIS_START + 18)
    typedef struct _DOT11_OPTIONAL_CAPABILITY {
        ULONG uReserved;
        BOOL bDot11PCF;
        BOOL bDot11PCFMPDUTransferToPC;
        BOOL bStrictlyOrderedServiceClass;
    } DOT11_OPTIONAL_CAPABILITY, * PDOT11_OPTIONAL_CAPABILITY;

#define OID_DOT11_CURRENT_OPTIONAL_CAPABILITY       (OID_DOT11_NDIS_START + 19)
    typedef struct _DOT11_CURRENT_OPTIONAL_CAPABILITY {
        ULONG uReserved;
        BOOL bDot11CFPollable;
        BOOL bDot11PCF;
        BOOL bDot11PCFMPDUTransferToPC;
        BOOL bStrictlyOrderedServiceClass;
    } DOT11_CURRENT_OPTIONAL_CAPABILITY, * PDOT11_CURRENT_OPTIONAL_CAPABILITY;

//
// 802.11 MIB OIDs
//

//
// OIDs for dot11StationConfigEntry
//

#define OID_DOT11_STATION_ID                        (OID_DOT11_NDIS_START + 20)
    // DOT11_MAC_ADDRESS

#define OID_DOT11_MEDIUM_OCCUPANCY_LIMIT            (OID_DOT11_NDIS_START + 21)
    // ULONG (in TUs)

#define OID_DOT11_CF_POLLABLE                       (OID_DOT11_NDIS_START + 22)
    // BOOL

#define OID_DOT11_CFP_PERIOD                        (OID_DOT11_NDIS_START + 23)
    // ULONG (in DTIM intervals)

#define OID_DOT11_CFP_MAX_DURATION                  (OID_DOT11_NDIS_START + 24)
    // ULONG (in TUs)

#define OID_DOT11_POWER_MGMT_MODE                   (OID_DOT11_NDIS_START + 25)
    typedef enum _DOT11_POWER_MODE {
        dot11_power_mode_unknown = 0,
        dot11_power_mode_active = 1,
        dot11_power_mode_powersave = 2
    } DOT11_POWER_MODE, * PDOT11_POWER_MODE;
    #define DOT11_POWER_SAVE_LEVEL_MAX_PSP      1
    // Maximum power save polling.
    #define DOT11_POWER_SAVE_LEVEL_FAST_PSP     2
    // Fast power save polling.
    #define DOT11_POWER_SAVE_LEVEL_NO_PSP       3
    // Do not perform power save polling.
    typedef struct _DOT11_POWER_MGMT_MODE {
        DOT11_POWER_MODE dot11PowerMode;
        ULONG uPowerSaveLevel;
        USHORT usListenInterval;
        USHORT usAID;
        BOOL bReceiveDTIMs;
    } DOT11_POWER_MGMT_MODE, * PDOT11_POWER_MGMT_MODE;

#define OID_DOT11_OPERATIONAL_RATE_SET              (OID_DOT11_NDIS_START + 26)
    // DOT11_RATE_SET

#define OID_DOT11_BEACON_PERIOD                     (OID_DOT11_NDIS_START + 27)
    // ULONG (in TUs)

#define OID_DOT11_DTIM_PERIOD                       (OID_DOT11_NDIS_START + 28)
    // ULONG (in beacon intervals)

//
// OIDs for Dot11PrivacyEntry
//

#define OID_DOT11_WEP_ICV_ERROR_COUNT               (OID_DOT11_NDIS_START + 29)
    // ULONG

//
// OIDs for dot11OperationEntry
//

#define OID_DOT11_MAC_ADDRESS                       (OID_DOT11_NDIS_START + 30)
    // DOT11_MAC_ADDRESS

#define OID_DOT11_RTS_THRESHOLD                     (OID_DOT11_NDIS_START + 31)
    // ULONG (in number of octets)

#define OID_DOT11_SHORT_RETRY_LIMIT                 (OID_DOT11_NDIS_START + 32)
    // ULONG

#define OID_DOT11_LONG_RETRY_LIMIT                  (OID_DOT11_NDIS_START + 33)
    // ULONG

#define OID_DOT11_FRAGMENTATION_THRESHOLD           (OID_DOT11_NDIS_START + 34)
    // ULONG (in number of octets)

#define OID_DOT11_MAX_TRANSMIT_MSDU_LIFETIME        (OID_DOT11_NDIS_START + 35)
    // ULONG (in TUs)

#define OID_DOT11_MAX_RECEIVE_LIFETIME              (OID_DOT11_NDIS_START + 36)
    // ULONG (in TUs)

//
// OIDs for dot11CountersEntry
//

#define OID_DOT11_COUNTERS_ENTRY                    (OID_DOT11_NDIS_START + 37)
    typedef struct _DOT11_COUNTERS_ENTRY {
        ULONG uTransmittedFragmentCount;
        ULONG uMulticastTransmittedFrameCount;
        ULONG uFailedCount;
        ULONG uRetryCount;
        ULONG uMultipleRetryCount;
        ULONG uFrameDuplicateCount;
        ULONG uRTSSuccessCount;
        ULONG uRTSFailureCount;
        ULONG uACKFailureCount;
        ULONG uReceivedFragmentCount;
        ULONG uMulticastReceivedFrameCount;
        ULONG uFCSErrorCount;
        ULONG uTransmittedFrameCount;
    } DOT11_COUNTERS_ENTRY, * PDOT11_COUNTERS_ENTRY;

//
// OIDs for dot11PhyOperationEntry
//

#define OID_DOT11_SUPPORTED_PHY_TYPES               (OID_DOT11_NDIS_START + 38)
    typedef struct _DOT11_SUPPORTED_PHY_TYPES {
        ULONG uNumOfEntries;
        ULONG uTotalNumOfEntries;
        DOT11_PHY_TYPE dot11PHYType[1];
    } DOT11_SUPPORTED_PHY_TYPES, * PDOT11_SUPPORTED_PHY_TYPES;

#define OID_DOT11_CURRENT_REG_DOMAIN                (OID_DOT11_NDIS_START + 39)
    #define DOT11_REG_DOMAIN_OTHER                  0x00000000
    #define DOT11_REG_DOMAIN_FCC                    0x00000010
    #define DOT11_REG_DOMAIN_DOC                    0x00000020
    #define DOT11_REG_DOMAIN_ETSI                   0x00000030
    #define DOT11_REG_DOMAIN_SPAIN                  0x00000031
    #define DOT11_REG_DOMAIN_FRANCE                 0x00000032
    #define DOT11_REG_DOMAIN_MKK                    0x00000040
    // ULONG

#define OID_DOT11_TEMP_TYPE                         (OID_DOT11_NDIS_START + 40)
    typedef enum _DOT11_TEMP_TYPE {
        dot11_temp_type_unknown = 0,
        dot11_temp_type_1 = 1,
        dot11_temp_type_2 = 2
    } DOT11_TEMP_TYPE, * PDOT11_TEMP_TYPE;

//
// OIDs for dot11PhyAntennaEntry
//

#define OID_DOT11_CURRENT_TX_ANTENNA                (OID_DOT11_NDIS_START + 41)
    // ULONG

#define OID_DOT11_DIVERSITY_SUPPORT                 (OID_DOT11_NDIS_START + 42)
    typedef enum _DOT11_DIVERSITY_SUPPORT {
        dot11_diversity_support_unknown = 0,
        dot11_diversity_support_fixedlist = 1,
        dot11_diversity_support_notsupported = 2,
        dot11_diversity_support_dynamic = 3
    } DOT11_DIVERSITY_SUPPORT, * PDOT11_DIVERSITY_SUPPORT;

#define OID_DOT11_CURRENT_RX_ANTENNA                (OID_DOT11_NDIS_START + 43)
    // ULONG

//
// OIDs for dot11PhyTxPowerEntry
//

#define OID_DOT11_SUPPORTED_POWER_LEVELS            (OID_DOT11_NDIS_START + 44)
    typedef struct _DOT11_SUPPORTED_POWER_LEVELS {
        ULONG uNumOfSupportedPowerLevels;
        ULONG uTxPowerLevelValues[8];
    } DOT11_SUPPORTED_POWER_LEVELS, * PDOT11_SUPPORTED_POWER_LEVELS;

#define OID_DOT11_CURRENT_TX_POWER_LEVEL            (OID_DOT11_NDIS_START + 45)
    // ULONG

//
// OIDs for dot11PhyFHSSEntry
//

#define OID_DOT11_HOP_TIME                          (OID_DOT11_NDIS_START + 46)
    // ULONG (in microseconds)

#define OID_DOT11_CURRENT_CHANNEL_NUMBER            (OID_DOT11_NDIS_START + 47)
    // ULONG

#define OID_DOT11_MAX_DWELL_TIME                    (OID_DOT11_NDIS_START + 48)
    // ULONG (in TUs)

#define OID_DOT11_CURRENT_DWELL_TIME                (OID_DOT11_NDIS_START + 49)
    // ULONG (in TUs)

#define OID_DOT11_CURRENT_SET                       (OID_DOT11_NDIS_START + 50)
    // ULONG

#define OID_DOT11_CURRENT_PATTERN                   (OID_DOT11_NDIS_START + 51)
    // ULONG

#define OID_DOT11_CURRENT_INDEX                     (OID_DOT11_NDIS_START + 52)
    // ULONG

//
// OIDs for dot11PhyDSSSEntry
//

#define OID_DOT11_CURRENT_CHANNEL                   (OID_DOT11_NDIS_START + 53)
    // ULONG

#define OID_DOT11_CCA_MODE_SUPPORTED                (OID_DOT11_NDIS_START + 54)
    #define DOT11_CCA_MODE_ED_ONLY              0x00000001
    #define DOT11_CCA_MODE_CS_ONLY              0x00000002
    #define DOT11_CCA_MODE_ED_and_CS                0x00000004
    // ULONG

#define OID_DOT11_CURRENT_CCA_MODE                  (OID_DOT11_NDIS_START + 55)
    // ULONG

#define OID_DOT11_ED_THRESHOLD                      (OID_DOT11_NDIS_START + 56)
    // LONG (in "dBm"s)

//
// OIDs for dot11PhyIREntry
//

#define OID_DOT11_CCA_WATCHDOG_TIMER_MAX            (OID_DOT11_NDIS_START + 57)
    // ULONG (in nanoseconds)

#define OID_DOT11_CCA_WATCHDOG_COUNT_MAX            (OID_DOT11_NDIS_START + 58)
    // ULONG

#define OID_DOT11_CCA_WATCHDOG_TIMER_MIN            (OID_DOT11_NDIS_START + 59)
    // ULONG (in nanoseconds)

#define OID_DOT11_CCA_WATCHDOG_COUNT_MIN            (OID_DOT11_NDIS_START + 60)
    // ULONG

//
// OIDs for dot11RegDomainsSupportEntry
//

#define OID_DOT11_REG_DOMAINS_SUPPORT_VALUE         (OID_DOT11_NDIS_START + 61)
    typedef struct _DOT11_REG_DOMAIN_VALUE {
        ULONG uRegDomainsSupportIndex;
        ULONG uRegDomainsSupportValue;
    } DOT11_REG_DOMAIN_VALUE, * PDOT11_REG_DOMAIN_VALUE;
    typedef struct _DOT11_REG_DOMAINS_SUPPORT_VALUE {
        ULONG uNumOfEntries;
        ULONG uTotalNumOfEntries;
        DOT11_REG_DOMAIN_VALUE dot11RegDomainValue[1];
    } DOT11_REG_DOMAINS_SUPPORT_VALUE, * PDOT11_REG_DOMAINS_SUPPORT_VALUE;

//
// OIDs for dot11AntennaListEntry
//

#define OID_DOT11_SUPPORTED_TX_ANTENNA              (OID_DOT11_NDIS_START + 62)
    typedef struct _DOT11_SUPPORTED_ANTENNA {
        ULONG uAntennaListIndex;                    // Between 1 and 255.
        BOOL bSupportedAntenna;
    } DOT11_SUPPORTED_ANTENNA, * PDOT11_SUPPORTED_ANTENNA;
    typedef struct _DOT11_SUPPORTED_ANTENNA_LIST {
        ULONG uNumOfEntries;
        ULONG uTotalNumOfEntries;
        DOT11_SUPPORTED_ANTENNA dot11SupportedAntenna[1];
    } DOT11_SUPPORTED_ANTENNA_LIST, * PDOT11_SUPPORTED_ANTENNA_LIST;

#define OID_DOT11_SUPPORTED_RX_ANTENNA              (OID_DOT11_NDIS_START + 63)
    // DOT11_SUPPORTED_ANTENNA_LIST

#define OID_DOT11_DIVERSITY_SELECTION_RX            (OID_DOT11_NDIS_START + 64)
    typedef struct _DOT11_DIVERSITY_SELECTION_RX {
        ULONG uAntennaListIndex;                    // Between 1 and 255.
        BOOL bDiversitySelectionRX;
    } DOT11_DIVERSITY_SELECTION_RX, * PDOT11_DIVERSITY_SELECTION_RX;
    typedef struct _DOT11_DIVERSITY_SELECTION_RX_LIST {
        ULONG uNumOfEntries;
        ULONG uTotalNumOfEntries;
        DOT11_DIVERSITY_SELECTION_RX dot11DiversitySelectionRx[1];
    } DOT11_DIVERSITY_SELECTION_RX_LIST, * PDOT11_DIVERSITY_SELECTION_RX_LIST;

//
// OIDs for dot11SupportedDataRatesTxEntry and dot11SupportedDataRatesRxEntry
//

#define OID_DOT11_SUPPORTED_DATA_RATES_VALUE        (OID_DOT11_NDIS_START + 65)
    typedef struct _DOT11_SUPPORTED_DATA_RATES_VALUE {
        UCHAR ucSupportedTxDataRatesValue[8];
        UCHAR ucSupportedRxDataRatesValue[8];
    } DOT11_SUPPORTED_DATA_RATES_VALUE, * PDOT11_SUPPORTED_DATA_RATES_VALUE;

//
// OIDs for dot11PhyOFDMEntry
//

#define OID_DOT11_CURRENT_FREQUENCY                 (OID_DOT11_NDIS_START + 66)
    // ULONG

#define OID_DOT11_TI_THRESHOLD                      (OID_DOT11_NDIS_START + 67)
    // LONG

#define OID_DOT11_FREQUENCY_BANDS_SUPPORTED         (OID_DOT11_NDIS_START + 68)
    #define DOT11_FREQUENCY_BANDS_LOWER    0x00000001
    #define DOT11_FREQUENCY_BANDS_MIDDLE   0x00000002
    #define DOT11_FREQUENCY_BANDS_UPPER    0x00000004
    // ULONG

//
// OIDs for dot11PhyHRDSSSEntry
//

#define OID_DOT11_SHORT_PREAMBLE_OPTION_IMPLEMENTED (OID_DOT11_NDIS_START + 69)
    // BOOL

#define OID_DOT11_PBCC_OPTION_IMPLEMENTED           (OID_DOT11_NDIS_START + 70)
    // BOOL

#define OID_DOT11_CHANNEL_AGILITY_PRESENT           (OID_DOT11_NDIS_START + 71)
    // BOOL

#define OID_DOT11_CHANNEL_AGILITY_ENABLED           (OID_DOT11_NDIS_START + 72)
    // BOOL

#define OID_DOT11_HR_CCA_MODE_SUPPORTED             (OID_DOT11_NDIS_START + 73)
    #define DOT11_HR_CCA_MODE_ED_ONLY        0x00000001
    #define DOT11_HR_CCA_MODE_CS_ONLY        0x00000002
    #define DOT11_HR_CCA_MODE_CS_AND_ED      0x00000004
    #define DOT11_HR_CCA_MODE_CS_WITH_TIMER  0x00000008
    #define DOT11_HR_CCA_MODE_HRCS_AND_ED    0x00000010
    // ULONG


//
// OIDs for dot11StationConfigEntry (Cont)
//

#define OID_DOT11_MULTI_DOMAIN_CAPABILITY_IMPLEMENTED   (OID_DOT11_NDIS_START + 74)
    // BOOL

#define OID_DOT11_MULTI_DOMAIN_CAPABILITY_ENABLED       (OID_DOT11_NDIS_START + 75)
    // BOOL

#define OID_DOT11_COUNTRY_STRING                        (OID_DOT11_NDIS_START + 76)
    // UCHAR[3]

//
// OIDs for dot11MultiDomainCapabilityEntry
//

typedef struct _DOT11_MULTI_DOMAIN_CAPABILITY_ENTRY {
    ULONG uMultiDomainCapabilityIndex;
    ULONG uFirstChannelNumber;
    ULONG uNumberOfChannels;
    LONG lMaximumTransmitPowerLevel;
} DOT11_MULTI_DOMAIN_CAPABILITY_ENTRY, *PDOT11_MULTI_DOMAIN_CAPABILITY_ENTRY;
typedef struct _DOT11_MD_CAPABILITY_ENTRY_LIST {
    ULONG uNumOfEntries;
    ULONG uTotalNumOfEntries;
    DOT11_MULTI_DOMAIN_CAPABILITY_ENTRY dot11MDCapabilityEntry[1];
} DOT11_MD_CAPABILITY_ENTRY_LIST, *PDOT11_MD_CAPABILITY_ENTRY_LIST;


#define OID_DOT11_MULTI_DOMAIN_CAPABILITY           (OID_DOT11_NDIS_START + 77)
    // DOT11_MD_CAPABILITY_ENTRY_LIST

//
// OIDs for dot11PhyFHSSEntry
//

#define OID_DOT11_EHCC_PRIME_RADIX                  (OID_DOT11_NDIS_START + 78)
    // ULONG

#define OID_DOT11_EHCC_NUMBER_OF_CHANNELS_FAMILY_INDEX  (OID_DOT11_NDIS_START + 79)
    // ULONG

#define OID_DOT11_EHCC_CAPABILITY_IMPLEMENTED       (OID_DOT11_NDIS_START + 80)
    // BOOL

#define OID_DOT11_EHCC_CAPABILITY_ENABLED           (OID_DOT11_NDIS_START + 81)
    // BOOL

#define OID_DOT11_HOP_ALGORITHM_ADOPTED             (OID_DOT11_NDIS_START + 82)
    typedef enum _DOT11_HOP_ALGO_ADOPTED {
        dot11_hop_algo_current = 0,
        dot11_hop_algo_hop_index = 1,
        dot11_hop_algo_hcc = 2
    } DOT11_HOP_ALGO_ADOPTED, * PDOT11_HOP_ALGO_ADOPTED;

#define OID_DOT11_RANDOM_TABLE_FLAG                 (OID_DOT11_NDIS_START + 83)
    // BOOL

#define OID_DOT11_NUMBER_OF_HOPPING_SETS            (OID_DOT11_NDIS_START + 84)
    // ULONG

#define OID_DOT11_HOP_MODULUS                       (OID_DOT11_NDIS_START + 85)
    // ULONG

#define OID_DOT11_HOP_OFFSET                        (OID_DOT11_NDIS_START + 86)
    // ULONG


//
// OIDs for dot11HoppingPatternEntry
//
#define OID_DOT11_HOPPING_PATTERN                   (OID_DOT11_NDIS_START + 87)
typedef struct _DOT11_HOPPING_PATTERN_ENTRY {
    ULONG uHoppingPatternIndex;
    ULONG uRandomTableFieldNumber;
} DOT11_HOPPING_PATTERN_ENTRY, *PDOT11_HOPPING_PATTERN_ENTRY;
typedef struct _DOT11_HOPPING_PATTERN_ENTRY_LIST {
    ULONG uNumOfEntries;
    ULONG uTotalNumOfEntries;
    DOT11_HOPPING_PATTERN_ENTRY dot11HoppingPatternEntry[1];
} DOT11_HOPPING_PATTERN_ENTRY_LIST, *PDOT11_HOPPING_PATTERN_ENTRY_LIST;


#define OID_DOT11_RANDOM_TABLE_FIELD_NUMBER         (OID_DOT11_NDIS_START + 88)
    // ULONG

//
// WPA Extensions
//

#define OID_DOT11_WPA_TSC                           (OID_DOT11_NDIS_START + 89)
typedef struct _DOT11_WPA_TSC {
    ULONG uReserved;
    DOT11_OFFLOAD_TYPE dot11OffloadType;
    HANDLE hOffload;
    DOT11_IV48_COUNTER dot11IV48Counter;
} DOT11_WPA_TSC, * PDOT11_WPA_TSC;

//
// dot11.
//

#define OID_DOT11_RSSI_RANGE                        (OID_DOT11_NDIS_START + 90)
typedef struct _DOT11_RSSI_RANGE {
    DOT11_PHY_TYPE dot11PhyType;
    ULONG uRSSIMin; // Minimum caliberation value of RSSI in the NIC.
    ULONG uRSSIMax; // Maximum caliberation value of RSSI in the NIC.
} DOT11_RSSI_RANGE, * PDOT11_RSSI_RANGE;

#define OID_DOT11_RF_USAGE                          (OID_DOT11_NDIS_START + 91)
//ULONG

#define OID_DOT11_NIC_SPECIFIC_EXTENSION            (OID_DOT11_NDIS_START + 92)
typedef struct _DOT11_NIC_SPECIFIC_EXTENSION {
    ULONG uBufferLength;
    ULONG uTotalBufferLength;
    UCHAR ucBuffer[1];
} DOT11_NIC_SPECIFIC_EXTENSION, * PDOT11_NIC_SPECIFIC_EXTENSION;

//
// AP join request
//

#define OID_DOT11_AP_JOIN_REQUEST                   (OID_DOT11_NDIS_START + 93)
    typedef struct _DOT11_AP_JOIN_REQUEST {
        ULONG uJoinFailureTimeout;
        DOT11_RATE_SET OperationalRateSet;
        ULONG uChCenterFrequency;
        DOT11_BSS_DESCRIPTION dot11BSSDescription;  // Must be the last field.
    } DOT11_AP_JOIN_REQUEST, * PDOT11_AP_JOIN_REQUEST;


//
// 802.11 Extensions to Standard NDIS Functions
//

//
// Miniport Send Path Extension
//

// Only 4 bits are present in the 802.11 header to track fragments.
#define DOT11_MAX_NUM_OF_FRAGMENTS                  16
// Priority Classes.
#define DOT11_PRIORITY_CONTENTION                   0
#define DOT11_PRIORITY_CONTENTION_FREE              1
// Service Classes.
#define DOT11_SERVICE_CLASS_REORDERABLE_MULTICAST   0
#define DOT11_SERVICE_CLASS_STRICTLY_ORDERED        1
// Flags.
#define DOT11_FLAGS_80211B_SHORT_PREAMBLE           0x00000001
#define DOT11_FLAGS_80211B_PBCC                     0x00000002
#define DOT11_FLAGS_80211B_CHANNEL_AGILITY          0x00000004
#define DOT11_FLAGS_PS_ON                           0x00000008

#ifdef NDIS_MINIPORT_DRIVER
typedef struct _DOT11_FRAGMENT_DESCRIPTOR {
    ULONG uOffset;
    ULONG uLength;
} DOT11_FRAGMENT_DESCRIPTOR, * PDOT11_FRAGMENT_DESCRIPTOR;

typedef struct _DOT11_PER_MSDU_COUNTERS {
    ULONG uTransmittedFragmentCount;
    ULONG uRetryCount;
    ULONG uRTSSuccessCount;
    ULONG uRTSFailureCount;
    ULONG uACKFailureCount;
} DOT11_PER_MSDU_COUNTERS, * PDOT11_PER_MSDU_COUNTERS;

typedef struct _DOT11_SEND_EXTENSION_INFO {
    ULONG uVersion;
    PVOID pvReserved;
    ULONG uFlags;
    ULONG uPSLifetime;
    ULONG uDelayedSleepValue;
    UCHAR ucTXDataRates[8];
    BOOLEAN bIndicateAssociatedACKs;
    BOOLEAN bIndicateTXStatus;
    UCHAR ucPriority;
    BOOLEAN bDontFragment;
    DWORD dwExtendedStatus;
    HANDLE hIntegrityOffload;
    HANDLE hWEPOffload;
    UCHAR ucWPAMSDUPriority;
    UCHAR ucNumOfRWsOnPeer;
    USHORT usAID;
    PDOT11_PER_MSDU_COUNTERS pDot11PerMSDUCounters;
    USHORT usNumberOfFragments;
    DOT11_FRAGMENT_DESCRIPTOR Dot11FragmentDescriptors[1];
} DOT11_SEND_EXTENSION_INFO, * PDOT11_SEND_EXTENSION_INFO;
#endif // NDIS_MINIPORT_DRIVER

//
// Miniport Receive Path Extension
//

#ifdef NDIS_MINIPORT_DRIVER
typedef struct _DOT11_RECV_EXTENSION_INFO {
    ULONG uVersion;
    PVOID pvReserved;
    DOT11_PHY_TYPE dot11PhyType;
    ULONG uChCenterFrequency;
    LONG lRSSI;
    LONG lRSSIMin;
    LONG lRSSIMax;
    ULONG uRSSI;
    UCHAR ucPriority;
    UCHAR ucDataRate;
    UCHAR ucPeerMacAddress[6];
    DWORD dwExtendedStatus;
    HANDLE hWEPOffloadContext;
    HANDLE hAuthOffloadContext;
    USHORT usWEPAppliedMask;
    USHORT usWPAMSDUPriority;
    DOT11_IV48_COUNTER dot11LowestIV48Counter;
    USHORT usDot11LeftRWBitMap;
    DOT11_IV48_COUNTER dot11HighestIV48Counter;
    USHORT usDot11RightRWBitMap;
    USHORT usNumberOfMPDUsReceived;
    USHORT usNumberOfFragments;
    PNDIS_PACKET pNdisPackets[1];       // Must be the last field.
} DOT11_RECV_EXTENSION_INFO, * PDOT11_RECV_EXTENSION_INFO;

#endif // NDIS_MINIPORT_DRIVER

//
// 802.11 Status Codes
//

#define DOT11_STATUS_SUCCESS                        0x00000001

#define DOT11_STATUS_RETRY_LIMIT_EXCEEDED           0x00000002

#define DOT11_STATUS_UNSUPPORTED_PRIORITY           0x00000004

#define DOT11_STATUS_UNSUPPORTED_SERVICE_CLASS      0x00000008

#define DOT11_STATUS_UNAVAILABLE_PRIORITY           0x00000010

#define DOT11_STATUS_UNAVAILABLE_SERVICE_CLASS      0x00000020

#define DOT11_STATUS_XMIT_MSDU_TIMER_EXPIRED        0x00000040

#define DOT11_STATUS_UNAVAILABLE_BSS                0x00000080

#define DOT11_STATUS_EXCESSIVE_DATA_LENGTH          0x00000100

#define DOT11_STATUS_ENCRYPTION_FAILED              0x00000200

#define DOT11_STATUS_WEP_KEY_UNAVAILABLE            0x00000400

#define DOT11_STATUS_ICV_VERIFIED                   0x00000800

#define DOT11_STATUS_PACKET_REASSEMBLED             0x00001000

#define DOT11_STATUS_PACKET_NOT_REASSEMBLED         0x00002000

#define DOT11_STATUS_GENERATE_AUTH_FAILED           0x00004000

#define DOT11_STATUS_AUTH_NOT_VERIFIED              0x00008000

#define DOT11_STATUS_AUTH_VERIFIED                  0x00010000

#define DOT11_STATUS_AUTH_FAILED                    0x00020000

//
// Flags for NDIS_STATUS_MEDIA_SPECIFIC_INDICATION
//

#define DOT11_STATUS_SCAN_CONFIRM                   1
#define DOT11_STATUS_JOIN_CONFIRM                   2
#define DOT11_STATUS_START_CONFIRM                  3
#define DOT11_STATUS_RESET_CONFIRM                  4

#ifdef NDIS_MINIPORT_DRIVER
typedef struct _DOT11_STATUS_INDICATION {
    ULONG uStatusType;
    NDIS_STATUS ndisStatus;
} DOT11_STATUS_INDICATION, * PDOT11_STATUS_INDICATION;
#endif // NDIS_MINIPORT_DRIVER

//
// Private 802.11 OIDs: this should be the last section
//
// We reserve 1024 entries for real DOT11 OIDs
//

#define OID_DOT11_PRIVATE_OIDS_START                (OID_DOT11_NDIS_START + 1024)

#define OID_DOT11_MAXIMUM_LOOKAHEAD                 (OID_DOT11_PRIVATE_OIDS_START + 0)
    // ULONG (in octets)

#define OID_DOT11_CURRENT_LOOKAHEAD                 (OID_DOT11_PRIVATE_OIDS_START + 1)
    // ULONG (in octets)

#define OID_DOT11_CURRENT_ADDRESS                   (OID_DOT11_PRIVATE_OIDS_START + 2)
    // DOT11_MAC_ADDRESS

#define OID_DOT11_PERMANENT_ADDRESS                 (OID_DOT11_PRIVATE_OIDS_START + 3)
    // DOT11_MAC_ADDRESS

#define OID_DOT11_MULTICAST_LIST                    (OID_DOT11_PRIVATE_OIDS_START + 4)
    // OID_802_3_MULTICAST_LIST

#endif // __WINDOT11_H__

