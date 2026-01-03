/**
 * @file DHCP.h
 * @brief Définitions globales, constantes protocolaires et callbacks pour
 *        le client DHCPv6 Prefix Delegation (PD) et les interactions RA/ND.
 *
 * Ce fichier regroupe :
 *   - les constantes DHCPv6 (RFC 8415)
 *   - les constantes DHCPv4 (RFC 2131 / 2132)
 *   - les options RA IPv6 (RFC 4861 / RFC 8106)
 *   - les limites internes (DUID, préfixes, interfaces LAN, DNS)
 *   - les chemins de registre Windows utilisés par le service
 *   - les callbacks d’intégration (prefix change)
 *
 */

#ifndef _H_DHCP
#define _H_DHCP

 // ============================================================================
 // SERVICE METADATA
 // ============================================================================

 /** @brief Nom affiché dans le Service Manager Windows. */
#define DISPLAY_NAME L"DHCPv6 Prefix Delegation Client"

/** @brief Description du service Windows. */
#define MYSERVICE_DESCRIPTION \
    L"Acquires IPv6 prefixes from ISP via DHCPv6-PD and delegates to LAN interfaces"

/** @brief Nom interne du service Windows. */
#define SERVICE_NAME L"DHCPv6PDClient"

// ============================================================================
// REGISTRY PATHS
// ============================================================================

/** @brief Clé de configuration générale du service. */
#define REG_KEY_PARAM L"SYSTEM\\CurrentControlSet\\Services\\DHCPv6PDClient\\Parameters"

/** @brief Clé de configuration DHCPv6 (options, DUID, IAID, etc.). */
#define REG_KEY_DHCPV6 L"SYSTEM\\CurrentControlSet\\Services\\DHCPv6PDClient\\Parameters\\DHCPV6"

/** @brief Clé de stockage de l’état DHCPv6 persistant. */
#define REG_KEY_STATE L"SYSTEM\\CurrentControlSet\\Services\\DHCPv6PDClient\\State"

// ============================================================================
// DHCPv6 CONSTANTS (RFC 8415)
// ============================================================================

/** @brief Port serveur DHCPv6 (UDP). */
#define DHCPV6_SERVER_PORT 547

/** @brief Port client DHCPv6 (UDP). */
#define DHCPV6_CLIENT_PORT 546

/** @brief Nombre maximal de tentatives d’envoi. */
#define MAX_RETRIES 5

/** @brief Timeout initial (SOLICIT) en millisecondes. */
#define INITIAL_TIMEOUT_MS 1000

/** @brief Timeout maximal exponentiel. */
#define MAX_TIMEOUT_MS 64000

/** @brief Valeur par défaut de SOL_MAX_RT (RFC 8415). */
#define DEFAULT_SOL_MAX_RT_MS 3600000

/** @brief Longueur minimale d’un préfixe PD accepté. */
#define MIN_PREFIX_LEN 48

/** @brief Longueur maximale d’un préfixe PD accepté. */
#define MAX_PREFIX_LEN 64

/** @brief Taille maximale d’un DUID client. */
#define MAX_DUID_LEN 128

/** @brief Taille maximale du DUID serveur. */
#define MAX_SERVER_DUID_LEN 128

/** @brief Nombre maximal de préfixes PD gérés simultanément. */
#define MAX_PREFIXES 12

/** @brief Nombre maximal d’interfaces LAN supportées. */
#define MAX_LAN_INTERFACES 12

/** @brief Nombre maximal de serveurs DNS via RDNSS. */
#define MAX_DNS_SERVERS 4

/** @brief Taille maximale d’un message DHCPv6. */
#define MAX_DHCPV6_MESSAGE_SIZE 4096

// ============================================================================
// DHCPv6 MESSAGE TYPES
// ============================================================================

#define DHCPV6_SOLICIT   1
#define DHCPV6_ADVERTISE 2
#define DHCPV6_REQUEST   3
#define DHCPV6_RENEW     5
#define DHCPV6_REBIND    6
#define DHCPV6_REPLY     7
#define DHCPV6_RELEASE   8
#define DHCPV6_REAPPLY   255  /**< Extension interne : réappliquer la config. */

// ============================================================================
// DHCPv6 OPTIONS
// ============================================================================

#define OPTION_CLIENTID                 1
#define OPTION_SERVERID                 2
#define OPTION_IA_NA                    3
#define OPTION_IAADDR                   5
#define OPTION_ORO                      6
#define OPTION_ELAPSED_TIME             8
#define OPTION_STATUS_CODE              13
#define OPTION_DNS_SERVERS              23
#define OPTION_IA_PD                    25
#define OPTION_IAPREFIX                 26
#define OPTION_INFORMATION_REFRESH_TIME 32
#define OPTION_SOL_MAX_RT               82

// ============================================================================
// ROUTER ADVERTISEMENT (RFC 4861 / RFC 8106)
// ============================================================================

/** @brief Type ICMPv6 Router Advertisement. */
#define ICMPV6_RA_TYPE 134

/** @brief Option Source Link-Layer Address. */
#define ND_OPT_SLLA_INFO 1

/** @brief Option Prefix Information. */
#define ND_OPT_PREFIX_INFO 3

/** @brief Option Link MTU. */
#define ND_OPT_MTU 5

/** @brief Option RDNSS (DNS via RA). */
#define ND_OPT_RDNSS 25

/** @brief Option DNSSL (Sufix List via RA). */
#define ND_OPT_DNSSL 31

// ============================================================================
// DHCPv4 CONSTANTS (RFC 2131 / 2132)
// ============================================================================

#define DHCPV4_DISCOVER 1
#define DHCPV4_OFFER    2
#define DHCPV4_REQUEST  3
#define DHCPV4_DECLINE  4
#define DHCPV4_ACK      5
#define DHCPV4_NAK      6
#define DHCPV4_RELEASE  7
#define DHCPV4_INFORM   8

// DHCPv4 Options
#define DHCPV4_OPT_SUBNET_MASK     1
#define DHCPV4_OPT_ROUTER          3
#define DHCPV4_OPT_DNS_SERVER      6
#define DHCPV4_OPT_HOSTNAME        12
#define DHCPV4_OPT_DOMAIN_NAME     15
#define DHCPV4_OPT_REQUESTED_IP    50
#define DHCPV4_OPT_LEASE_TIME      51
#define DHCPV4_OPT_MESSAGE_TYPE    53
#define DHCPV4_OPT_SERVER_ID       54
#define DHCPV4_OPT_PARAM_REQUEST   55
#define DHCPV4_OPT_RENEWAL_TIME    58
#define DHCPV4_OPT_REBIND_TIME     59
#define DHCPV4_OPT_CLIENT_ID       61
#define DHCPV4_OPT_CLASSLESS_ROUTE 121
#define DHCPV4_OPT_END             255

/** @brief Magic cookie DHCPv4 (RFC 2131). */
#define DHCPV4_MAGIC_COOKIE 0x63825363

/** @brief Ports DHCPv4. */
#define DHCPV4_SERVER_PORT 67
#define DHCPV4_CLIENT_PORT 68

/** @brief Nombre maximal de routes classless DHCPv4. */
#define DHCPV4_MAX_ROUTES 32

// ============================================================================
// CALLBACKS
// ============================================================================

/**
 * @brief Callback utilisateur déclenché lors d’un changement de préfixes.
 *
 * @param[in] client_prefixes     Liste des préfixes PD reçus du serveur.
 * @param[in] client_prefix_count Nombre de préfixes PD.
 * @param[in] lan_prefixes        Liste des préfixes /64 dérivés pour les LAN.
 * @param[in] lan_prefix_count    Nombre de préfixes LAN.
 * @param[in] user_data           Contexte utilisateur opaque.
 */
typedef void (*PrefixChangeCallback)(
    const void* client_prefixes,
    DWORD client_prefix_count,
    const void* lan_prefixes,
    DWORD lan_prefix_count,
    void* user_data
    );

/**
 * @brief Callback par défaut appelé lorsque les préfixes changent.
 *
 * Implémenté dans le service principal.
 */
extern void OnClientPrefixChange(
    const void* client_prefixes,
    DWORD client_prefix_count,
    const void* lan_prefixes,
    DWORD lan_prefix_count,
    void* user_data
);

// ============================================================================
// EXTERNALS (uniquement si SRV_MAIN n’est pas défini)
// ============================================================================

#ifndef SRV_MAIN

/** @brief État du service Windows. */
extern SERVICE_STATUS g_ServiceStatus;

/** @brief Handle du Service Control Manager. */
extern SERVICE_STATUS_HANDLE g_StatusHandle;

/** @brief Événement signalé lors de l’arrêt du service. */
extern HANDLE g_ServiceStopEvent;

/** @brief Source EventLog Windows. */
extern HANDLE g_LogEventSource;

/** @brief Log d’un message d’information. */
extern void LogMessage(const WCHAR* msg);

/** @brief Log d’un message d’erreur. */
extern void LogError(const WCHAR* msg);

/**
 * @brief Récupère LUID et IfIndex d’une interface réseau.
 */
extern BOOL GetCurInterfaceInfo(const WCHAR* name, NET_LUID* luid, NET_IFINDEX* ifindex, BYTE* Mac, DWORD* MTU);

#endif // SRV_MAIN
#endif // _H_DHCP
