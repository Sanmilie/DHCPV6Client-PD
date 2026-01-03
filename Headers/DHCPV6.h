/**
 * @file DHCPV6.h
 * @brief Structures de configuration, d’état et de callbacks pour le client
 *        DHCPv6 Prefix Delegation (PD) souverain et les Router Advertisements.
 *
 * Ce fichier décrit :
 *   - les structures ICMPv6/RA (Router Advertisement, Prefix Information, RDNSS)
 *   - la configuration DHCPv6-PD et RA (DHCPv6Config)
 *   - l’état complet du bail DHCPv6 (DHCPv6State)
 *   - l’interface de contrôle du démon (struct DHCPV6)
 *
 * Il définit le contrat explicite entre :
 *   - le moteur DHCPv6-PD
 *   - la configuration Windows (registry, interfaces)
 *   - le kernel IPv6 (adresses, routes, RA)
 *   - les services en cascade (callbacks de changement de préfixe)
 */

#ifndef _H_DHCPV6
#define _H_DHCPV6

#pragma pack(push,1)

 /**
  * @struct icmp6_ra
  * @brief En-tête ICMPv6 Router Advertisement (RFC 4861).
  *
  * Utilisé pour construire les messages RA envoyés sur les interfaces LAN.
  */
struct icmp6_ra
{
    uint8_t  type;              /**< Type ICMPv6 (134 = ND_ROUTER_ADVERT). */
    uint8_t  code;              /**< Code (0). */
    uint16_t cksum;             /**< Checksum ICMPv6. */
    uint8_t  hop_limit;         /**< Hop Limit recommandé (64). */
    uint8_t  flags;             /**< Flags M/O (0 pour SLAAC pur). */
    uint16_t router_lifetime;   /**< Lifetime du routeur, en secondes (max 9000). */
    uint32_t reachable_time;    /**< Temps reachable, en ms, 0 = non spécifié. */
    uint32_t retrans_timer;     /**< Temps de retransmission, en ms, 0 = non spécifié. */
};

/**
 * @struct nd_opt_prefix_info
 * @brief Option Prefix Information (Type 3, RFC 4861).
 *
 * Décrit un préfixe on-link et/ou autonome pour SLAAC.
 */
struct nd_opt_prefix_info
{
    uint8_t  type;              /**< Type (3). */
    uint8_t  len;               /**< Longueur en unités de 8 octets (4 = 32 octets). */
    uint8_t  prefix_len;        /**< Longueur du préfixe (généralement 64). */
    uint8_t  flags;             /**< L=1, A=1 pour on-link + autonomous. */
    uint32_t valid_lifetime;    /**< Valid lifetime, en secondes. */
    uint32_t preferred_lifetime;/**< Preferred lifetime, en secondes. */
    uint32_t reserved2;         /**< Réservé. */
    uint8_t  prefix[16];        /**< Préfixe IPv6. */
};

/**
 * @struct nd_opt_rdnss
 * @brief Option RDNSS (Recursive DNS Server, Type 25, RFC 8106).
 *
 * Fournit une ou plusieurs adresses de serveurs DNS via RA.
 */
struct nd_opt_rdnss
{
    uint8_t  type;              /**< Type (25). */
    uint8_t  len;               /**< Longueur en unités de 8 octets (3 = 24 octets pour 1 DNS). */
    uint16_t reserved;          /**< Réservé. */
    uint32_t lifetime;          /**< Lifetime RDNSS, en secondes. */
    struct in6_addr dns[1];     /**< Tableau extensible d’adresses DNS. */
};

/**
 * @struct nd_opt_dnssl
 * @brief Option DNSSL (DNS Search List, Type 31, RFC 6106) pour Router Advertisement.
 *
 * Permet d'indiquer un ou plusieurs suffixes de recherche DNS aux clients IPv6 via RA.
 *
 * @note Le champ `domain` est un tableau extensible encodé en format DNS wire format (labels length-prefixed).
 */
struct nd_opt_dnssl 
{
    uint8_t type;   // 31
    uint8_t len;    // in units of 8 bytes
    uint16_t reserved;
    uint32_t lifetime;
    BYTE domain[1]; // extensible
};

/**
 * @struct nd_opt_mtu
 * @brief Option MTU (Type 5) pour Router Advertisement.
 *
 * Indique la MTU recommandée sur le lien pour les clients IPv6.
 */
struct nd_opt_mtu 
{
    uint8_t type;      // 5
    uint8_t len;       // 1 (8 octets)
    uint16_t reserved; // 0
    uint32_t mtu;      // host->network order
};

/**
 * @struct nd_opt_slla
 * @brief Option Source Link-Layer Address (Type 1) pour Router Advertisement.
 *
 * Permet de fournir l'adresse MAC du routeur aux clients IPv6.
 */
struct nd_opt_slla 
{
    uint8_t type;   // 1
    uint8_t len;    // 1 (8 octets)
    uint8_t mac[6]; // MAC du serveur
};


#pragma pack(pop)

/**
 * @struct DHCPv6Config
 * @brief Configuration statique et dynamique du client DHCPv6-PD/RA.
 *
 * Contient :
 *   - interface WAN
 *   - interfaces LAN
 *   - options DHCPv6-PD (DUID, /64 unique, plages de préfixes)
 *   - options Router Advertisement
 *   - serveurs DNS pour RDNSS
 */
typedef struct DHCPv6Config
{
    WCHAR wan_interface[256];                         /**< Nom de l’interface WAN.  */
    WCHAR lan_interfaces[MAX_LAN_INTERFACES][256];    /**< Noms des interfaces LAN. */
    int   lan_count;                                  /**< Nombre d’interfaces LAN. */

    /** @name Options DHCPv6-PD */
    ///@{
    BOOL  allow_single_64;    /**< Autoriser un /64 unique en PD (sans subdivision). */
    BOOL  force_stable_duid;  /**< Forcer un DUID stable (registry) ou autoriser l’entropie. */
    BOOL  disable_release;    /**< Ne pas envoyer de DHCPv6 RELEASE à l’arrêt. */
    DWORD min_prefix_len;     /**< Longueur minimale de préfixe PD acceptée. */
    DWORD max_prefix_len;     /**< Longueur maximale de préfixe PD acceptée. */
    ///@}

    /** @name Options Router Advertisement */
    ///@{
    BOOL  enable_ra;          /**< Activer l’envoi de RA sur les LAN. */
    DWORD ra_interval_sec;    /**< Intervalle entre RA périodiques. */
    DWORD ra_lifetime_sec;    /**< Router lifetime annoncé dans les RA. */
    ///@}

    /** @name DNS pour RDNSS */
    ///@{
    BYTE  dns_servers[MAX_DNS_SERVERS][16]; /**< Adresses IPv6 des DNS. */
    int   dns_count;                        /**< Nombre de DNS configurés. */
    DWORD rdnss_lifetime_sec;              /**< Lifetime RDNSS annoncé, en secondes. */
    ///@}
} DHCPv6Config;

/**
 * @struct IAAddress
 * @brief Représente une adresse IPv6 IA_NA avec ses lifetimes.
 */
typedef struct IAAddress
{
    BYTE  addr[16];             /**< Adresse IPv6. */
    DWORD preferred_lifetime;   /**< Preferred lifetime, en secondes. */
    DWORD valid_lifetime;       /**< Valid lifetime, en secondes. */
} IAAddress;

/**
 * @struct IAPrefix
 * @brief Représente un préfixe délégué IA_PD avec ses lifetimes.
 */
typedef struct IAPrefix
{
    BYTE  prefix[16];           /**< Préfixe IPv6. */
    BYTE  prefix_len;           /**< Longueur du préfixe, en bits. */
    DWORD preferred_lifetime;   /**< Preferred lifetime, en secondes. */
    DWORD valid_lifetime;       /**< Valid lifetime, en secondes. */
} IAPrefix;

/**
 * @struct DHCPv6State
 * @brief État complet du bail DHCPv6, des préfixes PD et de l’intégration WAN/RA.
 *
 * Cet état est persistent (stocké dans le registre) et contient :
 *   - DUID client et DUID serveur
 *   - IA_NA (adresse WAN) + timers T1/T2
 *   - IA_PD (préfixes délégués) + timers T1/T2
 *   - informations de session (serveur, TXID, unicast/multicast)
 *   - information d’interface WAN (LUID, IfIndex)
 *   - configuration RA (dernier envoi, sol_max_rt)
 */
typedef struct DHCPv6State
{
    DWORD Version;  /**< Version de structure / de format d’état. */

    /** @name DUID client et serveur */
    ///@{
    BYTE duid[MAX_DUID_LEN];                      /**< DUID client. */
    WORD duid_len;                                /**< Longueur du DUID client. */
    BYTE server_duid[MAX_SERVER_DUID_LEN];        /**< DUID serveur courant. */
    WORD server_duid_len;                         /**< Longueur du DUID serveur. */
    BYTE selected_server_duid[MAX_SERVER_DUID_LEN]; /**< DUID du serveur sélectionné (ADVERTISE). */
    WORD selected_server_duid_len;                /**< Longueur du DUID sélectionné. */
    ///@}

    /** @name IA_NA (adresse WAN) */
    ///@{
    DWORD     iaid_na;         /**< IAID pour IA_NA. */
    IAAddress wan_address;     /**< Adresse IPv6 WAN (globale ou link-local selon contexte). */
    BOOL      has_wan_address; /**< TRUE si une adresse WAN est en place. */
    DWORD     t1_na;           /**< T1 pour IA_NA, en secondes. */
    DWORD     t2_na;           /**< T2 pour IA_NA, en secondes. */
    ///@}

    /** @name IA_PD (préfixes délégués) */
    ///@{
    DWORD    iaid_pd;                        /**< IAID pour IA_PD. */
    IAPrefix prefixes[MAX_PREFIXES];         /**< Tableau de préfixes PD. */
    int      prefix_count;                   /**< Nombre de préfixes dans le tableau. */
    DWORD    t1_pd;                          /**< T1 pour IA_PD, en secondes. */
    DWORD    t2_pd;                          /**< T2 pour IA_PD, en secondes. */
    ///@}

    /** @name État de bail et transaction */
    ///@{
    time_t lease_start;        /**< Timestamp du début de bail. */
    time_t transaction_start;  /**< Timestamp de la dernière transaction DHCPv6. */
    BOOL   in_renewal;         /**< TRUE si en phase de RENEW/REBIND. */
    int    renew_retries;      /**< Nombre de tentatives de renouvellement. */
    ///@}

    /** @name Passerelle et serveur DHCPv6 */
    ///@{
    BYTE             gateway_ll[16]; /**< Adresse link-local de la passerelle WAN. */
    BOOL             has_gateway;    /**< TRUE si une passerelle est connue. */
    struct sockaddr_in6 server_addr; /**< Adresse du serveur DHCPv6 (pour unicast). */
    BOOL             use_unicast;    /**< TRUE si l’on doit envoyer en unicast. */
    BYTE             last_txid[3];   /**< Dernier Transaction ID (XID) utilisé. */
    ///@}

    /** @name Interface WAN */
    ///@{
    NET_LUID   wan_luid;       /**< LUID de l’interface WAN. */
    NET_IFINDEX wan_ifindex;   /**< Index de l’interface WAN. */
    DWORD      sol_max_rt_ms;  /**< SOL_MAX_RT courant en millisecondes. */
    ///@}

    /** @name État RA */
    ///@{
    time_t last_ra_time;       /**< Timestamp du dernier RA envoyé. */
    ///@}

    BOOL   PrefixChanged;
} DHCPv6State;

typedef struct DHCPV6 DHCPV6, * pDHCPV6;

/**
 * @struct DHCPV6
 * @brief Interface haut niveau du moteur DHCPv6-PD + RA.
 *
 * Cette structure regroupe :
 *   - les callbacks de logique (state machine, acquisition, timers, cleanup)
 *   - les fonctions RA (envoi sur tous les LANs)
 *   - les callbacks pour les serveurs en cascade (changement de préfixe)
 *   - la configuration (DHCPv6Config)
 *   - l’état courant (DHCPv6State)
 *
 */
typedef struct DHCPV6
{
    /** @name Fonctions DHCPv6 */
    ///@{
    int  (*DHCPStateMachine)(pDHCPV6 ClientV6); /**< State machine principale. */
    BOOL(*AcquireDHCP)(BYTE type);             /**< Acquisition/renouvellement PD/NA. */
    DWORD(*GetT1)();                            /**< Calcule le T1 minimal. */
    DWORD(*GetT2)();                            /**< Calcule le T2 minimal. */
    BOOL(*LoadDHCPState)();                    /**< Charge l’état persistant. */
    BOOL(*CheckWANStatus)();                   /**< Vérifie l’état WAN (UP/DOWN). */
    void (*CleanupConfiguration)();             /**< Nettoie la config réseau appliquée. */
    BOOL(*SendRELEASE)();                      /**< Envoie un DHCPv6 RELEASE si nécessaire. */
    ///@}

    /** @name Fonctions Router Advertisement */
    ///@{
    void (*SendAllRAs)();                       /**< Envoie des RA sur toutes les interfaces LAN. */
    ///@}

    /** @name Callbacks serveur cascade */
    ///@{
    void (*RegisterPrefixChangeCallback)(PrefixChangeCallback callback, void* user_data); /**< Enregistre un callback. */
    void (*NotifyServerOfPrefixChange)();      /**< Notifie le callback enregistré. */
    ///@}

    /** @name État interne des callbacks (privé) */
    ///@{
    PrefixChangeCallback _prefix_change_callback; /**< Callback de changement de préfixe. */
    void* _callback_user_data;     /**< Contexte utilisateur associé. */
    ///@}

    /** @name Configuration et état */
    ///@{
    DHCPv6Config Config; /**< Configuration DHCPv6/RA. */
    DHCPv6State  State;  /**< État courant du client. */
    ///@}
} DHCPV6, * pDHCPV6;

/**
 * @brief Initialise le moteur DHCPv6-PD et retourne son interface.
 *
 * Initialise :
 *   - Config (via LoadConfigFromRegistry)
 *   - State (zéro, puis éventuellement charge l’état)
 *   - pointeurs de fonctions (state machine, RA, callbacks)
 *
 * @return Pointeur vers une structure DHCPV6 initialisée.
 */
pDHCPV6 InitDHCPV6();

#endif
