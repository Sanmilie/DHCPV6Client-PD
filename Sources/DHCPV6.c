/* ============================================================================
 * @file DHCPV6.c
 * @brief
 *  Projet : DHCPv6-PD Router & RA Daemon pour Windows
 *  Créateur : Yannick LaRue
 *  Entreprise : San@sro Inc. / SSE Carte à Puce Inc.
 *
 *  Philosophie et Contrat d’Architecture
 *  -----------------------------------------------
 *  Ce démon remplace entièrement la logique IPv6 de Windows pour tout ce qui
 *  concerne DHCPv6-PD, l’attribution d’adresses, les routes, les Router
 *  Advertisements (RA) et les RDNSS (DNS via RA).
 *
 *  Pourquoi ?
 *  ----------
 *  Windows n’est pas un routeur IPv6 fiable.
 *  - Il n’annonce jamais RDNSS (RFC 8106).
 *  - Il ne synchronise pas DHCPv6-PD avec RA/ND.
 *  - Il ne dérive pas les /64 à partir d’un préfixe délégué (/48, /56, /60).
 *  - Il ne nettoie pas les anciennes adresses ou routes lors d’un changement de PD.
 *  - Il laisse des états hybrides, contradictoires ou persistants dans le kernel.
 *
 *  Ce démon impose donc un modèle souverain, cohérent et déterministe :
 *
 *  1. DHCPv6-PD complet et stable
 *     - DUID stable (optionnel), IAID dérivées du NET_LUID.
 *     - Gestion SOLICIT / REQUEST / RENEW / REBIND conforme RFC 8415.
 *     - Timers T1/T2 recalculés proprement selon les lifetimes NA/PD.
 *     - Reprise d’état persistante (registry) après redémarrage.
 *
 *  2. Dérivation bit-exacte des sous-réseaux LAN
 *     - À partir du préfixe délégué (48–64), calcul MSB-first des /64.
 *     - Un /64 par interface LAN, adresse ::1 réservée pour le routeur.
 *     - Refus explicite des préfixes < /48 (explosion combinatoire).
 *
 *  3. Configuration kernel propre et auditable
 *     - Suppression systématique des anciennes adresses globales.
 *     - Suppression des routes obsolètes (WAN + LAN).
 *     - Application déterministe des nouvelles adresses et routes.
 *     - Validation continue : toute divergence kernel → reconfiguration.
 *
 *  4. Router Advertisements (RA) souverains
 *     - RA complets : Prefix Information, Router Lifetime, RDNSS.
 *     - DNS cohérents (prefix::1 ou valeurs configurées). FAI non Utilisé
 *     - RA immédiats après acquisition, après changement réseau, et périodiques.
 *     - Windows RA/ND désactivés : aucune annonce parasite.
 *
 *  5. Sécurité et cohérence
 *     - Refus des préfixes non alignés (fail-fast).
 *     - Refus des états hybrides (plusieurs globales sur WAN, LAN pollués).
 *     - Kernel considéré comme non fiable : ce démon est la source de vérité.
 *
 *  En résumé
 *  ---------
 *  Ce démon transforme Windows en routeur IPv6 professionnel :
 *  - propre,
 *  - déterministe,
 *  - conforme aux RFC,
 *  - souverain sur le PD, les LAN, les RA et les DNS.
 *
 *  Toute la logique ND/RA/DHCPv6 native de Windows est ignorée ou neutralisée.
 *  Le système devient prévisible, stable, et parfaitement contrôlé.
 * 
 * @author Yannick LaRue
 * @copyright San@sro Inc. / SSE Carte à Puce Inc.
 * ============================================================================ */


#include <winsock2.h>
#include <ws2tcpip.h>
#include <MSWSock.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <stdio.h>
#include <time.h>
#include <bcrypt.h>
#include <inttypes.h>
#include "../Headers/DHCP.h"
#include "../Headers/DHCPV6.h"
#include "../Headers/IPv6Utils.h"

static DHCPV6 CurInterface;
static HKEY RegistryKey = NULL;
static HANDLE NetworkChangeHandle = 0;
static volatile LONG NetworkChangedFlag = 0;

typedef enum { IF_UP, IF_DOWN, IF_UNKNOWN } InterfaceStatus;

// ============================================================================
// INTERFACE UTILITIES
// ============================================================================

/**
* @brief Récupère l’adresse SLAAC (Global Unicast ou ULA) sur l’interface WAN.
*
* Utilisé lorsque le serveur DHCPv6 ne fournit pas d’IA_NA.
*
* Filtrage :
*   - ignore link-local (FE80::/10)
*   - ignore multicast (FF00::/8)
*   - accepte Global Unicast (2000::/3)
*   - accepte Unique Local (FC00::/7)
*
* Met à jour :
*   - CurInterface.State.wan_address
*   - CurInterface.State.has_wan_address
*
* @retval TRUE  Si une adresse SLAAC valide est trouvée.
* @retval FALSE Si aucune adresse utilisable n’est détectée.
*/
static BOOL GetSLAACAddress()
{
	MIB_UNICASTIPADDRESS_TABLE* t = NULL;
	BOOL found = FALSE;
	WCHAR log[256] = { 0 };

	if (GetUnicastIpAddressTable(AF_INET6, &t) != NO_ERROR)
	{
		LogError(L"Failed to query IP address table for SLAAC");
		return FALSE;
	}

	for (ULONG i = 0; i < t->NumEntries; i++)
	{
		// Vérifier si c'est notre interface WAN
		if (t->Table[i].InterfaceLuid.Value != CurInterface.State.wan_luid.Value)
		{
			continue;
		}

		// Vérifier si c'est une adresse /64
		if (t->Table[i].OnLinkPrefixLength != 64)
		{
			continue;
		}

		BYTE* addr = t->Table[i].Address.Ipv6.sin6_addr.s6_addr;
		BYTE first_byte = addr[0];

		// Ignorer link-local (FE80::/10)
		if (first_byte == 0xFE && (addr[1] & 0xC0) == 0x80)
		{
			continue;
		}

		// Ignorer multicast (FF00::/8)
		if (first_byte == 0xFF)
		{
			continue;
		}

		// Chercher Global Unicast (2000::/3) ou Unique Local (FC00::/7)
		BOOL is_global = (first_byte >= 0x20 && first_byte <= 0x3F);
		BOOL is_ula = ((first_byte & 0xFE) == 0xFC);

		if (is_global || is_ula)
		{
			// Copier l'adresse SLAAC
			memcpy(CurInterface.State.wan_address.addr, addr, 16);

			// Récupérer les lifetimes
			CurInterface.State.wan_address.preferred_lifetime = t->Table[i].PreferredLifetime;
			CurInterface.State.wan_address.valid_lifetime = t->Table[i].ValidLifetime;

			CurInterface.State.has_wan_address = TRUE;
			found = TRUE;

			WCHAR ipstr[INET6_ADDRSTRLEN];
			InetNtop(AF_INET6, addr, ipstr, _countof(ipstr));
			_snwprintf_s(log, _countof(log), _TRUNCATE,
				L"SLAAC address detected: %s/64 (valid=%lu, pref=%lu)",
				ipstr,
				CurInterface.State.wan_address.valid_lifetime,
				CurInterface.State.wan_address.preferred_lifetime);
			LogMessage(log);

			break;
		}
	}

	FreeMibTable(t);

	if (!found)
	{
		LogMessage(L"No SLAAC address found on WAN interface");
	}

	return found;
}

/**
* @brief Callback système déclenché lors d’un changement réseau IPv6.
*
* Détecte :
*   - changement d’adresse WAN
*   - changement de préfixe WAN
*   - changement sur une interface LAN
*
* Met à jour :
*   - NetworkChangedFlag (1 = LAN, 2 = WAN)
*
* @param[in] CallerContext   Contexte utilisateur (non utilisé).
* @param[in] Row             Ligne d’interface modifiée.
* @param[in] NotificationType Type de notification.
*/
static VOID WINAPI NetworkChangeCallback(
	PVOID CallerContext,
	PMIB_IPINTERFACE_ROW Row,
	MIB_NOTIFICATION_TYPE NotificationType
)
{
	UNREFERENCED_PARAMETER(CallerContext);
	BYTE old_wan_addr[16] = { 0 };
	BOOL had_old;
	BOOL has_new;

	if (Row->Family != AF_INET6)
		return;

	// Vérifier si c'est notre interface WAN
	if (Row->InterfaceLuid.Value == CurInterface.State.wan_luid.Value)
	{
		WCHAR log[128];
		swprintf_s(log, _countof(log),
			L"Network change on WAN (type: %d)", NotificationType);
		LogMessage(log);
		InterlockedExchange(&NetworkChangedFlag, 2);
		// Note: On ne peut pas appeler AcquireDHCPv6 ici (contexte callback)
		// On utilise le check dans la boucle principale
		return;
	}

	memcpy(old_wan_addr, CurInterface.State.wan_address.addr, 16);
	had_old = CurInterface.State.has_wan_address;
	has_new = GetSLAACAddress(); // met à jour CurInterface.State.wan_address

	// Si on n'avait pas d'ancienne adresse → impossible de comparer
	if (!had_old || !has_new)
	{
		// On ne peut pas valider le préfixe → on signale un changement WAN
		InterlockedExchange(&NetworkChangedFlag, 2);
		return;
	}

	// Vérifier que l'adress global est encore dans le même préfixe
	if (!IPv6_AddressInPrefix(old_wan_addr, CurInterface.State.wan_address.addr, 64))
	{
		IPv6_LogPrefix(L"Network Prefix change on WAN", CurInterface.State.wan_address.addr, 64);
		InterlockedExchange(&NetworkChangedFlag, 2);
		return;
	}

	// Vérifier si c'est une interface LAN
	for (int i = 0; i < CurInterface.Config.lan_count && i < MAX_LAN_INTERFACES; i++)
	{
		NET_LUID ll;
		if (GetCurInterfaceInfo(CurInterface.Config.lan_interfaces[i], &ll, NULL))
		{
			if (Row->InterfaceLuid.Value == ll.Value)
			{
				WCHAR log[128];
				swprintf_s(log, _countof(log),
					L"Network change on LAN %d (type: %d)", i, NotificationType);
				LogMessage(log);
				InterlockedExchange(&NetworkChangedFlag, 1);
				break;
			}
		}
	}
}

/**
* @brief Enregistre les notifications de changement réseau IPv6.
*
* @retval TRUE  Si l’enregistrement réussit.
* @retval FALSE Si NotifyIpInterfaceChange échoue.
*/
static BOOL SetupNetworkChangeNotification()
{
	NTSTATUS status = NotifyIpInterfaceChange(
		AF_INET6,
		NetworkChangeCallback,
		NULL,
		FALSE,  // Pas d'appel initial
		&NetworkChangeHandle
	);

	if (status == NO_ERROR)
	{
		LogMessage(L"Network change notification registered");
		return TRUE;
	}

	WCHAR log[128];
	swprintf_s(log, _countof(log),
		L"Failed to register network notification: 0x%lx", status);
	LogError(log);
	return FALSE;
}

/**
* @brief Désenregistre les notifications réseau IPv6.
*/
static void CleanupNetworkChangeNotification()
{
	if (NetworkChangeHandle)
	{
		CancelMibChangeNotify2(NetworkChangeHandle);
		NetworkChangeHandle = NULL;
		LogMessage(L"Network change notification unregistered");
	}
}

/**
* @brief Enregistre une notification de changement dans la clé de registre.
*
* @return HANDLE  Handle d’événement à attendre, ou INVALID_HANDLE_VALUE en cas d’erreur.
*/
static HANDLE SetupRegistryNotification()
{
	if (RegistryKey)
	{
		RegCloseKey(RegistryKey);
		RegistryKey = NULL;
	}

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_DHCPV6, 0, KEY_NOTIFY, &RegistryKey) != ERROR_SUCCESS)
	{
		return INVALID_HANDLE_VALUE;
	}

	HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!hEvent || RegNotifyChangeKeyValue(RegistryKey, FALSE, REG_NOTIFY_CHANGE_LAST_SET, hEvent, TRUE) != ERROR_SUCCESS)
	{
		if (hEvent) CloseHandle(hEvent);
		RegCloseKey(RegistryKey);
		RegistryKey = NULL;
		return INVALID_HANDLE_VALUE;
	}

	return hEvent;
}

/**
* @brief Récupère la passerelle IPv6 de l’interface WAN.
*
* @param[out] gw  Adresse IPv6 de la passerelle (16 octets).
*
* @retval TRUE  Si une passerelle est trouvée.
* @retval FALSE Si aucune passerelle n'est trouvée.
*/
static BOOL GetWANGateway(BYTE* gw)
{
	PIP_ADAPTER_ADDRESSES pAddr = NULL;
	ULONG len = 0;
	ULONG result;
	BOOL found = FALSE;

	result = GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_GATEWAYS, NULL, NULL, &len);
	if (result != ERROR_BUFFER_OVERFLOW && result != ERROR_SUCCESS)
	{
		return FALSE;
	}

	pAddr = (IP_ADAPTER_ADDRESSES*)HeapAlloc(GetProcessHeap(), 0, len);
	if (!pAddr)
	{
		return FALSE;
	}

	result = GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_GATEWAYS, NULL, pAddr, &len);
	if (result == NO_ERROR)
	{
		for (PIP_ADAPTER_ADDRESSES p = pAddr; p != NULL; p = p->Next)
		{
			if (p->Luid.Value == CurInterface.State.wan_luid.Value)
			{
				for (PIP_ADAPTER_GATEWAY_ADDRESS_LH g = p->FirstGatewayAddress; g != NULL; g = g->Next)
				{
					if (g->Address.lpSockaddr->sa_family == AF_INET6)
					{
						struct sockaddr_in6* sa = (struct sockaddr_in6*)g->Address.lpSockaddr;
						memcpy(gw, &sa->sin6_addr, 16);
						found = TRUE;
						break;
					}
				}
				break;
			}
		}
	}

	HeapFree(GetProcessHeap(), 0, pAddr);
	return found;
}

/**
 * @brief Retourne l’état opérationnel d’une interface (UP/DOWN).
 *
 * @param[in] luid  Identifiant NET_LUID de l’interface.
 *
 * @return IF_UP, IF_DOWN ou IF_UNKNOWN.
 */
static InterfaceStatus GetInterfaceStatus(NET_LUID luid)
{
	MIB_IF_ROW2 ifRow = { 0 };
	ifRow.InterfaceLuid = luid;
	if (GetIfEntry2(&ifRow) == NO_ERROR)
		return (ifRow.OperStatus == IfOperStatusUp) ? IF_UP : IF_DOWN;
	return IF_UNKNOWN;
}

/**
 * @brief Vérifie si l’interface WAN est connectée.
 *
 * Détecte les changements d’état et met à jour les informations de l’interface.
 *
 * @retval TRUE  Si l’interface WAN est UP.
 * @retval FALSE Si l’interface WAN est DOWN ou a été réinitialisée.
 */
static BOOL CheckWANStatus()
{
	static InterfaceStatus last = IF_UNKNOWN;
	InterfaceStatus curr = GetInterfaceStatus(CurInterface.State.wan_luid);
	if (curr != last)
	{
		if (curr == IF_UP && last == IF_DOWN)
		{
			LogMessage(L"WAN reconnected");
			NET_LUID nl;
			NET_IFINDEX ni;
			if (GetCurInterfaceInfo(CurInterface.Config.wan_interface, &nl, &ni))
			{
				CurInterface.State.wan_luid = nl;
				CurInterface.State.wan_ifindex = ni;
			}
			CurInterface.State.lease_start = 0;
			CurInterface.State.has_wan_address = FALSE;
			CurInterface.State.prefix_count = 0;
			CurInterface.State.has_gateway = FALSE;
			CurInterface.State.use_unicast = FALSE;
			last = curr;
			return FALSE;
		}
		last = curr;
	}
	return (curr == IF_UP);
}

// ============================================================================
// REGISTRE — DUID, IAID, STATE
// ============================================================================

/**
 * @brief Sauvegarde le DUID dans le registre.
 *
 * @retval TRUE  Si sauvegarde réussie.
 * @retval FALSE Si erreur ou DUID invalide.
 */
static BOOL SaveDUIDToRegistry()
{
	HKEY hKey = NULL;
	LONG result;

	if (CurInterface.State.duid_len == 0 || CurInterface.State.duid_len > MAX_DUID_LEN)
	{
		LogError(L"SaveDUIDToRegistry: Invalid DUID length");
		return FALSE;
	}

	result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_DHCPV6, 0, NULL, 0,
		KEY_WRITE, NULL, &hKey, NULL);
	if (result != ERROR_SUCCESS)
	{
		WCHAR log[128];
		_snwprintf_s(log, _countof(log), _TRUNCATE,
			L"Failed to create registry key: %lu", result);
		LogError(log);
		return FALSE;
	}

	result = RegSetValueExW(hKey, L"DUID", 0, REG_BINARY,
		CurInterface.State.duid, CurInterface.State.duid_len);
	RegCloseKey(hKey);

	if (result != ERROR_SUCCESS)
	{
		WCHAR log[128];
		_snwprintf_s(log, _countof(log), _TRUNCATE,
			L"Failed to save DUID to registry: %lu", result);
		LogError(log);
		return FALSE;
	}

	return TRUE;
}

/**
 * @brief Charge le DUID depuis le registre.
 *
 * @retval TRUE  Si le DUID est chargé avec succès.
 * @retval FALSE Si le DUID n’existe pas ou en cas d’erreur.
 */
static BOOL LoadDUIDFromRegistry()
{
	HKEY hKey = NULL;
	LONG result;
	DWORD size = MAX_DUID_LEN;

	result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_DHCPV6, 0, KEY_READ, &hKey);
	if (result != ERROR_SUCCESS)
	{
		return FALSE;
	}

	result = RegQueryValueExW(hKey, L"DUID", NULL, NULL, CurInterface.State.duid, &size);
	RegCloseKey(hKey);

	if (result == ERROR_SUCCESS && size > 0 && size <= MAX_DUID_LEN)
	{
		CurInterface.State.duid_len = (WORD)size;
		return TRUE;
	}

	return FALSE;
}

/**
 * @brief Sauvegarde l’état DHCPv6 dans le registre.
 *
 * @retval TRUE  Si la sauvegarde réussit.
 * @retval FALSE Si une erreur survient.
 */
static BOOL SaveDHCPv6State()
{
	HKEY hKey;
	LONG rc = RegCreateKeyExW(
		HKEY_LOCAL_MACHINE,
		REG_KEY_STATE,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		KEY_WRITE,
		NULL,
		&hKey,
		NULL
	);
	if (rc != ERROR_SUCCESS)
		return FALSE;

	rc = RegSetValueExW(
		hKey,
		L"State",
		0,
		REG_BINARY,
		(BYTE*)&CurInterface.State,
		sizeof(DHCPv6State)
	);

	RegCloseKey(hKey);
	return (rc == ERROR_SUCCESS);
}

/**
 * @brief Charge l’état DHCPv6 depuis le registre.
 *
 * @retval TRUE  Si le chargement réussit.
 * @retval FALSE Si une erreur survient.
 */
static BOOL LoadDHCPv6State()
{
	HKEY hKey;
	LONG rc = RegOpenKeyExW(
		HKEY_LOCAL_MACHINE,
		REG_KEY_STATE,
		0,
		KEY_READ,
		&hKey
	);
	if (rc != ERROR_SUCCESS)
		return FALSE;

	DWORD dataSize = sizeof(DHCPv6State);
	rc = RegGetValueW(
		hKey,
		NULL,
		L"State",
		RRF_RT_REG_BINARY,
		NULL,
		&CurInterface.State,
		&dataSize
	);

	RegCloseKey(hKey);
	return (rc == ERROR_SUCCESS);
}

// ============================================================================
// DUID & IAID
// ============================================================================

/**
* @brief Génère un DUID stable ou instable selon la configuration.
*
* - DUID-EN (type 2)
* - Enterprise Number
* - Identifiant dérivé du hostname, NET_LUID et timestamp
*/
static void GenerateDUID()
{
	if (CurInterface.Config.force_stable_duid && LoadDUIDFromRegistry())
	{
		LogMessage(L"Using stable DUID from registry (ForceStableDUID=1)");
		return;
	}

	LogMessage(L"Generating new DUID");
	CurInterface.State.duid_len = 0;

	// DUID-EN (type 2, RFC 8415)
	CurInterface.State.duid[CurInterface.State.duid_len++] = 0x00;  // DUID-EN type
	CurInterface.State.duid[CurInterface.State.duid_len++] = 0x02;

	// Enterprise Number derived from national OID authority (Canada)
	CurInterface.State.duid[CurInterface.State.duid_len++] = 0x00;
	CurInterface.State.duid[CurInterface.State.duid_len++] = 0x01;
	CurInterface.State.duid[CurInterface.State.duid_len++] = 0xBB;
	CurInterface.State.duid[CurInterface.State.duid_len++] = 0xC8;  // Enterprise Number = 113640 (Canadian national OID)

	// Identifier - utiliser un hash stable
	DWORD identifier[4] = { 0 };

	// 1. Hash du hostname
	WCHAR hostname[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
	DWORD hostname_len = _countof(hostname);
	if (GetComputerNameW(hostname, &hostname_len))
	{
		for (DWORD i = 0; i < hostname_len; i++)
		{
			identifier[0] = identifier[0] * 31 + hostname[i];
		}
	}

	if (CurInterface.Config.force_stable_duid)
	{
		// 2. Compagny ID
		memcpy(&identifier[1], "SRO", 3);
	}
	else
	{
		// 2. Time - Instabilité Volontaire par option
		identifier[1] = (DWORD)time(NULL);
	}
	// 3. Hash du NET_LUID
	identifier[2] = CurInterface.State.wan_luid.Value & 0xFFFFFFFF;
	identifier[3] = (CurInterface.State.wan_luid.Value >> 32) & 0xFFFFFFFF;

	// Copier l'identifiant dans le DUID
	if (CurInterface.State.duid_len + sizeof(identifier) <= MAX_DUID_LEN)
	{
		memcpy(&CurInterface.State.duid[CurInterface.State.duid_len], identifier, sizeof(identifier));
		CurInterface.State.duid_len += (WORD)sizeof(identifier);
	}

	SaveDUIDToRegistry();
}

/**
 * @brief Génère les IAID NA et PD à partir du NET_LUID.
 *
 * Garantit :
 *   - IAID_NA != IAID_PD
 *   - valeurs non nulles
 */
static void GenerateIAIDs()
{
	WCHAR log[128];
	// IAID basé sur NET_LUID pour stabilité
	CurInterface.State.iaid_na = CurInterface.State.wan_luid.Value & 0xFFFFFFFF;
	CurInterface.State.iaid_pd = (CurInterface.State.wan_luid.Value >> 32) & 0xFFFFFFFF;

	// FIX: Valeurs par défaut si 0
	if (CurInterface.State.iaid_na == 0) CurInterface.State.iaid_na = 1;
	if (CurInterface.State.iaid_pd == 0) CurInterface.State.iaid_pd = 2;

	// FIX: Éviter collision IAID_NA == IAID_PD
	if (CurInterface.State.iaid_na == CurInterface.State.iaid_pd)
	{
		CurInterface.State.iaid_pd = CurInterface.State.iaid_na + 1;
		swprintf_s(log, _countof(log),
			L"IAID collision detected, adjusted: NA=%u, PD=%u",
			CurInterface.State.iaid_na, CurInterface.State.iaid_pd);
		LogMessage(log);
	}

	swprintf_s(log, _countof(log), L"IAIDs generated: NA=%u, PD=%u",
		CurInterface.State.iaid_na, CurInterface.State.iaid_pd);
	LogMessage(log);
}

/**
 * @brief Génère un Transaction ID (XID) aléatoire pour DHCPv6.
 *
 * Utilise BCrypt RNG si disponible, sinon fallback sécurisé.
 */
static void GenerateTransactionID()
{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	NTSTATUS status = 0;

	if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0) == 0)
	{
		status = BCryptGenRandom(hAlg, CurInterface.State.last_txid, 3, 0);
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}
	if (status != 0 || CurInterface.State.last_txid[0] == 0)
	{
		// Fallback sécurisé
		FILETIME ft;
		LARGE_INTEGER li;
		GetSystemTimeAsFileTime(&ft);
		li.LowPart = ft.dwLowDateTime;
		li.HighPart = ft.dwHighDateTime;

		DWORD seed = li.LowPart ^ li.HighPart ^ GetCurrentThreadId() ^ GetCurrentProcessId();

		// PRNG simple mais suffisant pour XID
		seed = seed * 1103515245 + 12345;
		CurInterface.State.last_txid[0] = (BYTE)((seed >> 16) & 0xFF);
		CurInterface.State.last_txid[1] = (BYTE)((seed >> 8) & 0xFF);
		CurInterface.State.last_txid[2] = (BYTE)(seed & 0xFF);
	}

}


// ============================================================================
// CONFIGURATION - Ajout des options RA/RDNSS
// ============================================================================

/**
 * @brief Charge la configuration complète depuis le registre.
 *
 * Charge :
 *   - WANInterface
 *   - LANInterfaceX
 *   - AllowSingle64
 *   - ForceStableDUID
 *   - DisableRelease
 *   - MinPrefixLen / MaxPrefixLen
 *   - EnableRA, RAInterval, RALifetime
 *   - RDNSSLifetime
 *   - DNSServerX
 *
 * Applique :
 *   - valeurs par défaut si absent
 *   - validation des plages
 *
 * @retval TRUE  Si la configuration est chargée ou par défaut.
 * @retval FALSE Si la clé n’existe pas (defaults appliqués).
 */
static BOOL LoadConfigFromRegistry()
{
	HKEY hKey = NULL;
	LONG result;
	DWORD size;
	DWORD value = 0;
	WCHAR log[512] = { 0 };

	// Valeurs par défaut
	wcscpy_s(CurInterface.Config.wan_interface, _countof(CurInterface.Config.wan_interface), L"Internet");
	CurInterface.State.Version = 0;
	CurInterface.Config.lan_count = 0;
	CurInterface.Config.force_stable_duid = TRUE;
	CurInterface.Config.disable_release = FALSE;
	CurInterface.Config.min_prefix_len = MIN_PREFIX_LEN;
	CurInterface.Config.max_prefix_len = MAX_PREFIX_LEN;
	CurInterface.Config.allow_single_64 = FALSE;

	// Valeurs par défaut RA
	CurInterface.Config.enable_ra = TRUE;
	CurInterface.Config.ra_interval_sec = 600;     // 10 minutes
	CurInterface.Config.ra_lifetime_sec = 1800;    // 30 minutes
	CurInterface.Config.rdnss_lifetime_sec = 1200; // 20 minutes
	CurInterface.Config.dns_count = 0;

	result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_DHCPV6, 0, KEY_READ, &hKey);
	if (result != ERROR_SUCCESS)
	{
		_snwprintf_s(log, _countof(log), _TRUNCATE,
			L"Config: Using defaults (registry key not found: %lu)", result);
		LogMessage(log);
		return FALSE;
	}

	// WAN Interface
	size = sizeof(CurInterface.Config.wan_interface);
	result = RegQueryValueExW(hKey, L"WANInterface", NULL, NULL,
		(BYTE*)CurInterface.Config.wan_interface, &size);
	if (result != ERROR_SUCCESS)
	{
		LogMessage(L"Config: Using default WAN interface 'Internet'");
	}

	// LAN Interfaces
	CurInterface.Config.lan_count = 0;
	for (int i = 0; i < MAX_LAN_INTERFACES; i++)
	{
		WCHAR name[32];
		_snwprintf_s(name, _countof(name), _TRUNCATE, L"LANInterface%d", i);
		size = sizeof(CurInterface.Config.lan_interfaces[i]);
		result = RegQueryValueExW(hKey, name, NULL, NULL,
			(BYTE*)CurInterface.Config.lan_interfaces[i], &size);
		if (result == ERROR_SUCCESS)
		{
			CurInterface.Config.lan_count++;
		}
		else
		{
			break;
		}
	}

	// AllowSingle64
	size = sizeof(DWORD);
	if (RegQueryValueExW(hKey, L"AllowSingle64", NULL, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS)
	{
		CurInterface.Config.allow_single_64 = (value != 0);
	}

	// ForceStableDUID
	value = 0;
	size = sizeof(DWORD);
	if (RegQueryValueExW(hKey, L"ForceStableDUID", NULL, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS)
	{
		CurInterface.Config.force_stable_duid = (value != 0);
	}

	// DisableRelease
	value = 0;
	size = sizeof(DWORD);
	if (RegQueryValueExW(hKey, L"DisableRelease", NULL, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS)
	{
		CurInterface.Config.disable_release = (value != 0);
	}

	// MinPrefixLen
	value = MIN_PREFIX_LEN;
	size = sizeof(DWORD);
	if (RegQueryValueExW(hKey, L"MinPrefixLen", NULL, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS)
	{
		if (value >= 32 && value <= 64)
		{
			CurInterface.Config.min_prefix_len = value;
		}
	}

	// MaxPrefixLen
	value = MAX_PREFIX_LEN;
	size = sizeof(DWORD);
	if (RegQueryValueExW(hKey, L"MaxPrefixLen", NULL, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS)
	{
		if (value >= 32 && value <= 64 && value >= CurInterface.Config.min_prefix_len)
		{
			CurInterface.Config.max_prefix_len = value;
		}
	}

	// EnableRA
	size = sizeof(DWORD);
	if (RegQueryValueExW(hKey, L"EnableRA", NULL, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS)
	{
		CurInterface.Config.enable_ra = (value != 0);
	}

	// RAInterval
	size = sizeof(DWORD);
	if (RegQueryValueExW(hKey, L"RAInterval", NULL, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS)
	{
		if (value >= 4 && value <= 1800)  // RFC 4861: 4-1800 secondes
		{
			CurInterface.Config.ra_interval_sec = value;
		}
	}

	// RALifetime
	size = sizeof(DWORD);
	if (RegQueryValueExW(hKey, L"RALifetime", NULL, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS)
	{
		if (value <= 9000)  // RFC 4861: max 9000 secondes
		{
			CurInterface.Config.ra_lifetime_sec = value;
		}
	}

	// RDNSSLifetime
	size = sizeof(DWORD);
	if (RegQueryValueExW(hKey, L"RDNSSLifetime", NULL, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS)
	{
		CurInterface.Config.rdnss_lifetime_sec = value;
	}

	// DNS Servers (DNSServer0, DNSServer1, ...)
	for (int i = 0; i < MAX_DNS_SERVERS; i++)
	{
		WCHAR name[32];
		WCHAR dns_str[INET6_ADDRSTRLEN];
		_snwprintf_s(name, _countof(name), _TRUNCATE, L"DNSServer%d", i);
		size = sizeof(dns_str);

		if (RegQueryValueExW(hKey, name, NULL, NULL, (BYTE*)dns_str, &size) == ERROR_SUCCESS)
		{
			// "::1" signifie "préfixe::1" - on résout plus tard
			if (wcscmp(dns_str, L"::1") == 0)
			{
				// Marquer comme "self" avec tous 0 sauf dernier octet
				memset(CurInterface.Config.dns_servers[i], 0, 16);
				CurInterface.Config.dns_servers[i][15] = 1;
				CurInterface.Config.dns_count++;
			}
			else if (InetPtonW(AF_INET6, dns_str, CurInterface.Config.dns_servers[i]) == 1)
			{
				CurInterface.Config.dns_count++;
			}
		}
		else
		{
			break;
		}
	}

	// Si aucun DNS configuré, utiliser ::1 (préfixe::1)
	if (CurInterface.Config.dns_count == 0)
	{
		memset(CurInterface.Config.dns_servers[0], 0, 16);
		CurInterface.Config.dns_servers[0][15] = 1;
		CurInterface.Config.dns_count = 1;
		LogMessage(L"No DNS servers configured, using ::1 (prefix::1)");
	}

	RegCloseKey(hKey);

	_snwprintf_s(log, _countof(log), _TRUNCATE,
		L"Config: WAN='%s', LANs=%d, RA=%d (interval=%us), DNS=%d",
		CurInterface.Config.wan_interface,
		CurInterface.Config.lan_count,
		CurInterface.Config.enable_ra,
		CurInterface.Config.ra_interval_sec,
		CurInterface.Config.dns_count);
	LogMessage(log);

	GenerateDUID();
	GenerateIAIDs();

	return TRUE;
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

/**
 * @brief Enregistre un callback utilisateur pour les changements de préfixe.
 *
 * @param[in] callback   Fonction callback.
 * @param[in] user_data  Contexte utilisateur.
 */
static void RegisterPrefixChangeCallback(PrefixChangeCallback callback, void* user_data)
{
	if (!callback)
	{
		LogError(L"RegisterPrefixChangeCallback: NULL callback");
		return;
	}

	CurInterface._prefix_change_callback = callback;
	CurInterface._callback_user_data = user_data;

	LogMessage(L"Prefix change callback registered");
}

/**
 * @brief Notifie le serveur d’un changement de préfixe via le callback enregistré.
 *
 * Construit la liste des préfixes LAN à partir des préfixes WAN.
 */
static void NotifyPrefixChangeCallback()
{
	if (!CurInterface._prefix_change_callback)
		return;

	// Construire la liste des préfixes LAN actuels
	IAPrefix lan_prefixes[MAX_LAN_INTERFACES * MAX_PREFIXES];
	DWORD lan_count = 0;

	for (int pi = 0; pi < CurInterface.State.prefix_count && pi < MAX_PREFIXES; pi++)
	{
		IAPrefix* pd = &CurInterface.State.prefixes[pi];

		if (pd->prefix_len < 48 || pd->prefix_len > 64)
			continue;

		// Cas /64 unique
		if (pd->prefix_len == 64 && CurInterface.Config.allow_single_64)
		{
			if (lan_count < _countof(lan_prefixes))
			{
				memcpy(&lan_prefixes[lan_count], pd, sizeof(IAPrefix));
				lan_count++;
			}
			continue;
		}

		// Sous-réseaux multiples
		int subnet_bits = 64 - pd->prefix_len;
		int max_subnets = 1 << subnet_bits;
		int num_subnets = min(max_subnets, CurInterface.Config.lan_count);

		for (int sub = 0; sub < num_subnets; sub++)
		{
			if (lan_count >= _countof(lan_prefixes))
				break;

			BYTE subnet_prefix[16];
			if (!IPv6_CalculateSubnet(pd->prefix, pd->prefix_len, 64,
				(DWORD)sub, subnet_prefix))
				continue;

			IAPrefix* lan_pf = &lan_prefixes[lan_count];
			memcpy(lan_pf->prefix, subnet_prefix, 16);
			lan_pf->prefix_len = 64;
			lan_pf->valid_lifetime = pd->valid_lifetime;
			lan_pf->preferred_lifetime = pd->preferred_lifetime;
			lan_count++;
		}
	}

	WCHAR log[128];
	swprintf_s(log, _countof(log),
		L"Notifying server: %d client prefixes, %d LAN prefixes",
		CurInterface.State.prefix_count, lan_count);
	LogMessage(log);

	// Appeler le callback
	CurInterface._prefix_change_callback(
		(const void*)CurInterface.State.prefixes,
		(DWORD)CurInterface.State.prefix_count,
		(const void*)lan_prefixes,
		lan_count,
		CurInterface._callback_user_data
	);
}

// ============================================================================
// DHCPv6 MESSAGES
// ============================================================================

/**
 * @brief Ajoute une option DHCPv6 dans un buffer.
 *
 * @param[in,out] buf     Buffer DHCPv6.
 * @param[in]     off     Offset actuel.
 * @param[in]     max_len Taille max du buffer.
 * @param[in]     code    Code d’option.
 * @param[in]     len     Longueur de l’option.
 * @param[in]     data    Données de l’option.
 *
 * @return Nouveau offset après écriture.
 */
static WORD AddOption(BYTE* buf, WORD off, WORD max_len, WORD code, WORD len, const BYTE* data)
{
	if (off + 4 + len > max_len)
	{
		WCHAR log[128];
		_snwprintf_s(log, _countof(log), _TRUNCATE,
			L"Buffer overflow in AddOption: off=%u, len=%u, max=%u",
			off, len, max_len);
		LogError(log);
		return off;
	}

	buf[off++] = (code >> 8) & 0xFF;
	buf[off++] = code & 0xFF;
	buf[off++] = (len >> 8) & 0xFF;
	buf[off++] = len & 0xFF;

	if (data && len > 0)
	{
		memcpy(&buf[off], data, len);
		off += len;
	}

	return off;
}

/**
 * @brief Crée un message DHCPv6 dans le buffer fourni.
 *
 * @param[out] buf     Buffer pour le message DHCPv6.
 * @param[in]  buflen  Taille du buffer.
 * @param[in]  type    Type de message DHCPv6.
 *
 * @return Taille du message créé, ou 0 en cas d’erreur.
 */
static int CreateDHCPv6Message(BYTE* buf, DWORD buflen, BYTE type)
{
	if (buflen < 1024)
	{
		LogError(L"CreateDHCPv6Message: Buffer too small");
		return 0;
	}

	WORD off = 0;
	buf[off++] = type;

	if (type == DHCPV6_SOLICIT || type == DHCPV6_RENEW || type == DHCPV6_REBIND)
	{
		GenerateTransactionID();
		CurInterface.State.transaction_start = time(NULL);
	}

	memcpy(&buf[off], CurInterface.State.last_txid, 3);
	off += 3;

	off = AddOption(buf, off, (WORD)buflen, OPTION_CLIENTID, CurInterface.State.duid_len, CurInterface.State.duid);

	if (type != DHCPV6_SOLICIT && CurInterface.State.selected_server_duid_len > 0)
	{
		off = AddOption(buf, off, (WORD)buflen, OPTION_SERVERID,
			CurInterface.State.selected_server_duid_len, CurInterface.State.selected_server_duid);
	}

	// IA_NA
	if (type == DHCPV6_SOLICIT)
	{
		BYTE ia[12] = { 0 };
		DWORD iaid = htonl(CurInterface.State.iaid_na);
		memcpy(ia, &iaid, 4);
		off = AddOption(buf, off, (WORD)buflen, OPTION_IA_NA, 12, ia);
	}
	else if (type != DHCPV6_RELEASE && CurInterface.State.has_wan_address)
	{
		BYTE ia[256];
		WORD io = 0;
		DWORD iaid = htonl(CurInterface.State.iaid_na);
		memcpy(&ia[io], &iaid, 4); io += 4;

		DWORD t1 = htonl(CurInterface.State.t1_na), t2 = htonl(CurInterface.State.t2_na);
		memcpy(&ia[io], &t1, 4); io += 4;
		memcpy(&ia[io], &t2, 4); io += 4;

		// FIX: Sous-option IAADDR avec encodage correct
		ia[io++] = (OPTION_IAADDR >> 8) & 0xFF;
		ia[io++] = OPTION_IAADDR & 0xFF;
		ia[io++] = 0;
		ia[io++] = 24;
		memcpy(&ia[io], CurInterface.State.wan_address.addr, 16); io += 16;

		DWORD pref = htonl(CurInterface.State.wan_address.preferred_lifetime);
		DWORD valid = htonl(CurInterface.State.wan_address.valid_lifetime);
		memcpy(&ia[io], &pref, 4); io += 4;
		memcpy(&ia[io], &valid, 4); io += 4;

		off = AddOption(buf, off, (WORD)buflen, OPTION_IA_NA, io, ia);
	}

	// IA_PD
	if (type == DHCPV6_SOLICIT)
	{
		BYTE ia[12] = { 0 };
		DWORD iaid = htonl(CurInterface.State.iaid_pd);
		memcpy(ia, &iaid, 4);
		off = AddOption(buf, off, (WORD)buflen, OPTION_IA_PD, 12, ia);
	}
	else if (type != DHCPV6_RELEASE && CurInterface.State.prefix_count > 0)
	{
		BYTE ia[512];
		WORD io = 0;
		DWORD iaid = htonl(CurInterface.State.iaid_pd);
		memcpy(&ia[io], &iaid, 4); io += 4;

		DWORD t1 = htonl(CurInterface.State.t1_pd), t2 = htonl(CurInterface.State.t2_pd);
		memcpy(&ia[io], &t1, 4); io += 4;
		memcpy(&ia[io], &t2, 4); io += 4;

		for (int i = 0; i < CurInterface.State.prefix_count && i < MAX_PREFIXES; i++)
		{
			if (io + 29 > sizeof(ia))
			{
				LogError(L"IA_PD buffer full, truncating prefixes");
				break;
			}

			// FIX: Sous-option IAPREFIX avec encodage correct
			ia[io++] = (OPTION_IAPREFIX >> 8) & 0xFF;
			ia[io++] = OPTION_IAPREFIX & 0xFF;
			ia[io++] = 0;
			ia[io++] = 25;

			DWORD pref = htonl(CurInterface.State.prefixes[i].preferred_lifetime);
			DWORD valid = htonl(CurInterface.State.prefixes[i].valid_lifetime);
			memcpy(&ia[io], &pref, 4); io += 4;
			memcpy(&ia[io], &valid, 4); io += 4;

			ia[io++] = CurInterface.State.prefixes[i].prefix_len;
			memcpy(&ia[io], CurInterface.State.prefixes[i].prefix, 16); io += 16;
		}

		if (off + 4 + (DWORD)io > buflen)
		{
			LogError(L"Message buffer overflow prevented");
			return 0;
		}

		off = AddOption(buf, off, (WORD)buflen, OPTION_IA_PD, io, ia);
	}

	// Elapsed time
	WORD et = 0;
	if (CurInterface.State.transaction_start > 0)
	{
		time_t elapsed = time(NULL) - CurInterface.State.transaction_start;
		if (elapsed > 0 && elapsed < 655)
		{
			et = (WORD)(elapsed * 100);
		}
		else if (elapsed >= 655)
		{
			et = 0xFFFF;
		}
	}
	BYTE elapsed[2] = { (et >> 8) & 0xFF, et & 0xFF };
	off = AddOption(buf, off, (WORD)buflen, OPTION_ELAPSED_TIME, 2, elapsed);

	// FIX: ORO avec encodage correct sur 2 octets par option
	if (type == DHCPV6_SOLICIT)
	{
		WORD oro_list[] = {
			OPTION_IA_NA,
			OPTION_IA_PD,
			OPTION_DNS_SERVERS,
			OPTION_INFORMATION_REFRESH_TIME,
			OPTION_SOL_MAX_RT
		};

		BYTE oro[20];  // 5 options * 2 octets = 10 octets max, mais allouer 20 par précaution en cas d'extension future
		int oo = 0;

		for (int i = 0; i < _countof(oro_list); i++)
		{
			oro[oo++] = (oro_list[i] >> 8) & 0xFF;
			oro[oo++] = oro_list[i] & 0xFF;
		}

		off = AddOption(buf, off, (WORD)buflen, OPTION_ORO, (WORD)oo, oro);
	}

	WCHAR log[128];
	_snwprintf_s(log, _countof(log), _TRUNCATE, L"Message created: %u bytes", off);
	LogMessage(log);

	return (int)off;
}

// ============================================================================
// ROUTER ADVERTISEMENT - RFC 4861 + RDNSS (RFC 8106)
// ============================================================================

/**
* @brief Calcule le checksum ICMPv6 (RFC 2460).
*
* Utilise le pseudo-header IPv6 (source, destination, longueur, Next Header)
* et le contenu complet du paquet ICMPv6.
*
* @param[in] src_addr     Adresse source IPv6 (16 octets).
* @param[in] dst_addr     Adresse destination IPv6 (16 octets).
* @param[in] icmp_packet  Paquet ICMPv6 brut.
* @param[in] icmp_len     Longueur du paquet ICMPv6.
*
* @return Checksum ICMPv6 au format 16 bits.
*/
static uint16_t CalculateICMPv6Checksum(
	const BYTE* src_addr,
	const BYTE* dst_addr,
	const BYTE* icmp_packet,
	size_t icmp_len)
{
	uint32_t sum = 0;

	// Pseudo-header: source address (16 octets)
	for (int i = 0; i < 16; i += 2)
	{
		sum += (src_addr[i] << 8) | src_addr[i + 1];
	}

	// Pseudo-header: destination address (16 octets)
	for (int i = 0; i < 16; i += 2)
	{
		sum += (dst_addr[i] << 8) | dst_addr[i + 1];
	}

	// Pseudo-header: ICMPv6 length (32 bits)
	sum += (icmp_len >> 16) & 0xFFFF;
	sum += icmp_len & 0xFFFF;

	// Pseudo-header: next header = 58 (ICMPv6)
	sum += 58;

	// ICMPv6 packet
	for (size_t i = 0; i < icmp_len; i += 2)
	{
		if (i + 1 < icmp_len)
		{
			sum += (icmp_packet[i] << 8) | icmp_packet[i + 1];
		}
		else
		{
			sum += icmp_packet[i] << 8;
		}
	}

	// Fold 32-bit sum to 16 bits
	while (sum >> 16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return (uint16_t)~sum;
}

/**
* @brief Envoie un Router Advertisement complet sur une interface LAN.
*
* Construit un RA incluant :
*   - en-tête ICMPv6 Router Advertisement
*   - une ou plusieurs options Prefix Information (par préfixe délégué)
*   - une option RDNSS (RFC 8106) si des DNS sont configurés
*
* Le paquet est émis vers ff02::1 (all-nodes multicast) sur l’interface LAN
* spécifiée par son index logique.
*
* @param[in] lan_index  Index logique de l’interface LAN dans la configuration.
*
* @retval TRUE  Si le RA a été envoyé avec succès.
* @retval FALSE Si l’interface est introuvable ou en cas d’erreur socket.
*/
static BOOL SendRA(int lan_index)
{
	WCHAR log[256];

	if (lan_index < 0 || lan_index >= CurInterface.Config.lan_count)
	{
		return FALSE;
	}

	NET_LUID lan_luid;
	NET_IFINDEX lan_ifindex;

	if (!GetCurInterfaceInfo(CurInterface.Config.lan_interfaces[lan_index], &lan_luid, &lan_ifindex))
	{
		_snwprintf_s(log, _countof(log), _TRUNCATE,
			L"SendRA: LAN interface %d (%s) not found",
			lan_index, CurInterface.Config.lan_interfaces[lan_index]);
		LogError(log);
		return FALSE;
	}

	// Obtenir l'adresse link-local de l'interface LAN
	BYTE src_addr[16] = { 0 };
	BOOL has_src = FALSE;

	MIB_UNICASTIPADDRESS_TABLE* addr_table = NULL;
	if (GetUnicastIpAddressTable(AF_INET6, &addr_table) == NO_ERROR)
	{
		for (ULONG i = 0; i < addr_table->NumEntries; i++)
		{
			if (addr_table->Table[i].InterfaceLuid.Value == lan_luid.Value)
			{
				BYTE* addr = addr_table->Table[i].Address.Ipv6.sin6_addr.s6_addr;
				// Link-local: FE80::/10
				if (addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80)
				{
					memcpy(src_addr, addr, 16);
					has_src = TRUE;
					break;
				}
			}
		}
		FreeMibTable(addr_table);
	}

	if (!has_src)
	{
		_snwprintf_s(log, _countof(log), _TRUNCATE,
			L"SendRA: No link-local on LAN %d, skipping", lan_index);
		return FALSE;
	}

	// Créer le socket ICMPv6
	SOCKET s = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (s == INVALID_SOCKET)
	{
		LogError(L"SendRA: Failed to create ICMPv6 socket");
		return FALSE;
	}

	// Bind à l'interface spécifique
	setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char*)&lan_ifindex, sizeof(lan_ifindex));

	// Construire le paquet RA
	BYTE packet[512] = { 0 };
	size_t offset = 0;

	// 1. ICMPv6 Router Advertisement header
	struct icmp6_ra* ra = (struct icmp6_ra*)packet;
	ra->type = ICMPV6_RA_TYPE;  // ND_ROUTER_ADVERT
	ra->code = 0;
	ra->cksum = 0;  // Calculé plus tard
	ra->hop_limit = 64;
	ra->flags = 0;  // M=0 (pas de DHCPv6 managed), O=0 (pas de DHCPv6 other)
	ra->router_lifetime = htons((uint16_t)CurInterface.Config.ra_lifetime_sec);
	ra->reachable_time = 0;
	ra->retrans_timer = 0;
	offset += sizeof(struct icmp6_ra);

	// 2. Pour chaque préfixe délégué, ajouter une option Prefix Information
	for (int pi = 0; pi < CurInterface.State.prefix_count && pi < MAX_PREFIXES; pi++)
	{
		IAPrefix* pd = &CurInterface.State.prefixes[pi];

		if (pd->prefix_len < 48 || pd->prefix_len > 64) continue;

		// Cas /64 unique - publier sur LAN 0 seulement
		if (pd->prefix_len == 64 && CurInterface.Config.allow_single_64)
		{
			if (lan_index != 0) continue;  // Skip autres LANs

			struct nd_opt_prefix_info* opt = (struct nd_opt_prefix_info*)(packet + offset);
			opt->type = ND_OPT_PREFIX_INFO;
			opt->len = 4;  // 32 octets
			opt->prefix_len = 64;
			opt->flags = 0xC0;  // L=1 (on-link), A=1 (autonomous)
			opt->valid_lifetime = htonl(pd->valid_lifetime);
			opt->preferred_lifetime = htonl(pd->preferred_lifetime);
			opt->reserved2 = 0;
			memcpy(opt->prefix, pd->prefix, 16);
			offset += sizeof(struct nd_opt_prefix_info);

			WCHAR ipstr[INET6_ADDRSTRLEN];
			InetNtop(AF_INET6, pd->prefix, ipstr, _countof(ipstr));
			_snwprintf_s(log, _countof(log), _TRUNCATE,
				L"RA: Single /64 %s on LAN 0", ipstr);
			LogMessage(log);
			continue;
		}

		// Préfixes subdivisés - calculer le sous-réseau pour ce LAN
		int subnet_bits = 64 - pd->prefix_len;
		int max_subnets = 1 << subnet_bits;

		if (lan_index >= max_subnets) continue;

		BYTE subnet_prefix[16];
		if (!IPv6_CalculateSubnet(pd->prefix, pd->prefix_len, 64, (DWORD)lan_index, subnet_prefix))
		{
			continue;
		}

		struct nd_opt_prefix_info* opt = (struct nd_opt_prefix_info*)(packet + offset);
		opt->type = ND_OPT_PREFIX_INFO;
		opt->len = 4;
		opt->prefix_len = 64;
		opt->flags = 0xC0;  // L=1, A=1
		opt->valid_lifetime = htonl(pd->valid_lifetime);
		opt->preferred_lifetime = htonl(pd->preferred_lifetime);
		opt->reserved2 = 0;
		memcpy(opt->prefix, subnet_prefix, 16);
		offset += sizeof(struct nd_opt_prefix_info);

		WCHAR ipstr[INET6_ADDRSTRLEN];
		InetNtop(AF_INET6, subnet_prefix, ipstr, _countof(ipstr));
		_snwprintf_s(log, _countof(log), _TRUNCATE,
			L"RA: Prefix %s/64 on LAN %d", ipstr, lan_index);
		LogMessage(log);
	}

	// 3. Option RDNSS (DNS servers)
	if (CurInterface.Config.dns_count > 0)
	{
		struct nd_opt_rdnss* opt = (struct nd_opt_rdnss*)(packet + offset);
		opt->type = ND_OPT_RDNSS;
		opt->len = (BYTE)(1 + (CurInterface.Config.dns_count * 2));  // 8 + (N * 16) octets / 8
		opt->reserved = 0;
		opt->lifetime = htonl(CurInterface.Config.rdnss_lifetime_sec);

		for (int i = 0; i < CurInterface.Config.dns_count && i < MAX_DNS_SERVERS; i++)
		{
			memcpy(&opt->dns[i], CurInterface.Config.dns_servers[i], 16);
		}

		offset += 8 + (CurInterface.Config.dns_count * 16);

		_snwprintf_s(log, _countof(log), _TRUNCATE,
			L"RA: RDNSS with %d DNS servers", CurInterface.Config.dns_count);
		LogMessage(log);
	}

	// 4. Calculer le checksum
	BYTE dst_addr[16];
	inet_pton(AF_INET6, "ff02::1", dst_addr);  // All nodes multicast

	uint16_t cksum = CalculateICMPv6Checksum(src_addr, dst_addr, packet, offset);
	ra->cksum = htons(cksum);

	// 5. Envoyer le paquet
	struct sockaddr_in6 dest = { 0 };
	dest.sin6_family = AF_INET6;
	inet_pton(AF_INET6, "ff02::1", &dest.sin6_addr);
	dest.sin6_scope_id = lan_ifindex;

	int sent = sendto(s, (char*)packet, (int)offset, 0, (struct sockaddr*)&dest, sizeof(dest));
	closesocket(s);

	if (sent > 0)
	{
		_snwprintf_s(log, _countof(log), _TRUNCATE,
			L"RA sent on LAN %d (%d bytes)", lan_index, sent);
		LogMessage(log);
		return TRUE;
	}
	else
	{
		_snwprintf_s(log, _countof(log), _TRUNCATE,
			L"RA failed on LAN %d (error %d)", lan_index, WSAGetLastError());
		LogError(log);
		return FALSE;
	}
}

/**
* @brief Envoie des Router Advertisements sur toutes les interfaces LAN configurées.
*
* Conditions :
*   - RA doit être activé (Config.enable_ra == TRUE).
*   - Au moins un préfixe délégué doit être présent (prefix_count > 0).
*
* Met à jour CurInterface.State.last_ra_time.
*/
static void SendAllRAs()
{
	if (!CurInterface.Config.enable_ra)
	{
		return;
	}

	if (CurInterface.State.prefix_count == 0)
	{
		return;
	}

	WCHAR log[128];
	_snwprintf_s(log, _countof(log), _TRUNCATE,
		L"Sending RAs on %d LAN interfaces", CurInterface.Config.lan_count);
	LogMessage(log);

	for (int i = 0; i < CurInterface.Config.lan_count; i++)
	{
		SendRA(i);
	}

	CurInterface.State.last_ra_time = time(NULL);
}

// ============================================================================
// PARSE RESPONSE
// ============================================================================

/**
* @brief Analyse un message DHCPv6 reçu et met à jour l’état interne.
*
* Gère :
*   - ADVERTISE (sélection du serveur)
*   - REPLY (IA_NA, IA_PD)
*   - SOL_MAX_RT (temps max entre SOLICIT)
*   - lifetimes (T1/T2, valid/preferred)
*   - validation stricte des préfixes (longueur, type, plage)
*
* Met à jour :
*   - CurInterface.State.wan_address / has_wan_address
*   - CurInterface.State.prefixes / prefix_count
*   - CurInterface.State.t1_na / t2_na / t1_pd / t2_pd
*   - CurInterface.State.selected_server_duid
*
* @param[in] buf            Buffer contenant le message DHCPv6.
* @param[in] len            Longueur du message en octets.
* @param[in] expected_type  Type de message attendu (ADVERTISE, REPLY, etc.).
*
* @retval TRUE  Si le message est valide et fournit une adresse ou un préfixe.
* @retval FALSE Si le message est invalide, rejeté ou sans utilité.
*/
static BOOL ParseResponse(BYTE* buf, int len, BYTE expected_type)
{
	if (len < 4) return FALSE;
	if (buf[0] != expected_type) return FALSE;
	if (memcmp(&buf[1], CurInterface.State.last_txid, 3) != 0) return FALSE;

	int off = 4;
	BOOL err = FALSE;
	BOOL has_server_id = FALSE;
	BYTE received_server_duid[MAX_SERVER_DUID_LEN] = { 0 };
	WORD received_server_duid_len = 0;
	WCHAR log[256] = { 0 };

	// Réinitialiser SOL_MAX_RT à la valeur par défaut
	CurInterface.State.sol_max_rt_ms = DEFAULT_SOL_MAX_RT_MS;

	// Variables pour validation T1/T2
	DWORD min_valid_na = 0xFFFFFFFF;
	DWORD min_valid_pd = 0xFFFFFFFF;
	BOOL has_ia_na = FALSE;
	BOOL has_ia_pd = FALSE;

	while (off + 4 <= len)
	{
		WORD code = (buf[off] << 8) | buf[off + 1];
		WORD olen = (buf[off + 2] << 8) | buf[off + 3];
		off += 4;

		if (off + olen > len)
		{
			LogError(L"ParseResponse: Option length exceeds buffer");
			break;
		}

		if (code == OPTION_STATUS_CODE && olen >= 2)
		{
			WORD st = (buf[off] << 8) | buf[off + 1];
			if (st != 0)
			{
				_snwprintf_s(log, _countof(log), _TRUNCATE, L"STATUS_CODE error: %u", st);
				LogError(log);
				err = TRUE;
			}
		}
		else if (code == OPTION_SERVERID)
		{
			received_server_duid_len = min(olen, MAX_SERVER_DUID_LEN);
			memcpy(received_server_duid, &buf[off], received_server_duid_len);
			has_server_id = TRUE;
		}
		else if (code == OPTION_SOL_MAX_RT && olen >= 4)
		{
			DWORD sol_max_rt_sec = 0;
			memcpy(&sol_max_rt_sec, &buf[off], 4);
			sol_max_rt_sec = ntohl(sol_max_rt_sec);

			// Clamp selon RFC 8415
			if (sol_max_rt_sec < 1) sol_max_rt_sec = 1;
			if (sol_max_rt_sec > 3600) sol_max_rt_sec = 3600;

			CurInterface.State.sol_max_rt_ms = sol_max_rt_sec * 1000;

			_snwprintf_s(log, _countof(log), _TRUNCATE,
				L"SOL_MAX_RT received: %lu sec (%lu ms)",
				sol_max_rt_sec, CurInterface.State.sol_max_rt_ms);
			LogMessage(log);
		}
		else if (code == OPTION_IA_NA)
		{
			has_ia_na = TRUE;

			if (olen >= 12)
			{
				memcpy(&CurInterface.State.t1_na, &buf[off + 4], 4);
				memcpy(&CurInterface.State.t2_na, &buf[off + 8], 4);
				CurInterface.State.t1_na = ntohl(CurInterface.State.t1_na);
				CurInterface.State.t2_na = ntohl(CurInterface.State.t2_na);
			}

			int io = off + 12;
			while (io + 4 <= off + olen)
			{
				WORD iopt = (buf[io] << 8) | buf[io + 1];
				WORD ilen = (buf[io + 2] << 8) | buf[io + 3];
				io += 4;

				if (io + ilen > off + olen) break;

				if (iopt == OPTION_STATUS_CODE && ilen >= 2)
				{
					if (((buf[io] << 8) | buf[io + 1]) != 0) err = TRUE;
				}
				else if (iopt == OPTION_IAADDR && ilen >= 24)
				{
					memcpy(CurInterface.State.wan_address.addr, &buf[io], 16);
					memcpy(&CurInterface.State.wan_address.preferred_lifetime, &buf[io + 16], 4);
					memcpy(&CurInterface.State.wan_address.valid_lifetime, &buf[io + 20], 4);
					CurInterface.State.wan_address.preferred_lifetime = ntohl(CurInterface.State.wan_address.preferred_lifetime);
					CurInterface.State.wan_address.valid_lifetime = ntohl(CurInterface.State.wan_address.valid_lifetime);

					// Validation de l'adresse WAN
					BYTE first_byte = CurInterface.State.wan_address.addr[0];
					if (first_byte == 0xFF)
					{  // Multicast
						LogError(L"WAN address is multicast - rejecting");
						err = TRUE;
					}
					else if (first_byte == 0xFE && (CurInterface.State.wan_address.addr[1] & 0xC0) == 0x80)
					{
						LogMessage(L"WAN address is link-local - accepting");
					}

					CurInterface.State.has_wan_address = TRUE;

					// Tracker le min valid_lifetime
					if (CurInterface.State.wan_address.valid_lifetime < min_valid_na)
					{
						min_valid_na = CurInterface.State.wan_address.valid_lifetime;
					}

					IPv6_LogAddress(L"WAN address assigned", CurInterface.State.wan_address.addr);
				}
				io += ilen;
			}
		}
		else if (code == OPTION_IA_PD)
		{
			has_ia_pd = TRUE;

			if (olen >= 12)
			{
				memcpy(&CurInterface.State.t1_pd, &buf[off + 4], 4);
				memcpy(&CurInterface.State.t2_pd, &buf[off + 8], 4);
				CurInterface.State.t1_pd = ntohl(CurInterface.State.t1_pd);
				CurInterface.State.t2_pd = ntohl(CurInterface.State.t2_pd);
			}

			int io = off + 12;
			CurInterface.State.prefix_count = 0;

			while (io + 4 <= off + olen && CurInterface.State.prefix_count < MAX_PREFIXES)
			{
				WORD iopt = (buf[io] << 8) | buf[io + 1];
				WORD ilen = (buf[io + 2] << 8) | buf[io + 3];
				io += 4;

				if (io + ilen > off + olen) break;

				if (iopt == OPTION_STATUS_CODE && ilen >= 2)
				{
					if (((buf[io] << 8) | buf[io + 1]) != 0) err = TRUE;
				}
				else if (iopt == OPTION_IAPREFIX && ilen >= 25)
				{
					IAPrefix* p = &CurInterface.State.prefixes[CurInterface.State.prefix_count];
					memcpy(&p->preferred_lifetime, &buf[io], 4);
					memcpy(&p->valid_lifetime, &buf[io + 4], 4);
					p->preferred_lifetime = ntohl(p->preferred_lifetime);
					p->valid_lifetime = ntohl(p->valid_lifetime);
					p->prefix_len = buf[io + 8];
					memcpy(p->prefix, &buf[io + 9], 16);

					// Validation stricte du préfixe
					BYTE first_byte = p->prefix[0];

					// Rejeter les préfixes non valides
					if (first_byte == 0xFF)
					{  // Multicast
						_snwprintf_s(log, _countof(log), _TRUNCATE,
							L"Prefix rejected: multicast prefix");
						LogError(log);
					}
					else if ((first_byte & 0xFE) == 0xFC)
					{  // Unique Local (FC00::/7)
					   // Accepté - c'est bien pour LAN
					}
					else if (first_byte == 0x00)
					{  // Possiblement ::/0
						BOOL all_zero = TRUE;
						for (int i = 0; i < 16; i++)
						{
							if (p->prefix[i] != 0)
							{
								all_zero = FALSE;
								break;
							}
						}
						if (all_zero)
						{
							LogError(L"Prefix rejected: ::/0");
							io += ilen;
							continue;
						}
					}
					else if (p->prefix_len < (BYTE)CurInterface.Config.min_prefix_len)
					{
						_snwprintf_s(log, _countof(log), _TRUNCATE,
							L"Prefix /%u refused (too small, min /%u)",
							p->prefix_len, CurInterface.Config.min_prefix_len);
						LogError(log);
					}
					else if (p->prefix_len > (BYTE)CurInterface.Config.max_prefix_len)
					{
						_snwprintf_s(log, _countof(log), _TRUNCATE,
							L"Prefix /%u refused (too large, max /%u)",
							p->prefix_len, CurInterface.Config.max_prefix_len);
						LogError(log);
					}
					else if (p->prefix_len == 64 && !CurInterface.Config.allow_single_64)
					{
						LogMessage(L"Single /64 refused (set AllowSingle64=1)");
					}
					else
					{
						// Tracker le min valid_lifetime
						if (p->valid_lifetime < min_valid_pd)
						{
							min_valid_pd = p->valid_lifetime;
						}

						WCHAR ipstr[INET6_ADDRSTRLEN];
						if (InetNtop(AF_INET6, p->prefix, ipstr, _countof(ipstr)))
						{
							_snwprintf_s(log, _countof(log), _TRUNCATE,
								L"Prefix accepted: %s/%u (valid=%lu, pref=%lu)",
								ipstr, p->prefix_len,
								p->valid_lifetime, p->preferred_lifetime);
							LogMessage(log);
						}
						CurInterface.State.prefix_count++;
					}
				}
				io += ilen;
			}
		}
		off += olen;
	}


	if (!has_ia_na && expected_type == DHCPV6_REPLY)
	{
		LogMessage(L"No IA_NA in REPLY - checking for SLAAC address");
		if (GetSLAACAddress())
		{
			LogMessage(L"Using SLAAC address for WAN");

			// Calculer T1/T2 basés sur le valid_lifetime SLAAC
			if (CurInterface.State.wan_address.valid_lifetime > 0)
			{
				CurInterface.State.t1_na = CurInterface.State.wan_address.valid_lifetime / 2;
				CurInterface.State.t2_na = (CurInterface.State.wan_address.valid_lifetime * 4) / 5;

				_snwprintf_s(log, _countof(log), _TRUNCATE,
					L"SLAAC timers: T1=%u, T2=%u, Valid=%u",
					CurInterface.State.t1_na, CurInterface.State.t2_na,
					CurInterface.State.wan_address.valid_lifetime);
				LogMessage(log);
			}
		}
		else
		{
			LogMessage(L"No IA_NA and no SLAAC address - WAN configuration incomplete");
		}
	}

	// Validation et ajustement T1/T2 avec valid_lifetime
	if (has_ia_na && min_valid_na != 0xFFFFFFFF)
	{
		// Valeurs par défaut si non fournies
		if (CurInterface.State.t1_na == 0)
		{
			CurInterface.State.t1_na = min_valid_na / 2;
		}
		if (CurInterface.State.t2_na == 0)
		{
			CurInterface.State.t2_na = (min_valid_na * 4) / 5;
		}

		// Validation: 0 < T1 < T2 < valid_lifetime
		if (CurInterface.State.t2_na <= CurInterface.State.t1_na)
		{
			LogError(L"Invalid IA_NA: T2 <= T1, adjusting");
			CurInterface.State.t2_na = (CurInterface.State.t1_na * 3) / 2;
		}
		if (CurInterface.State.t2_na >= min_valid_na)
		{
			LogError(L"Invalid IA_NA: T2 >= valid_lifetime, adjusting");
			CurInterface.State.t2_na = (min_valid_na * 4) / 5;
		}
		if (CurInterface.State.t1_na >= CurInterface.State.t2_na)
		{
			CurInterface.State.t1_na = CurInterface.State.t2_na / 2;
		}

		_snwprintf_s(log, _countof(log), _TRUNCATE,
			L"IA_NA timers: T1=%u, T2=%u, Valid=%u",
			CurInterface.State.t1_na, CurInterface.State.t2_na, min_valid_na);
		LogMessage(log);
	}

	if (has_ia_pd && min_valid_pd != 0xFFFFFFFF)
	{
		// Valeurs par défaut si non fournies
		if (CurInterface.State.t1_pd == 0)
		{
			CurInterface.State.t1_pd = min_valid_pd / 2;
		}
		if (CurInterface.State.t2_pd == 0)
		{
			CurInterface.State.t2_pd = (min_valid_pd * 4) / 5;
		}

		// Validation: 0 < T1 < T2 < valid_lifetime
		if (CurInterface.State.t2_pd <= CurInterface.State.t1_pd)
		{
			LogError(L"Invalid IA_PD: T2 <= T1, adjusting");
			CurInterface.State.t2_pd = (CurInterface.State.t1_pd * 3) / 2;
		}
		if (CurInterface.State.t2_pd >= min_valid_pd)
		{
			LogError(L"Invalid IA_PD: T2 >= valid_lifetime, adjusting");
			CurInterface.State.t2_pd = (min_valid_pd * 4) / 5;
		}
		if (CurInterface.State.t1_pd >= CurInterface.State.t2_pd)
		{
			CurInterface.State.t1_pd = CurInterface.State.t2_pd / 2;
		}

		_snwprintf_s(log, _countof(log), _TRUNCATE,
			L"IA_PD timers: T1=%u, T2=%u, Valid=%u",
			CurInterface.State.t1_pd, CurInterface.State.t2_pd, min_valid_pd);
		LogMessage(log);
	}

	// Validation SERVERID
	if (expected_type == DHCPV6_ADVERTISE)
	{
		if (has_server_id)
		{
			received_server_duid_len = min(received_server_duid_len, MAX_SERVER_DUID_LEN);
			memcpy(CurInterface.State.selected_server_duid, received_server_duid, received_server_duid_len);
			CurInterface.State.selected_server_duid_len = received_server_duid_len;

			_snwprintf_s(log, _countof(log), _TRUNCATE,
				L"Server selected, DUID length: %u", received_server_duid_len);
			LogMessage(log);
		}
	}
	else if (expected_type == DHCPV6_REPLY)
	{
		if (has_server_id && CurInterface.State.selected_server_duid_len > 0)
		{
			if (received_server_duid_len != CurInterface.State.selected_server_duid_len ||
				memcmp(received_server_duid, CurInterface.State.selected_server_duid,
					min(received_server_duid_len, CurInterface.State.selected_server_duid_len)) != 0)
			{
				LogError(L"REPLY from different server - rejected");
				return FALSE;
			}
		}
	}

	return (!err && (CurInterface.State.has_wan_address || CurInterface.State.prefix_count > 0));
}

// ============================================================================
// NETWORK CONFIG
// ============================================================================

/**
* @brief Supprime toutes les adresses globales IPv6 gérées par le démon
*        sur l’interface WAN et les interfaces LAN.
*
* Filtre :
*   - ne supprime que les Global Unicast (2000::/3)
*   - ne touche pas aux link-local/multicast.
*/
static void CleanupOldAddresses()
{
	MIB_UNICASTIPADDRESS_TABLE* t = NULL;
	if (GetUnicastIpAddressTable(AF_INET6, &t) == NO_ERROR)
	{
		for (ULONG i = 0; i < t->NumEntries; i++)
		{
			BYTE fb = t->Table[i].Address.Ipv6.sin6_addr.s6_addr[0];
			// Filtrer les adresses globales (2000::/3)
			if (fb < 0x20 || fb > 0x3f) continue;

			if (t->Table[i].InterfaceLuid.Value == CurInterface.State.wan_luid.Value)
			{
				MIB_UNICASTIPADDRESS_ROW r = t->Table[i];
				DeleteUnicastIpAddressEntry(&r);
			}
			for (int j = 0; j < CurInterface.Config.lan_count && j < MAX_LAN_INTERFACES; j++)
			{
				NET_LUID ll;
				if (!GetCurInterfaceInfo(CurInterface.Config.lan_interfaces[j], &ll, NULL)) continue;
				if (t->Table[i].InterfaceLuid.Value == ll.Value)
				{
					MIB_UNICASTIPADDRESS_ROW r = t->Table[i];
					DeleteUnicastIpAddressEntry(&r);
					break;
				}
			}
		}
		FreeMibTable(t);
	}
}

/**
* @brief Supprime les routes IPv6 obsolètes liées à l’interface WAN.
*
* Actuellement :
*   - supprime la route par défaut (::/0) associée au WAN.
*/
static void CleanupOldRoutes()
{
	MIB_IPFORWARD_TABLE2* t = NULL;
	if (GetIpForwardTable2(AF_INET6, &t) == NO_ERROR)
	{
		for (ULONG i = 0; i < t->NumEntries; i++)
		{
			if (t->Table[i].InterfaceLuid.Value == CurInterface.State.wan_luid.Value &&
				t->Table[i].DestinationPrefix.PrefixLength == 0)
			{
				BOOL zero = TRUE;
				for (int j = 0; j < 16; j++)
					if (t->Table[i].DestinationPrefix.Prefix.Ipv6.sin6_addr.s6_addr[j] != 0) zero = FALSE;
				if (zero)
				{
					MIB_IPFORWARD_ROW2 r = t->Table[i];
					DeleteIpForwardEntry2(&r);
				}
			}
		}
		FreeMibTable(t);
	}
}

/**
* @brief Applique l’adresse WAN dans le kernel si nécessaire.
*
* Cas :
*   - si l’adresse existe déjà (SLAAC), elle n’est pas recréée.
*   - sinon, une adresse DHCPv6 IA_NA est créée sur l’interface WAN.
*
* @retval TRUE  Si l’adresse WAN est présente après l’appel.
* @retval FALSE En cas d’erreur de création.
*/
static BOOL ApplyWANAddress()
{
	if (!CurInterface.State.has_wan_address)
	{
		LogMessage(L"No WAN address to apply");
		return FALSE;
	}

	// Vérifier si l'adresse existe déjà (cas SLAAC)
	MIB_UNICASTIPADDRESS_TABLE* t = NULL;
	BOOL already_exists = FALSE;

	if (GetUnicastIpAddressTable(AF_INET6, &t) == NO_ERROR)
	{
		for (ULONG i = 0; i < t->NumEntries; i++)
		{
			if (t->Table[i].InterfaceLuid.Value == CurInterface.State.wan_luid.Value &&
				memcmp(&t->Table[i].Address.Ipv6.sin6_addr,
					CurInterface.State.wan_address.addr, 16) == 0)
			{
				already_exists = TRUE;
				LogMessage(L"WAN address already exists (SLAAC) - skipping creation");
				break;
			}
		}
		FreeMibTable(t);
	}

	// Si l'adresse existe déjà (SLAAC), on ne fait rien
	if (already_exists)
	{
		return TRUE;
	}

	// Sinon, créer l'adresse (cas DHCPv6 IA_NA)
	MIB_UNICASTIPADDRESS_ROW r = { 0 };
	InitializeUnicastIpAddressEntry(&r);
	r.InterfaceLuid = CurInterface.State.wan_luid;
	r.Address.si_family = AF_INET6;
	memcpy(&r.Address.Ipv6.sin6_addr, CurInterface.State.wan_address.addr, 16);
	r.OnLinkPrefixLength = 64;
	r.ValidLifetime = CurInterface.State.wan_address.valid_lifetime;
	r.PreferredLifetime = CurInterface.State.wan_address.preferred_lifetime;

	if (CreateUnicastIpAddressEntry(&r) != NO_ERROR)
	{
		LogError(L"Failed to apply WAN address (DHCPv6)");
		return FALSE;
	}

	LogMessage(L"WAN address applied (DHCPv6)");
	return TRUE;
}


/**
* @brief Applique les préfixes délégués sur les interfaces LAN.
*
* Pour chaque préfixe valide :
*   - répartit en sous-réseaux /64 (sauf cas single /64)
*   - configure une adresse ::1/64 sur chaque LAN
*   - crée les routes on-link correspondantes
*
* Rejette les préfixes :
*   - hors plage [48, 64]
*   - multicast, réservés
*
* @retval TRUE  Si au moins un préfixe a été appliqué.
* @retval FALSE Si aucun préfixe ou aucune interface LAN valide.
*/
static BOOL ApplyLANPrefixes()
{
	WCHAR log[256] = { 0 };
	if (CurInterface.State.prefix_count == 0 || CurInterface.Config.lan_count == 0)
	{
		LogMessage(L"No prefixes or LAN interfaces to configure");
		return FALSE;
	}

	for (int pi = 0; pi < CurInterface.State.prefix_count && pi < MAX_PREFIXES; pi++)
	{
		IAPrefix* pd = &CurInterface.State.prefixes[pi];

		// Validation renforcée des préfixes
		if (pd->prefix_len < 48 || pd->prefix_len > 64)
		{
			_snwprintf_s(log, _countof(log), _TRUNCATE,
				L"Skipping prefix /%u (invalid length for LAN)", pd->prefix_len);
			LogMessage(log);
			continue;
		}

		// Rejeter les préfixes non valides
		BYTE first_byte = pd->prefix[0];
		if (first_byte == 0xFF)
		{  // Multicast
			LogMessage(L"Skipping multicast prefix");
			continue;
		}
		if ((first_byte & 0xFE) == 0xFC)
		{  // Unique Local (FC00::/7)
			// Accepté - c'est bien pour LAN
		}
		else if ((first_byte & 0xC0) == 0x80)
		{  // Reserved (8000::/1)
			LogMessage(L"Skipping reserved prefix");
			continue;
		}

		// Cas spécial /64 unique
		if (pd->prefix_len == 64 && CurInterface.Config.allow_single_64)
		{
			NET_LUID ll;
			if (!GetCurInterfaceInfo(CurInterface.Config.lan_interfaces[0], &ll, NULL)) continue;

			BYTE la[16];
			memcpy(la, pd->prefix, 16);
			la[15] = 1;  // ::1 dans le sous-réseau

			MIB_UNICASTIPADDRESS_ROW r = { 0 };
			InitializeUnicastIpAddressEntry(&r);
			r.InterfaceLuid = ll;
			r.Address.si_family = AF_INET6;
			memcpy(&r.Address.Ipv6.sin6_addr, la, 16);
			r.OnLinkPrefixLength = 64;
			r.ValidLifetime = pd->valid_lifetime;
			r.PreferredLifetime = pd->preferred_lifetime;

			if (CreateUnicastIpAddressEntry(&r) == NO_ERROR)
			{
				WCHAR ipstr[INET6_ADDRSTRLEN];
				InetNtop(AF_INET6, la, ipstr, _countof(ipstr));
				_snwprintf_s(log, _countof(log), _TRUNCATE,
					L"Single /64 applied: %s/64 on %s",
					ipstr, CurInterface.Config.lan_interfaces[0]);
				LogMessage(log);
			}
			else
			{
				LogError(L"Failed to apply single /64 to LAN");
			}
			continue;
		}

		// Pour les préfixes plus grands (/48, /56, etc.), déléguer aux LANs
		// Calculer combien de sous-réseaux /64 disponibles
		int subnet_bits = 64 - pd->prefix_len;
		int max_subnets = 1 << subnet_bits;
		int num_subnets = min(max_subnets, CurInterface.Config.lan_count);

		if (num_subnets <= 0)
		{
			LogMessage(L"No subnets to allocate for this prefix");
			continue;
		}


		_snwprintf_s(log, _countof(log), _TRUNCATE,
			L"Delegating /%u: %d subnets available, assigning %d to LANs",
			pd->prefix_len, max_subnets, num_subnets);
		LogMessage(log);

		// Assigner un sous-réseau /64 à chaque interface LAN
		for (int sub = 0; sub < num_subnets; sub++)
		{
			if (sub >= CurInterface.Config.lan_count) break;

			NET_LUID ll;
			if (!GetCurInterfaceInfo(CurInterface.Config.lan_interfaces[sub], &ll, NULL))
			{
				_snwprintf_s(log, _countof(log), _TRUNCATE,
					L"LAN interface %d (%s) not found, skipping",
					sub, CurInterface.Config.lan_interfaces[sub]);
				LogMessage(log);
				continue;
			}

			// Calculer le préfixe /64 pour ce sous-réseau
			BYTE subnet_prefix[16];
			if (!IPv6_CalculateSubnet(pd->prefix, pd->prefix_len, 64, (DWORD)sub, subnet_prefix))
			{
				_snwprintf_s(log, _countof(log), _TRUNCATE,
					L"Failed to calculate subnet %d for prefix /%u",
					sub, pd->prefix_len);
				LogError(log);
				continue;
			}

			// Adresse d'interface: ::1 dans le /64
			BYTE la[16];
			memcpy(la, subnet_prefix, 16);
			la[15] = 1;

			// Log pour debug
			WCHAR ipstr[INET6_ADDRSTRLEN];
			InetNtop(AF_INET6, la, ipstr, _countof(ipstr));
			_snwprintf_s(log, _countof(log), _TRUNCATE,
				L"Assigning %s/64 to LAN %d (%s) [subnet %d/%d]",
				ipstr, sub, CurInterface.Config.lan_interfaces[sub], sub, num_subnets);
			LogMessage(log);

			MIB_UNICASTIPADDRESS_ROW r = { 0 };
			InitializeUnicastIpAddressEntry(&r);
			r.InterfaceLuid = ll;
			r.Address.si_family = AF_INET6;
			memcpy(&r.Address.Ipv6.sin6_addr, la, 16);
			r.OnLinkPrefixLength = 64;
			r.ValidLifetime = pd->valid_lifetime;
			r.PreferredLifetime = pd->preferred_lifetime;
			r.SkipAsSource = TRUE;

			MIB_IPFORWARD_ROW2 rt;
			InitializeIpForwardEntry(&rt);

			memcpy(&rt.DestinationPrefix.Prefix.Ipv6.sin6_addr, subnet_prefix, 16);
			rt.DestinationPrefix.Prefix.si_family = AF_INET6;
			rt.DestinationPrefix.PrefixLength = 64;
			rt.InterfaceLuid = ll;
			rt.NextHop.si_family = AF_INET6;
			rt.SitePrefixLength = 64;
			rt.Protocol = MIB_IPPROTO_NETMGMT;
			rt.Origin = NlroManual;
			rt.ValidLifetime = pd->valid_lifetime;
			rt.PreferredLifetime = pd->preferred_lifetime;
			rt.Publish = TRUE;
			rt.Immortal = FALSE;
			rt.Metric = 0;

			DeleteIpForwardEntry2(&rt);
			CreateIpForwardEntry2(&rt);

			if (CreateUnicastIpAddressEntry(&r) != NO_ERROR)
			{
				_snwprintf_s(log, _countof(log), _TRUNCATE,
					L"Failed to apply prefix to LAN interface %d", sub);
				LogError(log);
			}
		}
	}

	NotifyPrefixChangeCallback();
	return TRUE;
}

/**
* @brief Ajoute une route par défaut IPv6 (::/0) via la passerelle WAN.
*
* Si aucune passerelle n’est encore connue, tente de la découvrir via GetWANGateway().
*
* @retval TRUE  Si la route par défaut a été créée.
* @retval FALSE En cas d’échec ou de passerelle introuvable.
*/
static BOOL AddDefaultRoute()
{
	if (!CurInterface.State.has_gateway)
	{
		if (GetWANGateway(CurInterface.State.gateway_ll))
		{
			CurInterface.State.has_gateway = TRUE;
		}
		else return FALSE;
	}
	CleanupOldRoutes();
	MIB_IPFORWARD_ROW2 r = { 0 };
	InitializeIpForwardEntry(&r);
	r.InterfaceLuid = CurInterface.State.wan_luid;
	r.DestinationPrefix.Prefix.si_family = AF_INET6;
	r.DestinationPrefix.PrefixLength = 0;
	r.NextHop.si_family = AF_INET6;
	memcpy(&r.NextHop.Ipv6.sin6_addr, CurInterface.State.gateway_ll, 16);
	r.NextHop.Ipv6.sin6_scope_id = CurInterface.State.wan_ifindex;
	r.Metric = 1;
	r.Protocol = MIB_IPPROTO_NETMGMT;
	r.ValidLifetime = 0xffffffff;
	r.PreferredLifetime = 0xffffffff;

	return (CreateIpForwardEntry2(&r) == NO_ERROR);
}

/**
* @brief Nettoie la configuration réseau appliquée par le démon.
*
* Actions :
*   - supprime l’adresse WAN DHCPv6 (mais pas SLAAC)
*   - supprime les adresses LAN ::1/64 configurées
*   - supprime les routes associées (par défaut + on-link PD)
*   - réinitialise l’état interne (has_wan_address, prefix_count, etc.)
*/
static void CleanupConfiguration()
{
	LogMessage(L"Cleaning up network configuration");
	WCHAR log[256] = { 0 };

	// 1. Vérifier si l'adresse WAN est SLAAC avant de la supprimer
	if (CurInterface.State.has_wan_address)
	{
		MIB_UNICASTIPADDRESS_ROW r = { 0 };
		InitializeUnicastIpAddressEntry(&r);
		r.InterfaceLuid = CurInterface.State.wan_luid;
		r.Address.si_family = AF_INET6;
		memcpy(&r.Address.Ipv6.sin6_addr, CurInterface.State.wan_address.addr, 16);

		// Vérifier l'origine de l'adresse
		if (GetUnicastIpAddressEntry(&r) == NO_ERROR)
		{
			// Si l'adresse est SLAAC (DadState = IpDadStatePreferred/Deprecated),
			// on ne la supprime PAS - c'est le kernel qui gère
			if (r.SuffixOrigin == IpSuffixOriginRandom ||
				r.SuffixOrigin == IpSuffixOriginLinkLayerAddress)
			{
				LogMessage(L"WAN address is SLAAC - not removing (kernel managed)");
			}
			else
			{
				// Adresse DHCPv6 - on peut la supprimer
				if (DeleteUnicastIpAddressEntry(&r) == NO_ERROR)
				{
					LogMessage(L"WAN address removed (DHCPv6)");
				}
				else
				{
					LogError(L"Failed to remove WAN address");
				}
			}
		}
	}

	// 2. Supprimer les préfixes délégués sur les LANs
	for (int pi = 0; pi < CurInterface.State.prefix_count && pi < MAX_PREFIXES; pi++)
	{
		IAPrefix* pd = &CurInterface.State.prefixes[pi];

		if (pd->prefix_len < 48 || pd->prefix_len > 64) continue;

		// Cas /64 unique
		if (pd->prefix_len == 64 && CurInterface.Config.allow_single_64)
		{
			NET_LUID ll;
			if (!GetCurInterfaceInfo(CurInterface.Config.lan_interfaces[0], &ll, NULL)) continue;

			BYTE la[16];
			memcpy(la, pd->prefix, 16);
			la[15] = 1;

			MIB_UNICASTIPADDRESS_ROW r = { 0 };
			InitializeUnicastIpAddressEntry(&r);
			r.InterfaceLuid = ll;
			r.Address.si_family = AF_INET6;
			memcpy(&r.Address.Ipv6.sin6_addr, la, 16);
			DeleteUnicastIpAddressEntry(&r);

			LogMessage(L"Single /64 LAN address removed");
			continue;
		}

		// Calculer combien de sous-réseaux /64 disponibles
		int subnet_bits = 64 - pd->prefix_len;
		int max_subnets = 1 << subnet_bits;
		int num_subnets = min(max_subnets, CurInterface.Config.lan_count);

		for (int sub = 0; sub < num_subnets; sub++)
		{
			if (sub >= CurInterface.Config.lan_count) break;

			NET_LUID ll;
			if (!GetCurInterfaceInfo(CurInterface.Config.lan_interfaces[sub], &ll, NULL)) continue;

			// Calculer le préfixe /64 pour ce sous-réseau
			BYTE subnet_prefix[16];
			if (!IPv6_CalculateSubnet(pd->prefix, pd->prefix_len, 64, (DWORD)sub, subnet_prefix))
			{
				continue;  // Calcul échoué
			}

			// Adresse d'interface: ::1 dans le /64
			BYTE la[16];
			memcpy(la, subnet_prefix, 16);
			la[15] = 1;

			MIB_UNICASTIPADDRESS_ROW r = { 0 };
			InitializeUnicastIpAddressEntry(&r);
			r.InterfaceLuid = ll;
			r.Address.si_family = AF_INET6;
			memcpy(&r.Address.Ipv6.sin6_addr, la, 16);

			if (DeleteUnicastIpAddressEntry(&r) == NO_ERROR)
			{
				WCHAR ipstr[INET6_ADDRSTRLEN];
				InetNtop(AF_INET6, la, ipstr, _countof(ipstr));
				_snwprintf_s(log, _countof(log), _TRUNCATE,
					L"LAN address removed: %s/64 from %s",
					ipstr, CurInterface.Config.lan_interfaces[sub]);
				LogMessage(log);
			}
		}
	}

	// 3. Supprimer TOUTES les routes liées au service
	MIB_IPFORWARD_TABLE2* t = NULL;
	if (GetIpForwardTable2(AF_INET6, &t) == NO_ERROR)
	{
		int route_count = 0;

		for (ULONG i = 0; i < t->NumEntries; i++)
		{
			BOOL should_delete = FALSE;

			// Route par défaut sur WAN
			if (t->Table[i].InterfaceLuid.Value == CurInterface.State.wan_luid.Value &&
				t->Table[i].DestinationPrefix.PrefixLength == 0)
			{
				should_delete = TRUE;
			}

			// Routes on-link pour les préfixes délégués
			for (int pi = 0; pi < CurInterface.State.prefix_count && pi < MAX_PREFIXES; pi++)
			{
				IAPrefix* pd = &CurInterface.State.prefixes[pi];

				// Vérifier si c'est une route pour ce préfixe
				if (t->Table[i].DestinationPrefix.PrefixLength == 64)
				{
					// Comparer le préfixe (premiers 8 octets pour /64)
					BOOL prefix_match = TRUE;
					for (int b = 0; b < 8; b++)
					{
						if (t->Table[i].DestinationPrefix.Prefix.Ipv6.sin6_addr.s6_addr[b] !=
							pd->prefix[b])
						{
							prefix_match = FALSE;
							break;
						}
					}

					if (prefix_match)
					{
						// Vérifier que c'est sur une de nos LANs
						for (int li = 0; li < CurInterface.Config.lan_count; li++)
						{
							NET_LUID ll;
							if (GetCurInterfaceInfo(CurInterface.Config.lan_interfaces[li], &ll, NULL))
							{
								if (t->Table[i].InterfaceLuid.Value == ll.Value)
								{
									should_delete = TRUE;
									break;
								}
							}
						}
					}
				}
			}

			if (should_delete)
			{
				MIB_IPFORWARD_ROW2 r = t->Table[i];
				if (DeleteIpForwardEntry2(&r) == NO_ERROR)
				{
					route_count++;

					WCHAR ipstr[INET6_ADDRSTRLEN];
					InetNtop(AF_INET6, &r.DestinationPrefix.Prefix.Ipv6.sin6_addr,
						ipstr, _countof(ipstr));
					_snwprintf_s(log, _countof(log), _TRUNCATE,
						L"Route removed: %s/%u",
						ipstr, r.DestinationPrefix.PrefixLength);
					LogMessage(log);
				}
			}
		}

		FreeMibTable(t);

		_snwprintf_s(log, _countof(log), _TRUNCATE,
			L"Total routes removed: %d", route_count);
		LogMessage(log);
	}

	// 4. Réinitialiser l'état pour éviter les tentatives futures
	CurInterface.State.has_wan_address = FALSE;
	CurInterface.State.prefix_count = 0;
	CurInterface.State.has_gateway = FALSE;
	CurInterface.State.lease_start = 0;
	CurInterface.State.use_unicast = FALSE;

	LogMessage(L"Cleanup complete");
}
// ============================================================================
// DHCPv6 PROTOCOL avec IPV6_PKTINFO
// ============================================================================

/**
* @brief Envoie un message DHCPv6 (SOLICIT, REQUEST, RENEW, REBIND, RELEASE).
*
* Utilise IPV6_PKTINFO pour forcer l’interface source WAN.
*
* @param[in] s      Socket UDP IPv6 déjà ouvert/bindé.
* @param[in] dest   Adresse destination (multicast ou unicast).
* @param[in] type   Type de message DHCPv6 à envoyer.
*
* @retval TRUE  Si l’envoi a réussi.
* @retval FALSE Sinon.
*/
static BOOL SendDHCPv6(SOCKET s, struct sockaddr_in6* dest, BYTE type)
{
	BYTE buf[1024];
	int len = CreateDHCPv6Message(buf, sizeof(buf), type);

	// Utiliser IPV6_PKTINFO pour forcer l'interface source
	IN6_PKTINFO pktinfo = { 0 };
	pktinfo.ipi6_ifindex = CurInterface.State.wan_ifindex;
	if (setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, (char*)&pktinfo, sizeof(pktinfo)) != 0)
	{
		LogError(L"Failed to set IPV6_PKTINFO");
	}

	const WCHAR* names[] = { L"", L"SOLICIT", L"ADVERTISE", L"REQUEST", L"", L"RENEW", L"REBIND", L"REPLY", L"RELEASE" };
	WCHAR log[128];
	swprintf_s(log, _countof(log), L"Sending %s", type <= 8 ? names[type] : L"UNKNOWN");
	LogMessage(log);

	return (sendto(s, (char*)buf, len, 0, (struct sockaddr*)dest, sizeof(*dest)) > 0);
}

/**
* @brief Reçoit et filtre un message DHCPv6 en provenance du serveur.
*
* Gère :
*   - timeout via SO_RCVTIMEO
*   - validation de l’interface via IPV6_PKTINFO (WSARecvMsg)
*   - fallback avec validation par scope_id si WSARecvMsg non disponible
*   - enregistrement de l’adresse du serveur (unicast futur)
*
* @param[in] s       Socket UDP IPv6.
* @param[in] expect  Type de message attendu (ADVERTISE, REPLY, etc.).
* @param[in] toms    Timeout en millisecondes.
*
* @retval TRUE  Si un message valide attendu est reçu et parsé.
* @retval FALSE Sinon (timeout, mauvaise interface, message invalide).
*/
static BOOL RecvDHCPv6(SOCKET s, BYTE expect, int toms)
{
	struct timeval tv = { toms / 1000, (toms % 1000) * 1000 };
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

	BYTE buf[2048];
	struct sockaddr_in6 from;
	int flen = sizeof(from);

	BYTE ctrlbuf[256];
	WSABUF wbuf = { sizeof(buf), (char*)buf };
	WSAMSG msg = { 0 };
	msg.name = (struct sockaddr*)&from;
	msg.namelen = flen;
	msg.lpBuffers = &wbuf;
	msg.dwBufferCount = 1;
	msg.Control.buf = (char*)ctrlbuf;
	msg.Control.len = sizeof(ctrlbuf);

	DWORD received = 0;
	LPFN_WSARECVMSG WSARecvMsg = NULL;
	GUID guid = WSAID_WSARECVMSG;
	DWORD bytes;
	WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid),
		&WSARecvMsg, sizeof(WSARecvMsg), &bytes, NULL, NULL);

	int rlen;
	BOOL valid_interface = TRUE;

	if (WSARecvMsg)
	{
		//Utilisation de WSARecvMsg avec validation complète
		if (WSARecvMsg(s, &msg, &received, NULL, NULL) == 0)
		{
			rlen = received;

			if (msg.Control.len)
			{
				// Vérifier l'interface via IPV6_PKTINFO
				for (WSACMSGHDR* cmsg = WSA_CMSG_FIRSTHDR(&msg); cmsg; cmsg = WSA_CMSG_NXTHDR(&msg, cmsg))
				{
					if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO)
					{
						IN6_PKTINFO* pktinfo = (IN6_PKTINFO*)WSA_CMSG_DATA(cmsg);
						if (pktinfo->ipi6_ifindex != CurInterface.State.wan_ifindex)
						{
							WCHAR log[128];
							swprintf_s(log, _countof(log),
								L"Packet from wrong interface: %u (expected %u)",
								pktinfo->ipi6_ifindex, CurInterface.State.wan_ifindex);
							LogMessage(log);
							valid_interface = FALSE;
						}
						break;
					}
				}
			}

			// Vérifier aussi le scope_id pour link-local
			if (from.sin6_scope_id != 0 && from.sin6_scope_id != CurInterface.State.wan_ifindex)
			{
				WCHAR log[128];
				swprintf_s(log, _countof(log),
					L"Packet from wrong scope: %u (expected %u)",
					from.sin6_scope_id, CurInterface.State.wan_ifindex);
				LogMessage(log);
				valid_interface = FALSE;
			}

			if (!valid_interface)
			{
				LogMessage(L"Packet rejected: wrong interface");
				return FALSE;
			}
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		// FIX: Fallback avec validation manuelle de l'interface
		LogMessage(L"WSARecvMsg not available, using fallback with validation");

		rlen = recvfrom(s, (char*)buf, sizeof(buf), 0, (struct sockaddr*)&from, &flen);

		if (rlen <= 0)
		{
			return FALSE;
		}

		// FIX: Validation stricte même en fallback
		// 1. Vérifier le scope_id pour link-local
		if (from.sin6_scope_id != 0)
		{
			if (from.sin6_scope_id != CurInterface.State.wan_ifindex)
			{
				WCHAR log[128];
				swprintf_s(log, _countof(log),
					L"Fallback: Packet from wrong scope: %u (expected %u)",
					from.sin6_scope_id, CurInterface.State.wan_ifindex);
				LogMessage(log);
				return FALSE;
			}
			valid_interface = TRUE;
		}

		// 2. Pour les adresses global/unicast, vérifier via l'adresse source
		// Si le serveur répond depuis une global, on accepte (pas de scope_id)
		// Mais on vérifie qu'on a bien envoyé depuis notre WAN
		if (!valid_interface)
		{
			// Accepter si aucune info de scope (serveur distant avec global)
			// Dans ce cas, on fait confiance au fait qu'on a bindé sur WAN
			WCHAR log[128];
			swprintf_s(log, _countof(log),
				L"Fallback: Accepting packet without scope verification");
			LogMessage(log);
			valid_interface = TRUE;
		}
	}

	if (rlen > 0 && valid_interface)
	{
		// Enregistrer l'adresse du serveur pour unicast futur
		if (expect == DHCPV6_ADVERTISE || expect == DHCPV6_REPLY)
		{
			memcpy(&CurInterface.State.server_addr, &from, sizeof(from));
			CurInterface.State.use_unicast = TRUE;

			WCHAR ipstr[INET6_ADDRSTRLEN];
			InetNtop(AF_INET6, &from.sin6_addr, ipstr, _countof(ipstr));
			WCHAR log[256];
			swprintf_s(log, _countof(log), L"Server address saved: %s (scope %u)",
				ipstr, from.sin6_scope_id);
			LogMessage(log);
		}

		return ParseResponse(buf, rlen, expect);
	}

	return FALSE;
}

/**
* @brief Envoie un message DHCPv6 RELEASE si un bail est actif.
*
* Libère :
*   - adresse WAN DHCPv6
*   - préfixes PD
*
* Puis met à jour l’état interne et le stocke dans le registre.
*
* @retval TRUE  Si le RELEASE est envoyé (ou s’il n’y a rien à libérer).
* @retval FALSE En cas d’erreur critique de socket.
*/
static BOOL SendRELEASE()
{
	if (!CurInterface.State.has_wan_address && CurInterface.State.prefix_count == 0) return FALSE;

	LogMessage(L"Sending RELEASE");

	SOCKET s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET)
	{
		WSACleanup();
		return FALSE;
	}

	struct sockaddr_in6 local = { 0 };
	local.sin6_family = AF_INET6;
	local.sin6_port = htons(DHCPV6_CLIENT_PORT);
	bind(s, (struct sockaddr*)&local, sizeof(local));

	setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char*)&CurInterface.State.wan_ifindex, sizeof(CurInterface.State.wan_ifindex));

	struct sockaddr_in6 dest;
	if (CurInterface.State.use_unicast)
	{
		dest = CurInterface.State.server_addr;
	}
	else
	{
		memset(&dest, 0, sizeof(dest));
		dest.sin6_family = AF_INET6;
		dest.sin6_port = htons(DHCPV6_SERVER_PORT);
		inet_pton(AF_INET6, "ff02::1:2", &dest.sin6_addr);
		dest.sin6_scope_id = CurInterface.State.wan_ifindex;
	}

	SendDHCPv6(s, &dest, DHCPV6_RELEASE);
	closesocket(s);

	CurInterface.State.lease_start = 0;
	CurInterface.State.server_duid_len = 0;
	CurInterface.State.selected_server_duid_len = 0;
	memset(CurInterface.State.server_duid, 0, 128);
	memset(CurInterface.State.selected_server_duid, 0, 128);
	CurInterface.State.transaction_start = 0;
	//SaveState
	if (!SaveDHCPv6State())
	{
		LogError(L"DHCPv6 Save State failed");
	}
	return TRUE;
}

// ============================================================================
// DHCPv6 PROTOCOL avec gestion SOL_MAX_RT
// ============================================================================

/**
 * @brief Vérifie si le kernel possède déjà une adresse globale sur l’interface WAN.
 *
 * Filtre IPv6 :
 *   - ignore FE80::/10 (link-local)
 *   - ignore FEC0::/10 (site-local, déprécié)
 *   - ignore FF00::/8 (multicast)
 *
 * @retval TRUE  Si une adresse globale /64 est détectée sur le WAN.
 * @retval FALSE Sinon.
 */
static BOOL KernelHasWanAddress()
{
	MIB_UNICASTIPADDRESS_TABLE* t = NULL;
	BOOL has_address = FALSE;

	if (GetUnicastIpAddressTable(AF_INET6, &t) == NO_ERROR)
	{
		for (ULONG i = 0; i < t->NumEntries; i++)
		{
			if (t->Table[i].InterfaceLuid.Value == CurInterface.State.wan_luid.Value &&
				t->Table[i].OnLinkPrefixLength == 64)
			{
				BYTE first_byte = t->Table[i].Address.Ipv6.sin6_addr.s6_addr[0];
				// FE80/10 ou FEC0/10 (0xFE masqué) + multicast (0xFF)
				if ((first_byte & 0xFE) == 0xFE || first_byte == 0xFF)
				{
					continue;
				}
				has_address = TRUE;
				break;
			}
		}
		FreeMibTable(t);
	}

	return has_address;
}

/**
* @brief Vérifie si le kernel possède des adresses /64 ::1 sur les interfaces LAN.
*
* Utilisé lorsque prefix_count == 0 pour détecter une pollution résiduelle.
*
* Filtre :
*   - ignore link-local et multicast
*   - ignore les adresses temporaires (RFC 4941)
*   - ne considère que les suffixes ::1 statiques configurés par le démon
*
* @retval TRUE  Si au moins une adresse ::1/64 est détectée sur un LAN.
* @retval FALSE Si le démon a configurer aucune adresses.
*/
static BOOL KernelHasLanAddresses()
{
	MIB_UNICASTIPADDRESS_TABLE* t = NULL;
	BOOL has_addresses = FALSE;

	if (GetUnicastIpAddressTable(AF_INET6, &t) == NO_ERROR)
	{
		for (ULONG i = 0; i < t->NumEntries; i++)
		{
			if (t->Table[i].OnLinkPrefixLength != 64) continue;

			// Vérifier si c'est une de nos interfaces LAN
			for (int li = 0; li < CurInterface.Config.lan_count; li++)
			{
				NET_LUID ll;
				if (!GetCurInterfaceInfo(CurInterface.Config.lan_interfaces[li], &ll, NULL)) continue;

				if (t->Table[i].InterfaceLuid.Value == ll.Value)
				{
					BYTE* addr = t->Table[i].Address.Ipv6.sin6_addr.s6_addr;
					BYTE first_byte = addr[0];

					// Ignorer link-local/multicast
					if ((first_byte & 0xFE) == 0xFE || first_byte == 0xFF)
					{
						continue;
					}

					// Ignorer adresses temporaires (RFC 4941)
					// Notre daemon configure toujours ::1 comme suffixe
					// Toute autre adresse = privacy extension ou SLAAC
					BOOL is_static_suffix = TRUE;
					for (int b = 8; b < 15; b++)
					{
						if (addr[b] != 0)
						{
							is_static_suffix = FALSE;
							break;
						}
					}
					if (!is_static_suffix || addr[15] != 1)
					{
						// Adresse temporaire ou autre origin → ignore
						continue;
					}

					// Adresse ::1 valide trouvée
					has_addresses = TRUE;
					break;
				}
			}

			if (has_addresses) break;
		}
		FreeMibTable(t);
	}

	return has_addresses;
}

/**
* @brief Vérifie si l’adresse WAN a changé par rapport à l’état enregistré.
*
* Cas considérés comme “changement” :
*   - aucune adresse enregistrée mais le kernel en a une
*   - l’adresse enregistrée n’est plus présente
*   - plusieurs Global Unicast coexistent sur le WAN
*
* Filtre :
*   - exclut FE80::/10, FEC0::/10, FF00::/8
*
* @retval TRUE  Si un changement est détecté.
* @retval FALSE Si aucun changement n'est détecté.
*/
static BOOL WANAddressChanged()
{
	MIB_UNICASTIPADDRESS_TABLE* t = NULL;
	BOOL found_current = FALSE;
	BOOL found_other = FALSE;
	int wan_addr_count = 0;

	if (GetUnicastIpAddressTable(AF_INET6, &t) != NO_ERROR)
	{
		return TRUE;
	}

	for (ULONG i = 0; i < t->NumEntries; i++)
	{
		if (t->Table[i].InterfaceLuid.Value == CurInterface.State.wan_luid.Value &&
			t->Table[i].OnLinkPrefixLength == 64)
		{
			BYTE first_byte = t->Table[i].Address.Ipv6.sin6_addr.s6_addr[0];
			if ((first_byte & 0xFE) == 0xFE || first_byte == 0xFF)
			{
				continue;
			}

			wan_addr_count++;

			if (CurInterface.State.has_wan_address &&
				memcmp(&t->Table[i].Address.Ipv6.sin6_addr,
					CurInterface.State.wan_address.addr, 16) == 0)
			{
				found_current = TRUE;
			}
			else
			{
				found_other = TRUE;
			}
		}
	}

	FreeMibTable(t);

	if (!CurInterface.State.has_wan_address)
	{
		// Pas d'adresse enregistrée - essayer de récupérer SLAAC
		if (wan_addr_count > 0)
		{
			LogMessage(L"No registered address but kernel has one - checking SLAAC");
			if (GetSLAACAddress())
			{
				LogMessage(L"SLAAC address found and registered");
				return FALSE; // Pas de changement, on vient de récupérer
			}
		}
		return (wan_addr_count > 0);
	}

	if (!found_current)
	{
		WCHAR log[128];
		swprintf_s(log, _countof(log),
			L"WAN address missing from kernel (has %d addresses)", wan_addr_count);
		LogMessage(log);
		return TRUE;
	}

	if (wan_addr_count > 1)
	{
		WCHAR log[128];
		swprintf_s(log, _countof(log),
			L"Multiple Global on WAN (%d) - forcing cleanup", wan_addr_count);
		LogMessage(log);
		return TRUE;
	}

	return FALSE;
}

/**
* @brief Vérifie si les préfixes LAN appliqués correspondent à l’état attendu.
*
* - Pour chaque préfixe PD, vérifie que les adresses ::1/64 attendues
*   existent bien sur les bonnes interfaces LAN.
* - Refuse les préfixes < /48 pour éviter la combinatoire explosive.
* - Ignore les adresses temporaires RFC 4941 (ne compte que ::1 statiques).
*
* Fail-safe :
*   - en cas d’erreur ou d’incertitude, retourne TRUE (forcer reconfig).
*
* @retval TRUE  Si les préfixes ont changé ou sont incohérents.
* @retval FALSE Si tout est strictement conforme à l’état attendu.
*/
static BOOL LANPrefixesChanged()
{
	if (CurInterface.State.prefix_count == 0)
	{
		// Pas de préfixes délégués
		// Vérifier si le kernel a des adresses ::1 statiques sur les LANs
		BOOL has_lan = KernelHasLanAddresses();
		if (has_lan)
		{
			LogMessage(L"No delegated prefixes but kernel has LAN addresses - cleanup needed");
		}
		return has_lan;
	}

	MIB_UNICASTIPADDRESS_TABLE* t = NULL;

	if (GetUnicastIpAddressTable(AF_INET6, &t) != NO_ERROR)
	{
		// Fail-safe: assume changement si on ne peut pas vérifier
		LogError(L"LANPrefixesChanged: Cannot query IP table, assuming changed");
		return TRUE;
	}

	BOOL all_matched = TRUE;
	int total_expected = 0;

	// Pour chaque préfixe délégué, vérifier s'il est correctement appliqué
	for (int pi = 0; pi < CurInterface.State.prefix_count && pi < MAX_PREFIXES; pi++)
	{
		IAPrefix* pd = &CurInterface.State.prefixes[pi];

		// Validation stricte des préfixes
		if (pd->prefix_len < 48 || pd->prefix_len > 64)
		{
			continue; // Ignoré à l'apply, donc ignoré ici aussi
		}

		// Hard cap: refuse < /48 pour éviter explosion combinatoire
		// /48 → 65536 subnets potentiels, /56 → 256 subnets (acceptable)
		if (pd->prefix_len < 48)
		{
			WCHAR log[128];
			swprintf_s(log, _countof(log),
				L"Prefix /%u too large for change detection (< /48), forcing reconfig",
				pd->prefix_len);
			LogMessage(log);
			FreeMibTable(t);
			return TRUE;
		}

		// Cas spécial: /64 unique
		if (pd->prefix_len == 64)
		{
			// Cohérence avec Apply: si allow_single_64 == FALSE, ignoré
			if (!CurInterface.Config.allow_single_64)
			{
				continue;
			}

			NET_LUID ll;
			if (!GetCurInterfaceInfo(CurInterface.Config.lan_interfaces[0], &ll, NULL))
			{
				all_matched = FALSE;
				break;
			}

			BYTE la[16];
			memcpy(la, pd->prefix, 16);
			la[15] = 1;

			total_expected++;

			// Chercher cette adresse exacte
			BOOL found = FALSE;
			for (ULONG i = 0; i < t->NumEntries; i++)
			{
				if (t->Table[i].InterfaceLuid.Value == ll.Value &&
					t->Table[i].OnLinkPrefixLength == 64 &&
					memcmp(&t->Table[i].Address.Ipv6.sin6_addr, la, 16) == 0)
				{
					found = TRUE;
					break;
				}
			}

			if (!found)
			{
				WCHAR log[256];
				WCHAR ipstr[INET6_ADDRSTRLEN];
				InetNtop(AF_INET6, la, ipstr, _countof(ipstr));
				swprintf_s(log, _countof(log),
					L"Expected /64 address missing: %s", ipstr);
				LogMessage(log);
				all_matched = FALSE;
				break;
			}

			continue;
		}

		// Préfixes multiples (/56 uniquement à ce point)
		int subnet_bits = 64 - pd->prefix_len;
		int max_subnets = 1 << subnet_bits;
		int num_subnets = min(max_subnets, CurInterface.Config.lan_count);

		// Vérifier chaque sous-réseau attendu
		for (int sub = 0; sub < num_subnets; sub++)
		{
			if (sub >= CurInterface.Config.lan_count) break;

			NET_LUID ll;
			if (!GetCurInterfaceInfo(CurInterface.Config.lan_interfaces[sub], &ll, NULL))
			{
				all_matched = FALSE;
				break;
			}

			BYTE subnet_prefix[16];
			if (!IPv6_CalculateSubnet(pd->prefix, pd->prefix_len, 64, (DWORD)sub, subnet_prefix))
			{
				all_matched = FALSE;
				break;
			}

			BYTE la[16];
			memcpy(la, subnet_prefix, 16);
			la[15] = 1;

			total_expected++;

			// Chercher cette adresse exacte
			BOOL found = FALSE;
			for (ULONG i = 0; i < t->NumEntries; i++)
			{
				if (t->Table[i].InterfaceLuid.Value == ll.Value &&
					t->Table[i].OnLinkPrefixLength == 64 &&
					memcmp(&t->Table[i].Address.Ipv6.sin6_addr, la, 16) == 0)
				{
					found = TRUE;
					break;
				}
			}

			if (!found)
			{
				WCHAR log[256];
				WCHAR ipstr[INET6_ADDRSTRLEN];
				InetNtop(AF_INET6, la, ipstr, _countof(ipstr));
				swprintf_s(log, _countof(log),
					L"Expected subnet address missing: %s on LAN %d",
					ipstr, sub);
				LogMessage(log);
				all_matched = FALSE;
				break;
			}
		}

		if (!all_matched) break;
	}

	// Validation finale: vérifier qu'il n'y a pas d'adresses /64 ::1 supplémentaires
	// sur les interfaces LAN (pollution résiduelle)
	// 
	// Ignore adresses temporaires RFC 4941 (privacy extensions)
	// → seules les ::1 statiques comptent
	if (all_matched)
	{
		int kernel_count = 0;
		for (ULONG i = 0; i < t->NumEntries; i++)
		{
			if (t->Table[i].OnLinkPrefixLength != 64) continue;

			// Vérifier si c'est une de nos interfaces LAN
			for (int li = 0; li < CurInterface.Config.lan_count; li++)
			{
				NET_LUID ll;
				if (GetCurInterfaceInfo(CurInterface.Config.lan_interfaces[li], &ll, NULL))
				{
					if (t->Table[i].InterfaceLuid.Value == ll.Value)
					{
						BYTE* addr = t->Table[i].Address.Ipv6.sin6_addr.s6_addr;
						BYTE first_byte = addr[0];

						// Ignorer link-local/multicast
						if ((first_byte & 0xFE) == 0xFE || first_byte == 0xFF)
						{
							break;
						}

						// RFC 4941: ignorer adresses temporaires
						// Notre daemon configure ::1 comme suffixe
						// Toute autre adresse = privacy extension ou SLAAC
						BOOL is_static_suffix = TRUE;
						for (int b = 8; b < 15; b++)
						{
							if (addr[b] != 0)
							{
								is_static_suffix = FALSE;
								break;
							}
						}

						// Compter seulement les ::1 statiques
						if (is_static_suffix && addr[15] == 1)
						{
							kernel_count++;
						}

						break;
					}
				}
			}
		}

		if (kernel_count != total_expected)
		{
			WCHAR log[128];
			swprintf_s(log, _countof(log),
				L"Address count mismatch: expected %d, kernel has %d (ignoring RFC 4941 privacy)",
				total_expected, kernel_count);
			LogMessage(log);
			all_matched = FALSE;
		}
	}

	FreeMibTable(t);

	if (all_matched)
	{
		LogMessage(L"LAN prefixes validated: all match kernel state (RFC 4941 privacy ignored)");
	}

	return !all_matched;
}

/**
* @brief Exécute une séquence DHCPv6 complète (SOLICIT/REQUEST/RENEW/REBIND/REAPPLY).
*
* Gère :
*   - envoi des messages via SendDHCPv6()
*   - réception/parse via RecvDHCPv6() + ParseResponse()
*   - gestion de SOL_MAX_RT (RFC 8415)
*   - reconfiguration réseau conditionnelle :
*       - détection des changements WAN/LAN
*       - cleanup + ApplyWANAddress + ApplyLANPrefixes + AddDefaultRoute
*
* @param[in] type  Type d’échange DHCPv6 :
*                  DHCPV6_SOLICIT, DHCPV6_RENEW, DHCPV6_REBIND, DHCPV6_REAPPLY.
*
* @retval TRUE  Si l’état DHCPv6 est cohérent après l’appel.
* @retval FALSE Si tous les essais échouent.
*/
static BOOL AcquireDHCPv6(BYTE type)
{
	SOCKET s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET)
	{
		return FALSE;
	}

	DWORD yes = 1;
	setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, (char*)&yes, sizeof(yes));

	struct sockaddr_in6 local = { 0 };
	local.sin6_family = AF_INET6;
	local.sin6_port = htons(DHCPV6_CLIENT_PORT);
	bind(s, (struct sockaddr*)&local, sizeof(local));

	setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char*)&CurInterface.State.wan_ifindex, sizeof(CurInterface.State.wan_ifindex));

	struct sockaddr_in6 dest;
	if ((type == DHCPV6_RENEW || type == DHCPV6_REBIND || type == DHCPV6_REQUEST) && CurInterface.State.use_unicast)
	{
		dest = CurInterface.State.server_addr;
		LogMessage(L"Using unicast to server");
	}
	else
	{
		memset(&dest, 0, sizeof(dest));
		dest.sin6_family = AF_INET6;
		dest.sin6_port = htons(DHCPV6_SERVER_PORT);
		inet_pton(AF_INET6, "ff02::1:2", &dest.sin6_addr);
		dest.sin6_scope_id = CurInterface.State.wan_ifindex;
		LogMessage(L"Using multicast");
	}

	BOOL ok = FALSE;
	int toms = INITIAL_TIMEOUT_MS;
	int max_timeout_ms = CurInterface.State.sol_max_rt_ms > 0 ? CurInterface.State.sol_max_rt_ms : DEFAULT_SOL_MAX_RT_MS;

	if (type == DHCPV6_SOLICIT)
	{
		for (int retry = 0; retry < MAX_RETRIES && !ok; retry++)
		{
			if (!SendDHCPv6(s, &dest, DHCPV6_SOLICIT)) break;

			if (RecvDHCPv6(s, DHCPV6_ADVERTISE, toms))
			{
				Sleep(100);
				if (SendDHCPv6(s, &dest, DHCPV6_REQUEST))
				{
					if (RecvDHCPv6(s, DHCPV6_REPLY, toms))
					{
						CurInterface.State.lease_start = time(NULL);
						CurInterface.State.in_renewal = FALSE;
						CurInterface.State.renew_retries = 0;
						ok = TRUE;
					}
				}
			}

			if (!ok)
			{
				toms = min(toms * 2, max_timeout_ms);
				WCHAR log[128];
				swprintf_s(log, _countof(log), L"SOLICIT Retry %d/%d (timeout %dms, max=%dms)",
					retry + 1, MAX_RETRIES, toms, max_timeout_ms);
				LogMessage(log);
				Sleep(1000);
			}
		}
	}
	else if (type == DHCPV6_RENEW || type == DHCPV6_REBIND)
	{
		for (int retry = 0; retry < 3 && !ok; retry++)
		{
			if (SendDHCPv6(s, &dest, type))
			{
				if (RecvDHCPv6(s, DHCPV6_REPLY, toms))
				{
					CurInterface.State.lease_start = time(NULL);
					CurInterface.State.in_renewal = FALSE;
					CurInterface.State.renew_retries = 0;
					ok = TRUE;
				}
			}

			if (!ok)
			{
				toms = min(toms * 2, max_timeout_ms);
				WCHAR log[128];
				swprintf_s(log, _countof(log), L"%s Retry %d/3 (timeout %dms, max=%dms)",
					type == DHCPV6_RENEW ? L"RENEW" : L"REBIND", retry + 1, toms, max_timeout_ms);
				LogMessage(log);
				Sleep(1000);
			}
		}

		if (!ok && type == DHCPV6_REBIND)
		{
			LogMessage(L"REBIND failed - falling back to SOLICIT");
			CurInterface.State.lease_start = 0;
			CurInterface.State.use_unicast = FALSE;
			CurInterface.State.selected_server_duid_len = 0;
		}
	}

	//DHCPV6_REAPPLY est indépendant et host séquance DHCPv6 mais ne réalise pas de DHCPv6 exchange.
	if (ok || type == DHCPV6_REAPPLY)
	{
		if (ok)
			LogMessage(L"DHCPv6 exchange successful");

		//Retour True sur un DHCPV6_REAPPLY
		ok = TRUE;
		// FIX: Détecter les changements avant de nettoyer
		BOOL wan_changed = WANAddressChanged();
		BOOL lan_changed = LANPrefixesChanged();

		if (wan_changed || lan_changed || type == DHCPV6_SOLICIT)
		{
			LogMessage(L"WAN/LAN address changed - cleaning up and rebuild clean network");
			CleanupOldAddresses();
			CleanupOldRoutes();
			ApplyWANAddress();
			ApplyLANPrefixes();
			AddDefaultRoute();
		}
		else
		{
			LogMessage(L"WAN/LAN address unchanged - skipping cleanup");
		}
	}
	else
	{
		LogError(L"DHCPv6 exchange failed");
	}

	closesocket(s);

	//SaveState
	if (!SaveDHCPv6State())
	{
		LogError(L"DHCPv6 Save State failed");
	}

	return ok;
}

// ============================================================================
// TIMING
// ============================================================================

/**
* @brief Calcule le plus petit T1 (NA ou PD) disponible.
*
* Si T1_nx n’est pas fourni, dérive par défaut 50 % du valid_lifetime.
*
* @return Le plus petit T1 en secondes.
*/
static DWORD GetMinT1()
{
	DWORD t = 0xFFFFFFFF;
	if (CurInterface.State.has_wan_address && CurInterface.State.t1_na > 0) t = min(t, CurInterface.State.t1_na);
	if (CurInterface.State.prefix_count > 0 && CurInterface.State.t1_pd > 0) t = min(t, CurInterface.State.t1_pd);
	if (t == 0xFFFFFFFF)
	{
		if (CurInterface.State.has_wan_address) t = CurInterface.State.wan_address.valid_lifetime / 2;
		else if (CurInterface.State.prefix_count > 0) t = CurInterface.State.prefixes[0].valid_lifetime / 2;
	}
	return t;
}

/**
* @brief Calcule le plus petit T2 (NA ou PD) disponible.
*
* Si T2_nx n’est pas fourni, dérive par défaut 80 % du valid_lifetime.
*
* @return Le plus petit T2 en secondes.
*/
static DWORD GetMinT2()
{
	DWORD t = 0xFFFFFFFF;
	if (CurInterface.State.has_wan_address && CurInterface.State.t2_na > 0) t = min(t, CurInterface.State.t2_na);
	if (CurInterface.State.prefix_count > 0 && CurInterface.State.t2_pd > 0) t = min(t, CurInterface.State.t2_pd);
	if (t == 0xFFFFFFFF)
	{
		if (CurInterface.State.has_wan_address) t = (CurInterface.State.wan_address.valid_lifetime * 4) / 5;
		else if (CurInterface.State.prefix_count > 0) t = (CurInterface.State.prefixes[0].valid_lifetime * 4) / 5;
	}
	return t;
}

// ============================================================================
// STATE MACHINE
// ============================================================================

/**
 * @brief State machine principale DHCPv6/PD avec les RA.
 *
 * Rôle :
 *   - restaurer l’état DHCPv6 au démarrage (si disponible)
 *   - lancer une acquisition initiale (SOLICIT)
 *   - gérer T1/T2 (RENEW/REBIND)
 *   - gérer les changements réseau (NetworkChangedFlag)
 *   - gérer les changements de configuration (registry)
 *   - envoyer les RA :
 *       - à l’acquisition de PD
 *       - après reconfig
 *       - périodiquement selon ra_interval_sec
 *
 * @param[in] ClientV6  Contexte DHCPv6 (structure globale exposant les callbacks).
 *
 * @return 0 à l’arrêt du service.
 */
static int DHCPV6StateMachine(pDHCPV6 ClientV6)
{
	HANDLE regEvent = SetupRegistryNotification();
	DWORD LanStatus = 0;

	ClientV6->State.sol_max_rt_ms = DEFAULT_SOL_MAX_RT_MS;
	ClientV6->State.last_ra_time = 0;

	// Charger état ou acquérir nouveau bail
	if (ClientV6->LoadDHCPState())
	{
		if (!GetCurInterfaceInfo(ClientV6->Config.wan_interface, &ClientV6->State.wan_luid, &ClientV6->State.wan_ifindex))
		{
			LogError(L"FATAL: WAN interface not found");
			return 0;
		}
		LogMessage(L"Restore DHCPv6 State");
		if (ClientV6->State.lease_start != 0)
			ClientV6->AcquireDHCP(DHCPV6_REAPPLY);
		else
			ClientV6->AcquireDHCP(DHCPV6_SOLICIT);
	}
	else
	{
		if (!GetCurInterfaceInfo(ClientV6->Config.wan_interface, &ClientV6->State.wan_luid, &ClientV6->State.wan_ifindex))
		{
			LogError(L"FATAL: WAN interface not found");
			return 0;
		}
		LogMessage(L"Initial DHCPv6 acquisition");
		ClientV6->AcquireDHCP(DHCPV6_SOLICIT);
	}

	SetupNetworkChangeNotification();

	// Envoyer RAs immédiatement si on a des préfixes
	if (ClientV6->State.prefix_count > 0 && ClientV6->Config.enable_ra)
	{
		ClientV6->SendAllRAs();
	}

	HANDLE ev[2] = { g_ServiceStopEvent, regEvent };
	int evc = (regEvent != INVALID_HANDLE_VALUE) ? 2 : 1;

	while (TRUE)
	{
		DWORD wait = 10000;  // 10 secondes

		if (!ClientV6->CheckWANStatus())
		{
			wait = 5000;
		}
		else if (ClientV6->State.lease_start > 0)
		{
			time_t el = time(NULL) - ClientV6->State.lease_start;
			DWORD t1 = ClientV6->GetT1(), t2 = ClientV6->GetT2();

			if (el >= t2 && !ClientV6->State.in_renewal)
			{
				LogMessage(L"T2 reached - sending REBIND");
				if (!ClientV6->AcquireDHCP(DHCPV6_REBIND))
				{
					LogError(L"REBIND failed");
					ClientV6->State.lease_start = 0;
					ClientV6->State.use_unicast = FALSE;
					ClientV6->State.selected_server_duid_len = 0;
				}
				else if (ClientV6->Config.enable_ra)
				{
					// Nouveau préfixe → envoyer RAs immédiatement
					ClientV6->SendAllRAs();
				}
			}
			else if (el >= t1 && !ClientV6->State.in_renewal)
			{
				LogMessage(L"T1 reached - sending RENEW");
				ClientV6->State.in_renewal = TRUE;
				ClientV6->State.renew_retries = 0;
				if (ClientV6->AcquireDHCP(DHCPV6_RENEW))
				{
					ClientV6->State.in_renewal = FALSE;
				}
				else
				{
					ClientV6->State.renew_retries++;
					if (ClientV6->State.renew_retries >= 3)
					{
						ClientV6->State.in_renewal = FALSE;
					}
				}
			}
		}
		else
		{
			LogMessage(L"No active lease - sending SOLICIT");
			ClientV6->AcquireDHCP(DHCPV6_SOLICIT);
			wait = 30000;

			// Nouveau bail → envoyer RAs
			if (ClientV6->State.prefix_count > 0 && ClientV6->Config.enable_ra)
			{
				ClientV6->SendAllRAs();
			}
		}

		// Changement réseau → reconfig + RAs
		LanStatus = InterlockedExchange(&NetworkChangedFlag, 0);
		if (LanStatus == 1)
		{
			ClientV6->AcquireDHCP(DHCPV6_REAPPLY);
			//Notifier le serveur cascade si présent
			if (ClientV6->_prefix_change_callback)
			{
				ClientV6->NotifyServerOfPrefixChange();
				LogMessage(L"Server cascade notified of prefix change");
			}

			if (ClientV6->State.prefix_count > 0 && ClientV6->Config.enable_ra)
			{
				ClientV6->SendAllRAs();
			}
		}
		else if (LanStatus == 2)
		{
			LogMessage(L"WAN prefix change detected — full reset + SOLICIT");

			// Reset complet de la config locale
			ClientV6->CleanupConfiguration();

			ClientV6->State.prefix_count = 0;
			ClientV6->State.has_wan_address = FALSE;
			ClientV6->State.has_gateway = FALSE;
			ClientV6->State.use_unicast = FALSE;
			ClientV6->State.lease_start = 0;

			// Nouveau SOLICIT pour récupérer NA + PD cohérents
			ClientV6->AcquireDHCP(DHCPV6_SOLICIT);

			// Si on a récupéré un PD, on balance les RA
			if (ClientV6->State.prefix_count > 0 && ClientV6->Config.enable_ra)
			{
				ClientV6->SendAllRAs();
			}

			continue;
		}

		// Envoyer RAs périodiquement
		if (ClientV6->Config.enable_ra && ClientV6->State.prefix_count > 0)
		{
			time_t now = time(NULL);
			if (ClientV6->State.last_ra_time == 0 ||
				(now - ClientV6->State.last_ra_time) >= (time_t)ClientV6->Config.ra_interval_sec)
			{
				ClientV6->SendAllRAs();
			}
		}

		DWORD r = WaitForMultipleObjects(evc, ev, FALSE, wait);

		if (r == WAIT_OBJECT_0)
		{
			break;  // Stop service
		}
		else if (r == WAIT_OBJECT_0 + 1)
		{
			LogMessage(L"Registry changed - reloading");

			DHCPv6Config oldConfig = ClientV6->Config;

			LoadConfigFromRegistry();
			CloseHandle(ev[1]);
			regEvent = SetupRegistryNotification();
			ev[1] = regEvent;

			// 1. WANInterface : accepter le changement (rename ou bascule)
			NET_LUID nl;
			NET_IFINDEX ni;

			if (GetCurInterfaceInfo(ClientV6->Config.wan_interface, &nl, &ni))
			{
				ClientV6->State.wan_luid = nl;
				ClientV6->State.wan_ifindex = ni;
				LogMessage(L"WAN interface updated from registry");
			}
			else
			{
				LogError(L"WAN interface from registry not found");
			}

			// 2. LANInterfaces : valider et logguer (ajouts/renoms acceptés)
			for (int i = 0; i < ClientV6->Config.lan_count; i++)
			{
				NET_LUID ll;
				NET_IFINDEX li;

				if (GetCurInterfaceInfo(ClientV6->Config.lan_interfaces[i], &ll, &li))
				{
					WCHAR buf[256];
					swprintf(buf, 256, L"LAN interface %d updated: %s",
						i, ClientV6->Config.lan_interfaces[i]);
					LogMessage(buf);
				}
				else
				{
					WCHAR buf[256];
					swprintf(buf, 256, L"LAN interface %d not found: %s",
						i, ClientV6->Config.lan_interfaces[i]);
					LogError(buf);
				}
			}

			// 3. ForceStableDUID : ne PAS changer le DUID à chaud
			if (oldConfig.force_stable_duid != ClientV6->Config.force_stable_duid)
			{
				LogError(L"ForceStableDUID changed in registry; new DUID policy will only apply after service restart");
				// On NE TOUCHE PAS à CurInterface.State.duid ici.
				// On NE regénère PAS de DUID.
			}

			// 4. Réappliquer configuration réseau à partir de l’état DHCP actuel
			ClientV6->CleanupConfiguration();
			ClientV6->AcquireDHCP(DHCPV6_REAPPLY);

			// 5. Notifier le serveur cascade si présent
			if (ClientV6->_prefix_change_callback)
			{
				ClientV6->NotifyServerOfPrefixChange();
				LogMessage(L"Server cascade notified of prefix change");
			}

			// 6. Envoyer RA si on a un préfixe et un WAN valide
			if (ClientV6->State.wan_ifindex &&
				ClientV6->State.prefix_count > 0 &&
				ClientV6->Config.enable_ra)
			{
				ClientV6->SendAllRAs();
			}
		}
	}

	// Cleanup
	if (!ClientV6->Config.disable_release)
	{
		LogMessage(L"Service stopping - sending RELEASE");
		ClientV6->SendRELEASE();
		ClientV6->CleanupConfiguration();
	}
	else
	{
		LogMessage(L"Service stopping - RELEASE disabled");
	}

	CleanupNetworkChangeNotification();
	if (RegistryKey) RegCloseKey(RegistryKey);
	if (regEvent != INVALID_HANDLE_VALUE) CloseHandle(regEvent);

	return 0;
}

/**
 * @brief Initialise la structure DHCPV6 globale.
 *
 * Configure :
 *   - fonctions DHCPv6 (state machine, AcquireDHCP, timers, RELEASE, etc.)
 *   - fonctions RA (SendAllRAs)
 *   - callbacks serveur cascade (prefix change)
 *
 * Charge la configuration initiale depuis le registre.
 *
 * @return Pointeur sur la structure DHCPV6 initialisée.
 */
pDHCPV6 InitDHCPV6()
{
	memset(&CurInterface, 0, sizeof(DHCPV6));
	LoadConfigFromRegistry();

	// Fonctions DHCPv6
	CurInterface.DHCPStateMachine = DHCPV6StateMachine;
	CurInterface.AcquireDHCP = AcquireDHCPv6;
	CurInterface.CheckWANStatus = CheckWANStatus;
	CurInterface.CleanupConfiguration = CleanupConfiguration;
	CurInterface.GetT1 = GetMinT1;
	CurInterface.GetT2 = GetMinT2;
	CurInterface.SendRELEASE = SendRELEASE;
	CurInterface.LoadDHCPState = LoadDHCPv6State;

	// Fonctions Router Advertisement
	CurInterface.SendAllRAs = SendAllRAs;

	// Fonctions callback
	CurInterface.RegisterPrefixChangeCallback = RegisterPrefixChangeCallback;
	CurInterface.NotifyServerOfPrefixChange = NotifyPrefixChangeCallback;

	// Initialiser callbacks à NULL
	CurInterface._prefix_change_callback = NULL;
	CurInterface._callback_user_data = NULL;

	return &CurInterface;
}

