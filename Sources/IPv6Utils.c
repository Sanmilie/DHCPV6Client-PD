/* ============================================================================
 * @file IPv6Utils.c
 * @brief Utilitaires IPv6 déterministes pour calculs de sous-réseaux, validation, parsing et logging.
 *
 * Ce module fournit un ensemble de primitives IPv6 bit-exactes, utilisées comme base
 * pour un routeur / client PD souverain :
 *   - dérivation de sous-réseaux IPv6 (MSB-first)
 *   - validation d’alignement et chevauchement de préfixes
 *   - construction de pools de sous-réseaux disponibles
 *   - gestion des lifetimes (T1/T2) selon la RFC 8415
 *   - formatage, parsing et logging d’adresses et de préfixes IPv6
 *
 * Toutes les fonctions sont conçues pour être :
 *   - déterministes
 *   - strictement alignées sur les longueurs de préfixe
 *   - explicitement validées (aucune supposition implicite)
 *
 * @author Yannick LaRue
 * @copyright San@sro Inc. / SSE Carte à Puce Inc.
 * ============================================================================ */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include "../Headers/IPv6Utils.h"

// ============================================================================
// CALCUL DE SOUS-RÉSEAUX — dérivation bit-exacte d’un sous-réseau IPv6
// ============================================================================

/**
 * @brief Calcule un sous-réseau IPv6 à partir d’un préfixe délégué.
 *
 * L’algorithme fonctionne en MSB-first :
 *   1. Copie le préfixe parent @p delegated_prefix dans @p out_prefix.
 *   2. Écrit @p subnet_id dans les bits [delegated_len .. subnet_len).
 *   3. Force tous les bits après @p subnet_len à 0 (alignement strict).
 *
 * Des validations sont appliquées :
 *   - @p delegated_prefix et @p out_prefix doivent être non NULL.
 *   - @p delegated_len < @p subnet_len.
 *   - @p delegated_len et @p subnet_len doivent être ≤ 128.
 *   - Le nombre de bits de sous-réseau (subnet_len - delegated_len) doit être dans [1, 32].
 *   - @p subnet_id doit être dans la plage [0, 2^(subnet_bits) - 1].
 *   - Le préfixe parent doit être aligné (aucun bit à 1 après delegated_len).
 *
 * @param[in]  delegated_prefix  Préfixe délégué parent (16 octets, network order).
 * @param[in]  delegated_len     Longueur du préfixe délégué, en bits (0–128).
 * @param[in]  subnet_len        Longueur du sous-réseau dérivé, en bits (delegated_len–128).
 * @param[in]  subnet_id         Identifiant du sous-réseau à encoder dans les bits intermédiaires.
 * @param[out] out_prefix        Buffer de sortie pour le sous-réseau (16 octets).
 *
 * @retval TRUE  Si le sous-réseau est calculé avec succès.
 * @retval FALSE Si une validation échoue ou si l’alignement est invalide.
 */
BOOL IPv6_CalculateSubnet(
	const BYTE* delegated_prefix,
	BYTE delegated_len,
	BYTE subnet_len,
	DWORD subnet_id,
	BYTE* out_prefix)
{
	// ========== VALIDATION ==========
	if (!delegated_prefix || !out_prefix)
	{
		return FALSE;
	}

	if (delegated_len >= subnet_len)
	{
		return FALSE;
	}

	if (delegated_len > 128 || subnet_len > 128)
	{
		return FALSE;
	}

	// Calculer le nombre de bits disponibles
	int subnet_bits = subnet_len - delegated_len;

	if (subnet_bits <= 0 || subnet_bits > 32)
	{
		return FALSE;
	}

	// Vérifier que subnet_id est dans la plage valide
	UINT64 max_subnets = (subnet_bits < 32) ? (1UL << subnet_bits) : 0xFFFFFFFF;

	if (subnet_id >= max_subnets)
	{
		return FALSE;
	}

	// ========== ALIGNMENT CHECK ==========
	// Vérifier que le préfixe parent est aligné
	for (int bit = delegated_len; bit < 128; bit++)
	{
		int byte_idx = bit / 8;
		int bit_idx = 7 - (bit % 8);

		if (delegated_prefix[byte_idx] & (1 << bit_idx))
		{
			// Préfixe non aligné - erreur fatale
			return FALSE;
		}
	}

	// ========== COPIE DU PRÉFIXE ==========
	memcpy(out_prefix, delegated_prefix, 16);

	// ========== ÉCRITURE BIT-EXACTE DU SUBNET_ID ==========
	// Écrire subnet_id dans les bits [delegated_len..subnet_len)
	// MSB first (bit le plus significatif en premier)
	for (int i = 0; i < subnet_bits; i++)
	{
		int global_bit = delegated_len + i;
		int byte_idx = global_bit / 8;
		int bit_idx = 7 - (global_bit % 8);

		// Bit du subnet_id à écrire (MSB first)
		int subnet_bit = (subnet_id >> (subnet_bits - 1 - i)) & 0x01;

		if (subnet_bit)
		{
			out_prefix[byte_idx] |= (1 << bit_idx);
		}
		else
		{
			out_prefix[byte_idx] &= ~(1 << bit_idx);
		}
	}

	// ========== MASQUAGE FINAL ==========
	// S'assurer que tous les bits après subnet_len sont à 0
	for (int bit = subnet_len; bit < 128; bit++)
	{
		int byte_idx = bit / 8;
		int bit_idx = 7 - (bit % 8);
		out_prefix[byte_idx] &= ~(1 << bit_idx);
	}

	return TRUE;
}

/**
 * @brief Construit un pool de sous-réseaux dérivés d’un préfixe parent.
 *
 * Génère tous les sous-réseaux possibles entre @p parent_len et @p subnet_len,
 * en utilisant IPv6_CalculateSubnet(), puis exclut ceux présents dans @p exclude_list.
 * Les sous-réseaux valides sont copiés dans @p pool jusqu’à @p max_pool_size.
 *
 * @param[in]  parent_prefix   Préfixe parent (16 octets).
 * @param[in]  parent_len      Longueur du préfixe parent, en bits.
 * @param[in]  subnet_len      Longueur des sous-réseaux à générer, en bits.
 * @param[in]  exclude_list    Tableau de préfixes à exclure.
 * @param[in]  exclude_count   Nombre d’entrées dans @p exclude_list.
 * @param[out] pool            Tableau de sortie pour les sous-réseaux disponibles.
 * @param[in]  max_pool_size   Taille maximale de @p pool (en nombre d’entrées).
 *
 * @return Nombre de sous-réseaux valides ajoutés à @p pool.
 */
DWORD IPv6_BuildSubnetPool(
	const BYTE* parent_prefix,
	BYTE parent_len,
	BYTE subnet_len,
	const IPv6Prefix* exclude_list,
	DWORD exclude_count,
	IPv6Prefix* pool,
	DWORD max_pool_size)
{
	if (!parent_prefix || !pool || max_pool_size == 0)
	{
		return 0;
	}

	if (parent_len >= subnet_len || parent_len > 128 || subnet_len > 128)
	{
		return 0;
	}

	int subnet_bits = subnet_len - parent_len;
	if (subnet_bits <= 0 || subnet_bits > 32)
	{
		return 0;
	}

	DWORD max_subnets = (subnet_bits < 32) ? (1UL << subnet_bits) : 0xFFFFFFFF;
	DWORD pool_count = 0;

	// Générer tous les sous-réseaux possibles
	for (DWORD subnet_id = 0; subnet_id < max_subnets && pool_count < max_pool_size; subnet_id++)
	{
		BYTE subnet[16];
		if (!IPv6_CalculateSubnet(parent_prefix, parent_len, subnet_len, subnet_id, subnet))
		{
			continue;
		}

		// Vérifier si ce sous-réseau est dans la liste d'exclusion
		BOOL excluded = FALSE;
		for (DWORD i = 0; i < exclude_count; i++)
		{
			if (IPv6_PrefixEquals(subnet, subnet_len,
				exclude_list[i].prefix, exclude_list[i].prefix_len))
			{
				excluded = TRUE;
				break;
			}
		}

		if (!excluded)
		{
			// Ajouter au pool
			memcpy(pool[pool_count].prefix, subnet, 16);
			pool[pool_count].prefix_len = subnet_len;
			pool[pool_count].valid_lifetime = 0;  // À définir par l'appelant
			pool[pool_count].preferred_lifetime = 0;
			pool_count++;
		}
	}

	return pool_count;
}

// ============================================================================
// VALIDATION
// ============================================================================

/**
 * @brief Vérifie que tous les bits après prefix_len sont à 0.
 *
 * Un préfixe est considéré aligné si :
 *   - @p prefix est non NULL
 *   - @p prefix_len ≤ 128
 *   - tous les bits à partir de @p prefix_len jusqu’à 127 sont à 0
 *
 * @param[in] prefix      Préfixe IPv6 (16 octets).
 * @param[in] prefix_len  Longueur du préfixe, en bits (0–128).
 *
 * @retval TRUE  Si le préfixe est correctement aligné.
 * @retval FALSE Si @p prefix est NULL, prefix_len > 128 ou si un bit non nul est trouvé après prefix_len.
 */
BOOL IPv6_IsAligned(const BYTE* prefix, BYTE prefix_len)
{
	if (!prefix || prefix_len > 128)
	{
		return FALSE;
	}

	for (int bit = prefix_len; bit < 128; bit++)
	{
		int byte_idx = bit / 8;
		int bit_idx = 7 - (bit % 8);

		if (prefix[byte_idx] & (1 << bit_idx))
		{
			return FALSE;  // Bit non nul après prefix_len
		}
	}

	return TRUE;
}

/**
 * @brief Vérifie si deux préfixes IPv6 se chevauchent.
 *
 * Deux préfixes se chevauchent si tous les bits communs
 * (jusqu’à @c min(len1, len2)) sont identiques.
 *
 * @param[in] prefix1  Premier préfixe (16 octets).
 * @param[in] len1     Longueur du premier préfixe, en bits.
 * @param[in] prefix2  Second préfixe (16 octets).
 * @param[in] len2     Longueur du second préfixe, en bits.
 *
 * @retval TRUE  Si les deux préfixes se chevauchent.
 * @retval FALSE Si les arguments sont invalides ou si une divergence est trouvée.
 */
BOOL IPv6_PrefixOverlaps(
	const BYTE* prefix1, BYTE len1,
	const BYTE* prefix2, BYTE len2)
{
	if (!prefix1 || !prefix2 || len1 > 128 || len2 > 128)
	{
		return FALSE;
	}

	// Comparer les bits communs (min des deux longueurs)
	BYTE min_len = (len1 < len2) ? len1 : len2;

	for (int bit = 0; bit < min_len; bit++)
	{
		int byte_idx = bit / 8;
		int bit_idx = 7 - (bit % 8);

		int bit1 = (prefix1[byte_idx] >> bit_idx) & 0x01;
		int bit2 = (prefix2[byte_idx] >> bit_idx) & 0x01;

		if (bit1 != bit2)
		{
			return FALSE;  // Divergence - pas de chevauchement
		}
	}

	return TRUE;  // Tous les bits communs sont identiques
}

/**
* @brief Vérifie si une adresse IPv6 appartient à un préfixe donné.
*
* Compare les @p prefix_len premiers bits de @p address et @p prefix.
*
* @param[in] address     Adresse IPv6 (16 octets).
* @param[in] prefix      Préfixe IPv6 (16 octets).
* @param[in] prefix_len  Longueur du préfixe, en bits.
*
* @retval TRUE  Si l’adresse est incluse dans le préfixe.
* @retval FALSE Si les arguments sont invalides ou si un bit diverge.
*/
BOOL IPv6_AddressInPrefix(
	const BYTE* address,
	const BYTE* prefix,
	BYTE prefix_len)
{
	if (!address || !prefix || prefix_len > 128)
	{
		return FALSE;
	}

	// Comparer les prefix_len premiers bits
	for (int bit = 0; bit < prefix_len; bit++)
	{
		int byte_idx = bit / 8;
		int bit_idx = 7 - (bit % 8);

		int addr_bit = (address[byte_idx] >> bit_idx) & 0x01;
		int prefix_bit = (prefix[byte_idx] >> bit_idx) & 0x01;

		if (addr_bit != prefix_bit)
		{
			return FALSE;
		}
	}

	return TRUE;
}

/**
* @brief Détermine le type d’un préfixe IPv6 à partir de son premier octet.
*
* Classification :
*   - FF00::/8      → IPV6_TYPE_MULTICAST
*   - FE80::/10     → IPV6_TYPE_LINK_LOCAL
*   - FC00::/7      → IPV6_TYPE_UNIQUE_LOCAL
*   - 2000::/3      → IPV6_TYPE_GLOBAL_UNICAST
*
* @param[in] prefix  Préfixe ou adresse IPv6 (16 octets).
*
* @return Une valeur de l’énumération ::IPv6PrefixType,
*         ou IPV6_TYPE_INVALID si @p prefix est NULL ou non classifiable.
*/
IPv6PrefixType IPv6_GetPrefixType(const BYTE* prefix)
{
	if (!prefix)
	{
		return IPV6_TYPE_INVALID;
	}

	BYTE first_byte = prefix[0];

	// Multicast: FF00::/8
	if (first_byte == 0xFF)
	{
		return IPV6_TYPE_MULTICAST;
	}

	// Link-local: FE80::/10
	if (first_byte == 0xFE && (prefix[1] & 0xC0) == 0x80)
	{
		return IPV6_TYPE_LINK_LOCAL;
	}

	// Unique Local: FC00::/7
	if ((first_byte & 0xFE) == 0xFC)
	{
		return IPV6_TYPE_UNIQUE_LOCAL;
	}

	// Global Unicast: 2000::/3
	if ((first_byte & 0xE0) == 0x20)
	{
		return IPV6_TYPE_GLOBAL_UNICAST;
	}

	return IPV6_TYPE_INVALID;
}

// ============================================================================
// COMPARAISON ET COPIE
// ============================================================================

/**
* @brief Compare deux préfixes IPv6 (longueur + bits significatifs).
*
* @param[in] prefix1  Premier préfixe (16 octets).
* @param[in] len1     Longueur du premier préfixe, en bits.
* @param[in] prefix2  Second préfixe (16 octets).
* @param[in] len2     Longueur du second préfixe, en bits.
*
* @retval TRUE  Si les longueurs sont identiques et tous les bits significatifs correspondent.
* @retval FALSE Si les pointeurs sont NULL, les longueurs diffèrent ou une divergence de bit est trouvée.
*/
BOOL IPv6_PrefixEquals(
	const BYTE* prefix1, BYTE len1,
	const BYTE* prefix2, BYTE len2)
{
	if (!prefix1 || !prefix2)
	{
		return FALSE;
	}

	if (len1 != len2)
	{
		return FALSE;
	}

	// Comparer les bits significatifs uniquement
	for (int bit = 0; bit < len1; bit++)
	{
		int byte_idx = bit / 8;
		int bit_idx = 7 - (bit % 8);

		int bit1 = (prefix1[byte_idx] >> bit_idx) & 0x01;
		int bit2 = (prefix2[byte_idx] >> bit_idx) & 0x01;

		if (bit1 != bit2)
		{
			return FALSE;
		}
	}

	return TRUE;
}

/**
* @brief Copie un préfixe IPv6 et force son alignement.
*
* Copie @p src dans @p dest (16 octets) puis met à zéro tous les bits
* après @p prefix_len.
*
* @param[out] dest        Buffer de destination (16 octets).
* @param[in]  src         Préfixe source (16 octets).
* @param[in]  prefix_len  Longueur du préfixe, en bits.
*
* @retval TRUE  Si la copie et l’alignement sont valides.
* @retval FALSE Si les pointeurs sont NULL ou prefix_len > 128.
*/
BOOL IPv6_CopyPrefix(
	BYTE* dest,
	const BYTE* src,
	BYTE prefix_len)
{
	if (!dest || !src || prefix_len > 128)
	{
		return FALSE;
	}

	// Copier les octets
	memcpy(dest, src, 16);

	// Masquer les bits après prefix_len (aligner)
	for (int bit = prefix_len; bit < 128; bit++)
	{
		int byte_idx = bit / 8;
		int bit_idx = 7 - (bit % 8);
		dest[byte_idx] &= ~(1 << bit_idx);
	}

	return TRUE;
}

// ============================================================================
// FORMATTING / PARSING
// ============================================================================

/**
* @brief Formatte un préfixe IPv6 sous forme de chaîne "addr/len".
*
* Utilise InetNtopW pour formatter l’adresse, puis ajoute "/len".
*
* @param[in]  prefix       Préfixe IPv6 (16 octets).
* @param[in]  prefix_len   Longueur du préfixe, en bits.
* @param[out] buffer       Buffer de sortie.
* @param[in]  buffer_size  Taille du buffer en caractères (doit être ≥ 64).
*
* @retval TRUE  Si le formatage réussit.
* @retval FALSE Si les arguments sont invalides ou InetNtopW échoue.
*/
BOOL IPv6_FormatPrefix(
	const BYTE* prefix,
	BYTE prefix_len,
	WCHAR* buffer,
	DWORD buffer_size)
{
	if (!prefix || !buffer || buffer_size < 64)
	{
		return FALSE;
	}

	WCHAR addr_str[INET6_ADDRSTRLEN];
	if (!InetNtopW(AF_INET6, prefix, addr_str, INET6_ADDRSTRLEN))
	{
		return FALSE;
	}

	swprintf_s(buffer, buffer_size, L"%s/%u", addr_str, prefix_len);
	return TRUE;
}

/**
* @brief Parse une chaîne de préfixe IPv6 du format "addr/len".
*
* Étapes :
*   1. Duplique @p str dans un buffer local.
*   2. Sépare la partie adresse et la partie longueur sur le caractère '/'.
*   3. Parse l’adresse via InetPtonW.
*   4. Parse la longueur via _wtoi.
*   5. Aligne le préfixe via IPv6_CopyPrefix().
*
* @param[in]  str         Chaîne d’entrée ("2001:db8::/32", par exemple).
* @param[out] out_prefix  Buffer pour le préfixe IPv6 (16 octets).
* @param[out] out_len     Longueur du préfixe, en bits.
*
* @retval TRUE  Si le parsing et l’alignement réussissent.
* @retval FALSE Si la chaîne est invalide ou qu’une étape échoue.
*/
BOOL IPv6_ParsePrefix(
	const WCHAR* str,
	BYTE* out_prefix,
	BYTE* out_len)
{
	if (!str || !out_prefix || !out_len)
	{
		return FALSE;
	}

	WCHAR temp[128];
	wcscpy_s(temp, _countof(temp), str);

	// Séparer adresse et longueur
	WCHAR* slash = wcschr(temp, L'/');
	if (!slash)
	{
		return FALSE;
	}

	*slash = L'\0';
	WCHAR* addr_part = temp;
	WCHAR* len_part = slash + 1;

	// Parser l'adresse
	if (InetPtonW(AF_INET6, addr_part, out_prefix) != 1)
	{
		return FALSE;
	}

	// Parser la longueur
	int len = _wtoi(len_part);
	if (len < 0 || len > 128)
	{
		return FALSE;
	}

	*out_len = (BYTE)len;

	// Aligner le préfixe
	return IPv6_CopyPrefix(out_prefix, out_prefix, *out_len);
}

// ============================================================================
// LIFETIME MANAGEMENT
// ============================================================================

/**
* @brief Calcule T1 et T2 à partir d’un valid_lifetime, selon RFC 8415.
*
* Règles :
*   - T1 = 0.5 * valid_lifetime
*   - T2 = 0.8 * valid_lifetime
*   - Si valid_lifetime == 0 ou 0xFFFFFFFF, les timers sont désactivés (0).
*   - Garantit T1 < T2 en ajustant si nécessaire.
*
* @param[in]  valid_lifetime  Durée de validité totale, en secondes.
* @param[out] out_t1          Timer T1 calculé.
* @param[out] out_t2          Timer T2 calculé.
*/
void IPv6_CalculateTimers(
	DWORD valid_lifetime,
	DWORD* out_t1,
	DWORD* out_t2)
{
	if (!out_t1 || !out_t2)
	{
		return;
	}

	if (valid_lifetime == 0 || valid_lifetime == 0xFFFFFFFF)
	{
		*out_t1 = 0;
		*out_t2 = 0;
		return;
	}

	// T1 = 50% du valid_lifetime
	*out_t1 = valid_lifetime / 2;

	// T2 = 80% du valid_lifetime
	*out_t2 = (valid_lifetime * 4) / 5;

	// Assurer T1 < T2
	if (*out_t1 >= *out_t2)
	{
		*out_t1 = (*out_t2 > 0) ? (*out_t2 - 1) : 0;
	}
}

/**
* @brief Valide et corrige T1/T2 pour respecter les contraintes RFC 8415.
*
* Règles imposées :
*   - 0 < T1 < T2 < valid_lifetime
*   - Si T1 ou T2 valent 0, des valeurs par défaut sont dérivées de valid_lifetime.
*   - Si valid_lifetime == 0xFFFFFFFF, les valeurs existantes sont acceptées telles quelles.
*
* @param[in,out] t1              Pointeur sur T1 (peut être modifié).
* @param[in,out] t2              Pointeur sur T2 (peut être modifié).
* @param[in]     valid_lifetime  Durée de validité totale, en secondes.
*
* @retval TRUE  Si T1/T2 sont valides après ajustement.
* @retval FALSE Si les pointeurs sont NULL.
*/
BOOL IPv6_ValidateTimers(
	DWORD* t1,
	DWORD* t2,
	DWORD valid_lifetime)
{
	if (!t1 || !t2)
	{
		return FALSE;
	}

	// Cas spécial: valid_lifetime infini
	if (valid_lifetime == 0xFFFFFFFF)
	{
		return TRUE;
	}

	// Valeurs par défaut si non fournies
	if (*t1 == 0)
	{
		*t1 = valid_lifetime / 2;
	}

	if (*t2 == 0)
	{
		*t2 = (valid_lifetime * 4) / 5;
	}

	// Validation: T1 < T2 < valid_lifetime
	if (*t2 >= valid_lifetime)
	{
		*t2 = (valid_lifetime * 4) / 5;
	}

	if (*t1 >= *t2)
	{
		*t1 = *t2 / 2;
	}

	// Assurer T1 > 0
	if (*t1 == 0 && *t2 > 0)
	{
		*t1 = 1;
	}

	return (*t1 > 0 && *t1 < *t2 && *t2 < valid_lifetime);
}

// ============================================================================
// LOGGING HELPERS
// ============================================================================

/**
* @brief Log un préfixe IPv6 sous forme lisible "label: addr/len".
*
* Utilise InetNtopW pour convertir l’adresse, puis LogMessage() pour émettre la ligne.
*
* @param[in] label       Libellé à afficher avant le préfixe.
* @param[in] prefix      Préfixe IPv6 (16 octets).
* @param[in] prefix_len  Longueur du préfixe, en bits.
*/
void IPv6_LogPrefix(
	const WCHAR* label,
	const BYTE* prefix,
	BYTE prefix_len)
{
	WCHAR buffer[256];
	WCHAR addr_str[INET6_ADDRSTRLEN];

	if (!prefix || !label)
	{
		return;
	}

	if (InetNtopW(AF_INET6, prefix, addr_str, INET6_ADDRSTRLEN))
	{
		swprintf_s(buffer, _countof(buffer), L"%s: %s/%u", label, addr_str, prefix_len);
		LogMessage(buffer);
	}
}

/**
* @brief Log une adresse IPv6 sous forme lisible "label: addr".
*
* @param[in] label    Libellé à afficher avant l’adresse.
* @param[in] address  Adresse IPv6 (16 octets).
*/
void IPv6_LogAddress(
	const WCHAR* label,
	const BYTE* address)
{
	WCHAR buffer[256];
	WCHAR addr_str[INET6_ADDRSTRLEN];

	if (!address || !label)
	{
		return;
	}

	if (InetNtopW(AF_INET6, address, addr_str, INET6_ADDRSTRLEN))
	{
		swprintf_s(buffer, _countof(buffer), L"%s: %s", label, addr_str);
		LogMessage(buffer);
	}
}

// ============================================================================
// UTILITAIRES ADDITIONNELS
// ============================================================================

/**
* @brief Calcule le nombre total de sous-réseaux possibles.
*
* À partir d’un préfixe parent de longueur @p parent_len et d’une longueur
* de sous-réseau @p subnet_len, retourne 2^(subnet_len - parent_len),
* limité à @c 0xFFFFFFFF.
*
* @param[in] parent_len  Longueur du préfixe parent, en bits.
* @param[in] subnet_len  Longueur du sous-réseau, en bits.
*
* @return Nombre de sous-réseaux possibles, ou 0 si les paramètres sont invalides.
*/
DWORD IPv6_CountAvailableSubnets(
	BYTE parent_len,
	BYTE subnet_len)
{
	if (parent_len >= subnet_len || parent_len > 128 || subnet_len > 128)
	{
		return 0;
	}

	int subnet_bits = subnet_len - parent_len;
	if (subnet_bits <= 0 || subnet_bits > 32)
	{
		return 0;
	}

	return (subnet_bits < 32) ? (1UL << subnet_bits) : 0xFFFFFFFF;
}

/**
* @brief Force tous les bits après prefix_len à 0 dans un préfixe IPv6.
*
* @param[in,out] prefix      Préfixe IPv6 (16 octets) à modifier.
* @param[in]     prefix_len  Longueur du préfixe, en bits.
*/
void IPv6_MaskPrefix(
	BYTE* prefix,
	BYTE prefix_len)
{
	if (!prefix || prefix_len > 128)
	{
		return;
	}

	for (int bit = prefix_len; bit < 128; bit++)
	{
		int byte_idx = bit / 8;
		int bit_idx = 7 - (bit % 8);
		prefix[byte_idx] &= ~(1 << bit_idx);
	}
}

/**
* @brief Extrait le subnet_id d’un sous-réseau dérivé d’un préfixe parent.
*
* Inverse exacte de IPv6_CalculateSubnet() :
*   - Vérifie que @p subnet_prefix appartient au @p parent_prefix.
*   - Lit les bits [parent_len .. subnet_len) en MSB-first.
*   - Reconstruit @p out_subnet_id.
*
* @param[in]  parent_prefix  Préfixe parent (16 octets).
* @param[in]  parent_len     Longueur du préfixe parent, en bits.
* @param[in]  subnet_prefix  Préfixe du sous-réseau (16 octets).
* @param[in]  subnet_len     Longueur du sous-réseau, en bits.
* @param[out] out_subnet_id  Subnet ID reconstruit.
*
* @retval TRUE  Si le sous-réseau est valide et le subnet_id extrait.
* @retval FALSE Si les arguments sont invalides ou si le sous-réseau
*               n’appartient pas au parent.
*/
BOOL IPv6_ExtractSubnetID(
	const BYTE* parent_prefix,
	BYTE parent_len,
	const BYTE* subnet_prefix,
	BYTE subnet_len,
	DWORD* out_subnet_id)
{
	if (!parent_prefix || !subnet_prefix || !out_subnet_id)
	{
		return FALSE;
	}

	if (parent_len >= subnet_len || parent_len > 128 || subnet_len > 128)
	{
		return FALSE;
	}

	int subnet_bits = subnet_len - parent_len;
	if (subnet_bits <= 0 || subnet_bits > 32)
	{
		return FALSE;
	}

	// Vérifier que le sous-réseau appartient bien au parent
	if (!IPv6_PrefixOverlaps(parent_prefix, parent_len, subnet_prefix, subnet_len))
	{
		return FALSE;
	}

	// Extraire le subnet_id depuis les bits [parent_len..subnet_len)
	DWORD subnet_id = 0;

	for (int i = 0; i < subnet_bits; i++)
	{
		int global_bit = parent_len + i;
		int byte_idx = global_bit / 8;
		int bit_idx = 7 - (global_bit % 8);

		int bit_value = (subnet_prefix[byte_idx] >> bit_idx) & 0x01;

		// Reconstruire le subnet_id (MSB first)
		subnet_id |= (bit_value << (subnet_bits - 1 - i));
	}

	*out_subnet_id = subnet_id;
	return TRUE;
}

/**
* @brief Indique si un préfixe est routable globalement ou localement.
*
* Est considéré routable si :
*   - type == IPV6_TYPE_GLOBAL_UNICAST
*   - ou type == IPV6_TYPE_UNIQUE_LOCAL
*
* @param[in] prefix  Préfixe ou adresse IPv6 (16 octets).
*
* @retval TRUE  Si le préfixe est routable.
* @retval FALSE Sinon.
*/
BOOL IPv6_IsRoutable(const BYTE* prefix)
{
	IPv6PrefixType type = IPv6_GetPrefixType(prefix);
	return (type == IPV6_TYPE_GLOBAL_UNICAST || type == IPV6_TYPE_UNIQUE_LOCAL);
}


/**
* @brief Compare deux adresses IPv6 complètes (16 octets).
*
* @param[in] addr1  Première adresse IPv6.
* @param[in] addr2  Seconde adresse IPv6.
*
* @retval TRUE  Si les 16 octets sont identiques.
* @retval FALSE Si les pointeurs sont NULL ou si une différence est trouvée.
*/
BOOL IPv6_AddressEquals(const BYTE* addr1, const BYTE* addr2)
{
	if (!addr1 || !addr2)
	{
		return FALSE;
	}

	return (memcmp(addr1, addr2, 16) == 0);
}

/**
* @brief Construit une adresse IPv6 à partir d’un préfixe et d’un suffixe.
*
* Étapes :
*   1. Copie @p prefix dans @p out_address.
*   2. Met à zéro tous les bits après @p prefix_len.
*   3. Recopie les bits de @p suffix sur la partie host.
*
* Exemple :
*   prefix = 2001:db8::/64
*   suffix = ::1
*   → out_address = 2001:db8::1
*
* @param[in]  prefix       Préfixe IPv6 (16 octets).
* @param[in]  prefix_len   Longueur du préfixe, en bits.
* @param[in]  suffix       Suffixe IPv6 (16 octets).
* @param[out] out_address  Adresse IPv6 complète (16 octets).
*
* @retval TRUE  Si la combinaison est valide.
* @retval FALSE Si les arguments sont invalides ou prefix_len > 128.
*/
BOOL IPv6_CombinePrefixAndSuffix(
	const BYTE* prefix,
	BYTE prefix_len,
	const BYTE* suffix,
	BYTE* out_address)
{
	if (!prefix || !suffix || !out_address || prefix_len > 128)
	{
		return FALSE;
	}

	// Copier le préfixe
	memcpy(out_address, prefix, 16);

	// Masquer les bits après prefix_len
	for (int bit = prefix_len; bit < 128; bit++)
	{
		int byte_idx = bit / 8;
		int bit_idx = 7 - (bit % 8);
		out_address[byte_idx] &= ~(1 << bit_idx);
	}

	// Ajouter le suffixe
	for (int bit = prefix_len; bit < 128; bit++)
	{
		int byte_idx = bit / 8;
		int bit_idx = 7 - (bit % 8);

		int suffix_bit = (suffix[byte_idx] >> bit_idx) & 0x01;

		if (suffix_bit)
		{
			out_address[byte_idx] |= (1 << bit_idx);
		}
	}

	return TRUE;
}