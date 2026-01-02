/* ============================================================================
 *  @file IPv6Utils.h
 *  @brief Utilitaires IPv6 partagés : dérivation de sous-réseaux, validation,
 *         comparaison, parsing, timers RFC 8415 et logging formaté.
 *
 *  Ce module constitue une base déterministe pour la gestion des préfixes IPv6 :
 *    - calcul bit-exact de sous-réseaux (MSB-first)
 *    - extraction de subnet_id
 *    - validation d’alignement et chevauchement
 *    - construction de pools de sous-réseaux disponibles
 *    - gestion des lifetimes (T1/T2)
 *    - formatage et parsing de préfixes IPv6
 *    - logging structuré
 *
 * ============================================================================ */

#ifndef IPV6_UTILS_H
#define IPV6_UTILS_H

extern void LogMessage(const WCHAR* msg);

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @struct IPv6Prefix
 * @brief Représente un préfixe IPv6 aligné avec ses lifetimes.
 *
 * @var IPv6Prefix::prefix
 *      Adresse IPv6 (16 octets, network order).
 * @var IPv6Prefix::prefix_len
 *      Longueur du préfixe en bits (0–128).
 * @var IPv6Prefix::valid_lifetime
 *      Durée de validité (RFC 8415).
 * @var IPv6Prefix::preferred_lifetime
 *      Durée préférée (RFC 8415).
 */
typedef struct IPv6Prefix {
	BYTE prefix[16];
	BYTE prefix_len;
	DWORD valid_lifetime;
	DWORD preferred_lifetime;
} IPv6Prefix;

/**
 * @struct IPv6Address
 * @brief Représente une adresse IPv6 complète avec préfixe associé.
 *
 * @var IPv6Address::addr
 *      Adresse IPv6 (16 octets).
 * @var IPv6Address::prefix_len
 *      Longueur du préfixe associé.
 * @var IPv6Address::valid_lifetime
 *      Durée de validité.
 * @var IPv6Address::preferred_lifetime
 *      Durée préférée.
 */
typedef struct IPv6Address {
	BYTE addr[16];
	BYTE prefix_len;
	DWORD valid_lifetime;
	DWORD preferred_lifetime;
} IPv6Address;

// ============================================================================
// CALCUL DE SOUS-RÉSEAUX
// ============================================================================

/**
 * @brief Calcule un sous-réseau IPv6 de manière bit-exacte (MSB-first).
 *
 * Étapes :
 *   1. Copie du préfixe parent.
 *   2. Écriture de subnet_id dans les bits [delegated_len .. subnet_len).
 *   3. Mise à zéro des bits après subnet_len (alignement strict).
 *
 * @param[in]  delegated_prefix  Préfixe parent (16 octets).
 * @param[in]  delegated_len     Longueur du préfixe parent (0–128).
 * @param[in]  subnet_len        Longueur du sous-réseau dérivé.
 * @param[in]  subnet_id         Identifiant du sous-réseau (0-based).
 * @param[out] out_prefix        Préfixe résultant (16 octets).
 *
 * @retval TRUE  Si le sous-réseau est généré correctement.
 * @retval FALSE Si une validation échoue.
 */
BOOL IPv6_CalculateSubnet(
	const BYTE* delegated_prefix,
	BYTE delegated_len,
	BYTE subnet_len,
	DWORD subnet_id,
	BYTE* out_prefix
);

/**
 * @brief Extrait le subnet_id d’un sous-réseau dérivé d’un préfixe parent.
 *
 * Inverse exacte de IPv6_CalculateSubnet().
 *
 * @param[in]  parent_prefix  Préfixe parent.
 * @param[in]  parent_len     Longueur du préfixe parent.
 * @param[in]  subnet_prefix  Sous-réseau dérivé.
 * @param[in]  subnet_len     Longueur du sous-réseau.
 * @param[out] out_subnet_id  Identifiant extrait.
 *
 * @retval TRUE  Si extraction valide.
 * @retval FALSE Si le sous-réseau n’appartient pas au parent ou si paramètres invalides.
 */
BOOL IPv6_ExtractSubnetID(
	const BYTE* parent_prefix,
	BYTE parent_len,
	const BYTE* subnet_prefix,
	BYTE subnet_len,
	DWORD* out_subnet_id
);

/**
 * @brief Construit un pool de sous-réseaux disponibles.
 *
 * Génère tous les sous-réseaux possibles entre parent_len et subnet_len,
 * exclut ceux présents dans exclude_list, et remplit pool jusqu’à max_pool_size.
 *
 * @param[in]  parent_prefix  Préfixe parent.
 * @param[in]  parent_len     Longueur du préfixe parent.
 * @param[in]  subnet_len     Longueur des sous-réseaux dérivés.
 * @param[in]  exclude_list   Liste des sous-réseaux à exclure.
 * @param[in]  exclude_count  Nombre d’entrées dans exclude_list.
 * @param[out] pool           Tableau de sortie.
 * @param[in]  max_pool_size  Taille maximale du pool.
 *
 * @return Nombre de sous-réseaux valides ajoutés au pool.
 */
DWORD IPv6_BuildSubnetPool(
	const BYTE* parent_prefix,
	BYTE parent_len,
	BYTE subnet_len,
	const IPv6Prefix* exclude_list,
	DWORD exclude_count,
	IPv6Prefix* pool,
	DWORD max_pool_size
);

// ============================================================================
// VALIDATION
// ============================================================================

/**
 * @brief Vérifie qu’un préfixe est strictement aligné.
 *
 * Tous les bits après prefix_len doivent être à 0.
 *
 * @param[in] prefix      Préfixe IPv6.
 * @param[in] prefix_len  Longueur du préfixe.
 *
 * @retval TRUE  Si aligné.
 * @retval FALSE Si non aligné.
 */
BOOL IPv6_IsAligned(const BYTE* prefix, BYTE prefix_len);

/**
 * @brief Vérifie si deux préfixes IPv6 se chevauchent.
 *
 * Compare les bits communs jusqu’à min(len1, len2).
 *
 * @param[in] prefix1  Premier préfixe.
 * @param[in] len1     Longueur du premier préfixe.
 * @param[in] prefix2  Second préfixe.
 * @param[in] len2     Longueur du second préfixe.
 *
 * @retval TRUE  Si chevauchement.
 * @retval FALSE Si aucun chevauchement.
 */
BOOL IPv6_PrefixOverlaps(
	const BYTE* prefix1, BYTE len1,
	const BYTE* prefix2, BYTE len2
);

/**
 * @brief Vérifie si une adresse IPv6 appartient à un préfixe.
 *
 * @param[in] address     Adresse IPv6.
 * @param[in] prefix      Préfixe IPv6.
 * @param[in] prefix_len  Longueur du préfixe.
 *
 * @retval TRUE  Si l’adresse appartient au préfixe.
 * @retval FALSE Si l’adresse n'appartient pas au préfixe.
 */
BOOL IPv6_AddressInPrefix(
	const BYTE* address,
	const BYTE* prefix,
	BYTE prefix_len
);

// ============================================================================
// TYPE DE PRÉFIXE
// ============================================================================

/**
 * @enum IPv6PrefixType
 * @brief Classification des préfixes IPv6 selon leur portée.
 */
typedef enum IPv6PrefixType
{
	IPV6_TYPE_INVALID = 0,        /**< Préfixe invalide ou non classifiable. */
	IPV6_TYPE_GLOBAL_UNICAST,     /**< 2000::/3 */
	IPV6_TYPE_UNIQUE_LOCAL,       /**< FC00::/7 */
	IPV6_TYPE_LINK_LOCAL,         /**< FE80::/10 */
	IPV6_TYPE_MULTICAST           /**< FF00::/8 */
} IPv6PrefixType;

/**
 * @brief Détermine le type d’un préfixe IPv6.
 *
 * @param[in] prefix  Adresse ou préfixe IPv6.
 *
 * @return Une valeur de IPv6PrefixType.
 */
IPv6PrefixType IPv6_GetPrefixType(const BYTE* prefix);

// ============================================================================
// COMPARAISON ET COPIE
// ============================================================================

/**
 * @brief Compare deux préfixes IPv6 (longueur + bits significatifs).
 *
 * @param[in] prefix1  Premier préfixe.
 * @param[in] len1     Longueur du premier préfixe.
 * @param[in] prefix2  Second préfixe.
 * @param[in] len2     Longueur du second préfixe.
 *
 * @retval TRUE  Si identiques.
 * @retval FALSE Si different.
 */
BOOL IPv6_PrefixEquals(
	const BYTE* prefix1, BYTE len1,
	const BYTE* prefix2, BYTE len2
);

/**
 * @brief Copie un préfixe IPv6 et force l’alignement.
 *
 * @param[out] dest        Destination (16 octets).
 * @param[in]  src         Source (16 octets).
 * @param[in]  prefix_len  Longueur du préfixe.
 *
 * @retval TRUE  Si copie valide.
 * @retval FALSE Si non valide.
 */
BOOL IPv6_CopyPrefix(
	BYTE* dest,
	const BYTE* src,
	BYTE prefix_len
);

// ============================================================================
// FORMATTING / PARSING
// ============================================================================

/**
 * @brief Formatte un préfixe IPv6 sous forme "addr/len".
 *
 * @param[in]  prefix       Préfixe IPv6.
 * @param[in]  prefix_len   Longueur du préfixe.
 * @param[out] buffer       Buffer de sortie.
 * @param[in]  buffer_size  Taille du buffer.
 *
 * @retval TRUE  Si formatage réussi.
 * @retval FALSE Si erreur de formatage.
 */
BOOL IPv6_FormatPrefix(
	const BYTE* prefix,
	BYTE prefix_len,
	WCHAR* buffer,
	DWORD buffer_size
);

/**
 * @brief Parse une chaîne de préfixe IPv6 "addr/len".
 *
 * @param[in]  str         Chaîne d’entrée.
 * @param[out] out_prefix  Préfixe IPv6.
 * @param[out] out_len     Longueur du préfixe.
 *
 * @retval TRUE  Si parsing valide.
 * @retval FALSE Si parsing non valide.
 */
BOOL IPv6_ParsePrefix(
	const WCHAR* str,
	BYTE* out_prefix,
	BYTE* out_len
);

// ============================================================================
// LIFETIME MANAGEMENT
// ============================================================================

/**
 * @brief Calcule T1 et T2 selon RFC 8415.
 *
 * Règles :
 *   - T1 = 50% du valid_lifetime
 *   - T2 = 80% du valid_lifetime
 *
 * @param[in]  valid_lifetime  Durée totale.
 * @param[out] out_t1          Timer T1.
 * @param[out] out_t2          Timer T2.
 */
void IPv6_CalculateTimers(
	DWORD valid_lifetime,
	DWORD* out_t1,
	DWORD* out_t2
);

/**
 * @brief Valide et ajuste T1/T2 selon RFC 8415.
 *
 * Contrainte : 0 < T1 < T2 < valid_lifetime.
 *
 * @param[in,out] t1             Timer T1.
 * @param[in,out] t2             Timer T2.
 * @param[in]     valid_lifetime Durée totale.
 *
 * @retval TRUE  Si les timers sont valides.
 * @retval FALSE Si les timers sont non valides.
 */
BOOL IPv6_ValidateTimers(
	DWORD* t1,
	DWORD* t2,
	DWORD valid_lifetime
);

// ============================================================================
// LOGGING HELPERS
// ============================================================================

/**
 * @brief Log un préfixe IPv6 sous forme lisible.
 *
 * @param[in] label       Libellé.
 * @param[in] prefix      Préfixe IPv6.
 * @param[in] prefix_len  Longueur du préfixe.
 */
void IPv6_LogPrefix(
	const WCHAR* label,
	const BYTE* prefix,
	BYTE prefix_len
);

/**
 * @brief Log une adresse IPv6 sous forme lisible.
 *
 * @param[in] label    Libellé.
 * @param[in] address  Adresse IPv6.
 */
void IPv6_LogAddress(
	const WCHAR* label,
	const BYTE* address
);

#endif // IPV6_UTILS_H
