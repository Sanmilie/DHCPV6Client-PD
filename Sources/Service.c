/* ============================================================================
*  @file Service.c
*  @brief Service Windows pour DHCPv6 Prefix Delegation (PD) et Router
*         Advertisement (RA). Implémente :
*           - le daemon DHCPv6-PD (state machine)
*           - la supervision réseau (interfaces, LUID, IfIndex)
*           - l’intégration EventLog Windows
*           - l’installation/désinstallation du service
*           - le point d’entrée principal (service ou debug)
*
*  Ce module constitue l’orchestrateur souverain du client PD :
*    - initialisation du moteur DHCPv6
*    - gestion du thread de state machine
*    - gestion des événements système
*    - configuration persistante via registre
*
*  Toutes les opérations sont conçues pour être :
*    - déterministes
*    - robustes face aux erreurs Windows API
*    - traçables via EventLog
*
* @author Yannick LaRue
* @copyright San@sro Inc. / SSE Carte à Puce Inc.
* ============================================================================ */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <MSWSock.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <aclapi.h> 
#include <stdio.h>
#include <time.h>
#include <bcrypt.h>
#include <inttypes.h>
#define SRV_MAIN
#include "../Headers/DHCP.h"
#undef SRV_MAIN
#include "../Headers/DHCPV6.h"

SERVICE_STATUS			g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE	g_StatusHandle = NULL;
HANDLE					g_ServiceStopEvent = INVALID_HANDLE_VALUE;
HANDLE					g_LogEventSource = NULL;
BOOL					g_LogInfo = 1;

pDHCPV6 ClientV6;

// ============================================================================
// EVENT LOG
// ============================================================================

/**
* @brief Initialise la source EventLog Windows pour le service.
*
* Doit être appelée avant tout appel à LogMessage() ou LogError().
*/
void InitEventLog()
{
	g_LogEventSource = RegisterEventSourceW(NULL, L"DHCP-Client");
}

/**
* @brief Enregistre un message d’information dans l’EventLog Windows.
*
* @param[in] msg  Message Unicode à enregistrer.
*/
void LogMessage(const WCHAR* msg)
{
	if (g_LogEventSource && g_LogInfo)
	{
		LPCWSTR strings[1] = { msg };
		ReportEventW(g_LogEventSource, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, strings, NULL);
	}
}

/**
* @brief Enregistre un message d’erreur dans l’EventLog Windows.
*
* @param[in] msg  Message Unicode à enregistrer.
*/
void LogError(const WCHAR* msg)
{
	if (g_LogEventSource)
	{
		LPCWSTR strings[1] = { msg };
		ReportEventW(g_LogEventSource, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, strings, NULL);
	}
}

// ============================================================================
// NETWORK CONFIG SUPERVISION
// ============================================================================

/**
 * @brief Récupère le LUID, l'IfIndex, la MAC et la MTU d'une interface réseau IPv6.
 *
 * Cette fonction parcourt les interfaces IPv6 du système et cherche une correspondance
 * avec le nom fourni. La recherche se fait sur :
 *   - Description (p->Description)
 *   - FriendlyName (p->FriendlyName)
 *
 * Si l'interface est trouvée, les informations suivantes peuvent être récupérées :
 *   - LUID (Locally Unique Identifier)
 *   - IfIndex (index d'interface)
 *   - MAC du périphérique (6 octets minimum)
 *   - MTU du lien
 *
 * @param[in]  name     Nom de l'interface à rechercher (Description ou FriendlyName).
 * @param[out] luid     Pointeur pour récupérer le LUID de l'interface (optionnel).
 * @param[out] ifindex  Pointeur pour récupérer l'IfIndex de l'interface (optionnel).
 * @param[out] Mac      Pointeur pour récupérer l'adresse MAC (6 octets, optionnel).
 * @param[out] MTU      Pointeur pour récupérer la MTU de l'interface (optionnel).
 *
 * @retval TRUE  L'interface correspondant au nom a été trouvée et les informations
 *               disponibles ont été remplies.
 * @retval FALSE L'interface n'existe pas ou une erreur système est survenue.
 *
 * @note Cette fonction utilise GetAdaptersAddresses(AF_INET6) et alloue un buffer
 *       dynamique pour parcourir la liste des interfaces. Le buffer est toujours
 *       libéré avant le retour.
 * @note Les champs optionnels peuvent être passés à NULL si l'information n'est pas nécessaire.
 */
BOOL GetCurInterfaceInfo(const WCHAR* name, NET_LUID* luid, NET_IFINDEX* ifindex, BYTE* Mac, DWORD* MTU)
{
	PIP_ADAPTER_ADDRESSES pAddr = NULL;
	ULONG len = 0;
	ULONG result;
	BOOL found = FALSE;
	WCHAR log[128];

	// Premier appel pour obtenir la taille nécessaire
	result = GetAdaptersAddresses(AF_INET6, 0, NULL, NULL, &len);
	if (result != ERROR_BUFFER_OVERFLOW)
	{
		swprintf_s(log, sizeof(log) >> 1, L"GetAdaptersAddresses (1st) failed: %lu", result);
		LogError(log);
		return FALSE;
	}

	pAddr = (IP_ADAPTER_ADDRESSES*)HeapAlloc(GetProcessHeap(), 0, len);
	if (!pAddr)
	{
		LogError(L"GetCurInterfaceInfo: malloc failed");
		return FALSE;
	}

	result = GetAdaptersAddresses(AF_INET6, 0, NULL, pAddr, &len);
	if (result != NO_ERROR)
	{
		swprintf_s(log, sizeof(log) >> 1, L"GetAdaptersAddresses (2nd) failed: %lu", result);
		LogError(log);
		HeapFree(GetProcessHeap(), 0, pAddr);  // FIX: Libération avant retour erreur
		return FALSE;
	}

	for (PIP_ADAPTER_ADDRESSES p = pAddr; p != NULL; p = p->Next)
	{
		BOOL nameMatch = FALSE;

		if (p->Description && wcscmp(p->Description, name) == 0)
		{
			nameMatch = TRUE;
		}
		else if (p->FriendlyName && wcscmp(p->FriendlyName, name) == 0)
		{
			nameMatch = TRUE;
		}

		if (nameMatch)
		{
			if (luid) *luid = p->Luid;
			if (ifindex) *ifindex = p->IfIndex;
			if (Mac && p->PhysicalAddressLength >= 6) memcpy(Mac, p->PhysicalAddress, 6);
			if (MTU) *MTU = p->Mtu;
			found = TRUE;

			swprintf_s(log, sizeof(log) >> 1, L"Interface found: %s (LUID: %lld, Index: %u)",
				name, p->Luid.Value, p->IfIndex);
			LogMessage(log);
			break;
		}
	}

	HeapFree(GetProcessHeap(), 0, pAddr);  // FIX: Toujours libérer

	if (!found)
	{
		swprintf_s(log, sizeof(log) >> 1, L"Interface not found: %s", name);
		LogError(log);
	}

	return found;
}

// ============================================================================
// SERVICE CONTROL HANDLER
// ============================================================================

/**
 * @brief Callback Windows pour gérer les commandes du SCM.
 *
 * Gère :
 *   - SERVICE_CONTROL_STOP
 *
 * @param[in] c  Code de contrôle envoyé par le Service Control Manager.
 */
VOID WINAPI ServiceCtrlHandler(DWORD c)
{
	if (c == SERVICE_CONTROL_STOP && g_ServiceStatus.dwCurrentState == SERVICE_RUNNING)
	{
		LogMessage(L"Service stop requested");
		g_ServiceStatus.dwControlsAccepted = 0;
		g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		g_ServiceStatus.dwWaitHint = 30000;  // 30 secondes max pour s'arrêter
		SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
		SetEvent(g_ServiceStopEvent);
	}
}

/**
 * @brief Charge les parametres global depuis le registre.
 *
 * Charge :
 *   - LogInfo
 *
 * Applique :
 *   - valeurs par défaut si absent
 *   - validation des plages
 *
 * @retval TRUE  Si la configuration est chargée ou par défaut.
 * @retval FALSE Si la clé n’existe pas (defaults appliqués).
 */
static BOOL LoadParamFromRegistry()
{
	HKEY hKey = NULL;
	LONG result;
	DWORD size;
	DWORD value = 0;
	WCHAR log[512] = { 0 };

	// Valeurs par défaut
	g_LogInfo = 0;

	result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_PARAM, 0, KEY_READ, &hKey);
	if (result != ERROR_SUCCESS)
	{
		_snwprintf_s(log, _countof(log), _TRUNCATE,
			L"Global Param: Using defaults (registry key not found: %lu)", result);
		LogError(log);
		return FALSE;
	}


	// LogInfo
	size = sizeof(DWORD);
	if (RegQueryValueExW(hKey, L"LogInfo", NULL, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS)
	{
		g_LogInfo = (value != 0);
	}
	return TRUE;
}

// ============================================================================
// SERVICE MAIN
// ============================================================================

/**
 * @brief Point d’entrée principal du service Windows.
 *
 * Initialise :
 *   - Winsock
 *   - EventLog
 *   - moteur DHCPv6
 *   - thread de state machine
 *
 * @param[in] argc  Nombre d’arguments.
 * @param[in] argv  Tableau d’arguments.
 */
VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
	
	HANDLE ThreadWorker[2];
	WSADATA wsa;

	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
	if (!g_StatusHandle) return;

	g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return;

	SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

	g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	InitEventLog();
	//Load Global Param
	LoadParamFromRegistry();

	LogMessage(L"DHCPv6-PD Service Starting");
	ClientV6 = InitDHCPV6();

	//Thread IPV6
	ThreadWorker[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ClientV6->DHCPStateMachine, (void*)ClientV6, 0, NULL);
	g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

	WaitForMultipleObjects(1, ThreadWorker, 1, INFINITE);



	if (g_LogEventSource) DeregisterEventSource(g_LogEventSource);
	g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
	WSACleanup();
}

// ============================================================================
// SERVICE INSTALLATION/REMOVAL
// ============================================================================

/**
 * @brief Configure les ACL pour permettre à LocalService d'écrire.
 *
 * @param[in] registry_key_path  Chemin de la clé (ex: "SYSTEM\\...\\Parameters")
 *
 * @retval TRUE  Si ACL appliquées avec succès.
 * @retval FALSE Si une erreur survient.
 */
static BOOL SetRegistryACLForLocalService(const WCHAR* registry_key_path)
{
	HKEY hKey = NULL;
	LONG result;
	BOOL success = FALSE;

	// Ouvrir la clé avec droits WRITE_DAC (pour modifier les ACL)
	result = RegOpenKeyExW(
		HKEY_LOCAL_MACHINE,
		registry_key_path,
		0,
		WRITE_DAC | READ_CONTROL,
		&hKey
	);

	if (result != ERROR_SUCCESS)
	{
		wprintf(L"Failed to open registry key for ACL modification: %lu\n", result);
		return FALSE;
	}

	// Récupérer le SID de LocalService
	PSID pLocalServiceSID = NULL;
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

	if (!AllocateAndInitializeSid(
		&ntAuthority,
		1,
		SECURITY_LOCAL_SERVICE_RID,
		0, 0, 0, 0, 0, 0, 0,
		&pLocalServiceSID))
	{
		wprintf(L"AllocateAndInitializeSid failed: %lu\n", GetLastError());
		RegCloseKey(hKey);
		return FALSE;
	}

	// Créer une EXPLICIT_ACCESS pour LocalService
	EXPLICIT_ACCESSW ea;
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESSW));

	ea.grfAccessPermissions = KEY_READ | KEY_WRITE | KEY_CREATE_SUB_KEY | KEY_SET_VALUE;
	ea.grfAccessMode = GRANT_ACCESS;
	ea.grfInheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea.Trustee.ptstrName = (LPWSTR)pLocalServiceSID;

	// Récupérer l'ACL existante
	PACL pOldDACL = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;

	result = GetSecurityInfo(
		hKey,
		SE_REGISTRY_KEY,
		DACL_SECURITY_INFORMATION,
		NULL,
		NULL,
		&pOldDACL,
		NULL,
		&pSD
	);

	if (result != ERROR_SUCCESS)
	{
		wprintf(L"GetSecurityInfo failed: %lu\n", result);
		FreeSid(pLocalServiceSID);
		RegCloseKey(hKey);
		return FALSE;
	}

	// Créer une nouvelle ACL en fusionnant
	PACL pNewDACL = NULL;
	result = SetEntriesInAclW(1, &ea, pOldDACL, &pNewDACL);

	if (result != ERROR_SUCCESS)
	{
		wprintf(L"SetEntriesInAcl failed: %lu\n", result);
		LocalFree(pSD);
		FreeSid(pLocalServiceSID);
		RegCloseKey(hKey);
		return FALSE;
	}

	// Appliquer la nouvelle ACL
	result = SetSecurityInfo(
		hKey,
		SE_REGISTRY_KEY,
		DACL_SECURITY_INFORMATION,
		NULL,
		NULL,
		pNewDACL,
		NULL
	);

	if (result == ERROR_SUCCESS)
	{
		wprintf(L"Registry ACL set for LocalService: %s\n", registry_key_path);
		success = TRUE;
	}
	else
	{
		wprintf(L"SetSecurityInfo failed: %lu\n", result);
	}

	// Cleanup
	LocalFree(pNewDACL);
	LocalFree(pSD);
	FreeSid(pLocalServiceSID);
	RegCloseKey(hKey);

	return success;
}

/**
* @brief Installe le service DHCPv6-PD dans Windows.
*
* Actions :
*   - crée le service dans SCM
*   - configure la description
*   - crée la clé de registre de configuration
*   - initialise les valeurs par défaut
*
* @retval TRUE  Si installation réussie.
* @retval FALSE Si une étape échoue.
*/
BOOL InstallService()
{
	SC_HANDLE scm = NULL;
	SC_HANDLE svc = NULL;
	WCHAR path[MAX_PATH];
	BOOL success = FALSE;

	// Obtenir le chemin de l'exécutable
	if (!GetModuleFileNameW(NULL, path, MAX_PATH))
	{
		wprintf(L"Failed to get module filename\n");
		return FALSE;
	}

	// Ouvrir le gestionnaire de services
	scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!scm)
	{
		wprintf(L"OpenSCManager failed (%lu)\n", GetLastError());
		return FALSE;
	}

	// Créer le service
	svc = CreateServiceW(
		scm,
		SERVICE_NAME,
		DISPLAY_NAME,
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL,
		path,
		NULL,
		NULL,
		L"Afd\0NSI\0NlaSvc\0\0",
		L"NT AUTHORITY\\LocalService",
		NULL
	);

	if (svc)
	{
		// Définir la description
		SERVICE_DESCRIPTION sd = { (LPWSTR)MYSERVICE_DESCRIPTION };
		ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &sd);

		wprintf(L"Service installed successfully\n");
		success = TRUE;
	}
	else if (GetLastError() == ERROR_SERVICE_EXISTS)
	{
		svc = OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);

		ChangeServiceConfigW(scm,
			SERVICE_WIN32_OWN_PROCESS,
			SERVICE_AUTO_START,
			SERVICE_ERROR_NORMAL,
			path,
			NULL,
			NULL,
			L"Afd\0NSI\0NlaSvc\0\0",
			L"NT AUTHORITY\\LocalService",
			NULL,
			DISPLAY_NAME
		);
		// Définir la description
		SERVICE_DESCRIPTION sd = { (LPWSTR)MYSERVICE_DESCRIPTION };
		ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &sd);

		success = TRUE;
	}
	else
	{
		wprintf(L"CreateService failed (%lu)\n", GetLastError());
	}

	if (svc) CloseServiceHandle(svc);
	if (scm) CloseServiceHandle(scm);

	// Créer la clé de registre pour la configuration
	if (success)
	{
		HKEY hKey;
		LONG result;

		result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_PARAM, 0, NULL, 0,
			KEY_WRITE, NULL, &hKey, NULL);
		if (result == ERROR_SUCCESS)
		{
			// Valeurs par défaut
			DWORD value = 0;
			RegSetValueExW(hKey, L"LogInfo", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
		}

		result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_DHCPV6, 0, NULL, 0,
			KEY_WRITE, NULL, &hKey, NULL);
		if (result == ERROR_SUCCESS)
		{
			// Valeurs par défaut
			DWORD value = 0;
			RegSetValueExW(hKey, L"AllowSingle64", 0, REG_DWORD, (BYTE*)&value, sizeof(value));


			value = 1;  // DisableRelease par défaut pour éviter les problèmes
			RegSetValueExW(hKey, L"ForceStableDUID", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
			RegSetValueExW(hKey, L"DisableRelease", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
			RegSetValueExW(hKey, L"EnableRA", 0, REG_DWORD, (BYTE*)&value, sizeof(value));

			value = 600;
			RegSetValueExW(hKey, L"RAInterval", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
			value = 1800;
			RegSetValueExW(hKey, L"RALifetime", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
			value = 1200;
			RegSetValueExW(hKey, L"RDNSSLifetime", 0, REG_DWORD, (BYTE*)&value, sizeof(value));


			RegSetValueExW(hKey, L"DNSServer0", 0, REG_SZ, (BYTE*)L"::1", sizeof(L"::1"));

			WCHAR wan[] = L"Internet";
			RegSetValueExW(hKey, L"WANInterface", 0, REG_SZ, (BYTE*)wan, sizeof(wan));

			WCHAR lan0[] = L"Local Network";
			RegSetValueExW(hKey, L"LANInterface0", 0, REG_SZ, (BYTE*)lan0, sizeof(lan0));

			DWORD min_len = MIN_PREFIX_LEN;
			DWORD max_len = MAX_PREFIX_LEN;
			RegSetValueExW(hKey, L"MinPrefixLen", 0, REG_DWORD, (BYTE*)&min_len, sizeof(min_len));
			RegSetValueExW(hKey, L"MaxPrefixLen", 0, REG_DWORD, (BYTE*)&max_len, sizeof(max_len));

			RegCloseKey(hKey);

			wprintf(L"Default configuration created in registry\n");
			wprintf(L"Validate LANInterface0 Name and WANInterface Name MAX : 12 Lan\n");
			wprintf(L"Validate DNSServer0 address MAX 4 DNS\n");
			wprintf(L"Note: DUID is generated/stored in registry for persistence.\n");
			wprintf(L"Please edit HKLM\\%s before starting the service\n", REG_KEY_DHCPV6);
		}

		// ACL pour DHCPV6 (permet au service de sauvegarder le DUID)
		if (!SetRegistryACLForLocalService(REG_KEY_DHCPV6))
		{
			wprintf(L"Warning: Failed to set ACL for DHCPV6 key\n");
			wprintf(L"Service will not be able to persist DUID\n");
		}

		// === 3. Clé State (pour persistance) ===
		result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_STATE, 0, NULL, 0,
			KEY_WRITE, NULL, &hKey, NULL);
		if (result == ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
		}

		// ACL pour State (critique pour SaveDHCPv6State)
		if (!SetRegistryACLForLocalService(REG_KEY_STATE))
		{
			wprintf(L"Warning: Failed to set ACL for State key\n");
			wprintf(L"Service will not be able to persist state across reboots\n");
		}
	}

	return success;
}


/**
* @brief Supprime le service DHCPv6-PD du système.
*
* Arrête le service si nécessaire, puis :
*   - supprime l’entrée SCM
*   - supprime les clés de registre associées
*
* @retval TRUE  Si suppression réussie.
* @retval FALSE Si une étape échoue.
*/
BOOL RemoveService()
{
	SC_HANDLE scm = NULL;
	SC_HANDLE svc = NULL;
	BOOL success = FALSE;

	scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!scm)
	{
		wprintf(L"OpenSCManager failed (%lu)\n", GetLastError());
		return FALSE;
	}

	svc = OpenServiceW(scm, SERVICE_NAME, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
	if (!svc)
	{
		if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
		{
			wprintf(L"Service does not exist\n");
			success = TRUE;
		}
		else
		{
			wprintf(L"OpenService failed (%lu)\n", GetLastError());
		}
		CloseServiceHandle(scm);
		return success;
	}

	// Arrêter le service s'il est en cours d'exécution
	SERVICE_STATUS status;
	if (QueryServiceStatus(svc, &status))
	{
		if (status.dwCurrentState != SERVICE_STOPPED)
		{
			wprintf(L"Stopping service...\n");
			ControlService(svc, SERVICE_CONTROL_STOP, &status);

			// Attendre l'arrêt
			for (int i = 0; i < 10; i++)
			{
				Sleep(1000);
				QueryServiceStatus(svc, &status);
				if (status.dwCurrentState == SERVICE_STOPPED)
					break;
				wprintf(L".");
			}
			wprintf(L"\n");

			if (status.dwCurrentState != SERVICE_STOPPED)
			{
				wprintf(L"Warning: Service could not be stopped\n");
			}
		}
	}

	// Supprimer le service
	if (DeleteService(svc))
	{
		wprintf(L"Service removed successfully\n");
		success = TRUE;
	}
	else
	{
		wprintf(L"DeleteService failed (%lu)\n", GetLastError());
	}

	// Supprimer la clé de registre
	RegDeleteKeyW(HKEY_LOCAL_MACHINE, REG_KEY_DHCPV6);
	RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\DHCPv6PDClient");

	CloseServiceHandle(svc);
	CloseServiceHandle(scm);

	return success;
}

// ============================================================================
// MAIN - Avec arguments de ligne de commande
// ============================================================================

/**
* @brief Affiche l’aide en ligne de commande.
*/
void PrintUsage()
{
	wprintf(L"\nDHCPv6 Prefix Delegation Client\n");
	wprintf(L"===============================\n");
	wprintf(L"Usage: dhcpv6_pd_service.exe [option]\n\n");
	wprintf(L"Options:\n");
	wprintf(L"  -install    Install the service\n");
	wprintf(L"  -remove     Remove the service\n");
	wprintf(L"  -debug      Run in console mode (debug)\n");
	wprintf(L"  (no args)   Run as service\n\n");
	wprintf(L"Configuration registry key:\n");
	wprintf(L"  HKLM\\%s\n\n", REG_KEY_DHCPV6);
}

/**
* @brief Point d’entrée principal (console ou service).
*
* Modes :
*   - -install : installe le service
*   - -remove  : supprime le service
*   - -debug   : exécute en mode console
*   - (aucun)  : démarre en mode service
*
* @param[in] argc  Nombre d’arguments.
* @param[in] argv  Tableau d’arguments.
*
* @return Code de sortie Windows.
*/
int wmain(int argc, wchar_t* argv[])
{
	HANDLE ThreadWorker[2];
	// Vérifier les arguments
	if (argc > 1)
	{
		if (_wcsicmp(argv[1], L"-install") == 0 ||
			_wcsicmp(argv[1], L"/install") == 0 ||
			_wcsicmp(argv[1], L"--install") == 0)
		{
			return InstallService() ? 0 : 1;
		}
		else if (_wcsicmp(argv[1], L"-remove") == 0 ||
			_wcsicmp(argv[1], L"/remove") == 0 ||
			_wcsicmp(argv[1], L"--remove") == 0)
		{
			return RemoveService() ? 0 : 1;
		}
		else if (_wcsicmp(argv[1], L"-debug") == 0 ||
			_wcsicmp(argv[1], L"/debug") == 0 ||
			_wcsicmp(argv[1], L"--debug") == 0)
		{
			// Mode debug - exécution en console
			wprintf(L"Running in debug mode (press Ctrl+C to exit)\n");

			// Simuler ServiceMain
			WSADATA wsa;
			WSAStartup(MAKEWORD(2, 2), &wsa);

			InitEventLog();
			LogMessage(L"DHCPv6-PD Service Starting in debug mode");
			ClientV6 = InitDHCPV6();

			//Attend debugger
			while (1)
			{
				Sleep(5000);

			}

			//Thread IPV6
			ThreadWorker[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ClientV6->DHCPStateMachine, (void*)ClientV6, 0, NULL);
			g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
			SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

			WaitForMultipleObjects(1, ThreadWorker, 1, INFINITE);

			return 0;
		}
		else if (_wcsicmp(argv[1], L"-help") == 0 ||
			_wcsicmp(argv[1], L"/help") == 0 ||
			_wcsicmp(argv[1], L"--help") == 0 ||
			_wcsicmp(argv[1], L"/?") == 0)
		{
			PrintUsage();
			return 0;
		}
		else
		{
			wprintf(L"Unknown option: %s\n", argv[1]);
			PrintUsage();
			return 1;
		}
	}

	// Mode service normal
	SERVICE_TABLE_ENTRYW st[] = {
		{(LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONW)ServiceMain},
		{NULL, NULL}
	};

	if (!StartServiceCtrlDispatcherW(st))
	{
		DWORD err = GetLastError();
		if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
		{
			wprintf(L"Must run as a service. Use -install to install.\n");
		}
		else
		{
			wprintf(L"StartServiceCtrlDispatcher failed (%lu)\n", err);
		}
		return err;
	}

	return 0;
}
