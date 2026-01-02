# DHCPV6Client-PD Client for Windows

[![Windows](https://img.shields.io/badge/Windows-Server%202019%2B-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![IPv6](https://img.shields.io/badge/IPv6-RFC%208415-blue)](https://datatracker.ietf.org/doc/html/rfc8415)
[![GitHub release](https://img.shields.io/github/v/release/Sanmilie/DHCPV6Client-PD)](https://github.com/Sanmilie/DHCPV6Client-PD/releases)

Production-ready DHCPv6 Prefix Delegation client with Router Advertisements.

A Windows service that implements DHCPv6 Prefix Delegation client functionality with automatic subnet allocation and Router Advertisements.
What is this?
This service enables Windows to act as an IPv6 router by:

Requesting IPv6 prefixes from your ISP via DHCPv6-PD
Automatically subdividing delegated prefixes into /64 subnets
Announcing these subnets to LAN clients via Router Advertisements
Including DNS servers in RAs (RDNSS, RFC 8106)
Maintaining synchronization when prefixes change

Why?
Windows lacks native support for:

DHCPv6 Prefix Delegation (DHCPv6-PD) as a requesting router
Automatic subnet derivation from delegated prefixes
RDNSS announcements in Router Advertisements
Proper cleanup when ISP prefixes change

This service addresses these gaps by providing a complete, RFC-compliant implementation.

Features
DHCPv6-PD Client

Full RFC 8415 implementation (SOLICIT, REQUEST, RENEW, REBIND, RELEASE)
Stable DUID option for consistent ISP identification
IA_NA (WAN address) and IA_PD (prefix delegation) support
Automatic T1/T2 calculation with validation
Persistent state across reboots

Subnet Management

MSB-first derivation of /64 subnets from delegated prefixes
Supports /48, /56, /60 delegated prefixes (configurable)
Assigns ::1 to router on each LAN subnet
Optional single /64 mode for ISPs that don't delegate larger prefixes

Router Advertisements (RFC 4861)

Complete RA packets with Prefix Information and RDNSS options
Configurable intervals and lifetimes
Immediate RAs after prefix acquisition or changes
Proper ICMPv6 checksum calculation

Network Configuration

Clean management of addresses and routes
Change detection to avoid unnecessary reconfiguration
Network change monitoring with automatic response
Registry-based configuration with hot-reload support


Installation
Build
cmd cl dhcpv6_pd_service.c DHCPv6Client.c IPv6Utils.c /Fe:DHCPv6PDClient.exe ^
   /link ws2_32.lib iphlpapi.lib advapi32.lib bcrypt.lib
Or
Get from release.
Install
cmd DHCPv6PDClient.exe -install
Configure
Edit registry at HKLM\SYSTEM\CurrentControlSet\Services\DHCPv6PDClient\Parameters\DHCPV6:
Required:

WANInterface (REG_SZ): WAN interface name

LANInterface0 (REG_SZ): First LAN interface name

Additional LANInterfaceN entries as needed (up to 12)

Optional:

ForceStableDUID (REG_DWORD): Use persistent DUID (default: 1)

DisableRelease (REG_DWORD): Keep prefix on shutdown (default: 1)

AllowSingle64 (REG_DWORD): Accept /64 prefixes (default: 0)

EnableRA (REG_DWORD): Send Router Advertisements (default: 1)

RAInterval (REG_DWORD): RA interval in seconds (default: 600)

DNSServer0 (REG_SZ): DNS server address or ::1 for prefix::1

See source code for full list

Start
cmd net start DHCPv6PDClient


Monitor via Event Viewer → Application → Source: `DHCP-Client`

ROOT CA INSTALLATION (IF NEEDED)
---------------------------------

If you see "Unknown Publisher" warning:

1. Open RootCA.crt
2. Click "Install Certificate"
3. Select "Local Machine"
4. Place in "Trusted Root Certification Authorities"
5. Restart verification

---



##Example Configuration

**Basic home router with ISP (delegates `/56`):**

WANInterface = "Internet"
LANInterface0 = "Ethernet"
LANInterface1 = "WiFi"
DNSServer0 = "::1"
Result: First LAN gets prefix:0::/64, second gets prefix:1::/64, etc.

Troubleshooting
Check Event Viewer
All operations are logged to Windows Event Viewer (Application log, source DHCP-Client)
Common Issues
No prefix acquired:

Verify ISP supports DHCPv6-PD
Check WAN interface name matches registry exactly
Run in debug mode: DHCPv6PDClient.exe -debug

Clients not getting addresses:

Ensure Router Discovery is enabled on client interfaces
Check Windows Firewall allows ICMPv6
Verify RAs are being sent (check Event Viewer)

Service won't start:

Verify interface names exist in network connections
Check service account has necessary privileges
Review Event Viewer for specific errors

Limitations
By Design

SLAAC only for clients (no stateful DHCPv6 server)
No DHCPv6 relay functionality
No IPv4 support (IPv6 only)
No NAT66 (uses global addressing)

Technical Constraints

Maximum 12 LAN interfaces
Maximum 4 DNS servers
Prefix must be ≥ /48 and ≤ /64 by default

ISP Compatibility
Not all ISPs support DHCPv6-PD. Known working ISPs include Bell Canada, Videotron, Cogeco, and most European ISPs. Some major US ISPs (Comcast, AT&T) have limited or no PD support.

Security Notes

Service runs as NT AUTHORITY\LocalService (limited privileges)
DHCPv6 and RA have no built-in authentication (protocol limitation)
Recommend using firewall rules to restrict WAN DHCPv6 traffic

License
MIT License - See LICENSE file for details.

Support & Contributing

Report issues via GitHub Issues
Contributions welcome via Pull Requests
See source code comments for architecture details

Author: Yannick LaRue
Company: San@sro Inc. / SSE Carte à Puce Inc.
