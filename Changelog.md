## [1.0.2] - 2026-01-03

### Added

#### Router Advertisement Extensions
- **SLLA (Source Link-Layer Address)**: Router MAC address now included in RA packets
- **MTU Option**: Network MTU advertised to clients (RFC 4861)
- **DNSSL (DNS Search List)**: Support for domain search list in RA (RFC 8106)
  - New constants: `ND_OPT_SLLA`, `ND_OPT_MTU`, `ND_OPT_DNSSL` in `DHCP.h`
  - New structures: `nd_opt_slla`, `nd_opt_mtu`, `nd_opt_dnssl` in `DHCPV6.h`

#### Interface Information Gathering
- **Extended `GetCurInterfaceInfo()`**: Now retrieves MAC address and MTU in addition to LUID/IfIndex
  - Signature: `GetCurInterfaceInfo(name, luid, ifindex, mac, mtu)`
  - Updated all call sites across codebase

#### Prefix Change Detection & Rapid Transition
- **Prefix change detection**: Added `PrefixChanged` flag in `DHCPv6State`
- **Graceful prefix transition**: When ISP changes delegated prefix:
  1. Old prefix deprecated via short-lived RA (30s valid/preferred lifetime)
  2. Immediate RA sent to notify clients
  3. Full network reconstruction triggered:
     - Old addresses cleaned
     - Old routes removed
     - New WAN address applied
     - New LAN prefixes configured
     - Default route restored
- **Prevents stale prefix pollution** and ensures seamless client failover

## [1.0.1] - 2026-01-02

### Fixed
- **Critical**: Route cleanup now removes ALL global routes on WAN and LAN
  - Previously only removed default route (::/0) on WAN
  - LAN routes were not cleaned at all
  - Fixes routing ambiguity after ISP prefix changes
  
- **Critical**: LocalService can now write to registry
  - Previously failed silently due to default ACLs
  - DUID is now persistent across reboots
  - DHCPv6 state (leases, prefixes, timers) now preserved
  - ISP sees stable client identity instead of new DUID each boot

### Changed
- Improved logging: Separate counters for WAN and LAN route deletions
- Installation now configures registry ACLs for LocalService

### Security
- Service still runs as LocalService (not elevated)
- ACLs granted only on service-owned registry keys
- Follows principle of least privilege
