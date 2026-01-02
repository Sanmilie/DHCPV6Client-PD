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
