# Remaining work

The high-value route-netlink surface is implemented. This file intentionally
contains only follow-up work; the complete implemented/deferred matrix is in
[`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md).

## `ip route`

- Decode lightweight-tunnel attributes into structured output instead of the
  current lossless debug representation.
- Add `seg6local`, `ioam6`, `xfrm`, `rpl`, `ila`, and richer `ip`/`ip6`
  encapsulation forms when `netlink-packet-route` exposes stable public types.
- Add the separate `ip nexthop` object family and resolve its interaction with
  route `nhid` references.
- Expand save/restore fidelity tests for all route metrics, MPLS labels, and
  nested multipath attributes.

## `ip link` and XDP

- Audit every per-device option against the newest kernel and iproute2 help
  text, especially driver-specific bond, VXLAN, MACsec, WireGuard, and
  tunnel attributes.
- Add structured output for more driver-specific `xstats` and `afstats`
  groups.
- Add relocation/CO-RE fixtures to the libbpf loader tests; the raw ELF
  fallback is intentionally only a compatibility path.

## `ip address`, `ip monitor`, and VRF

- Add address-statistics records instead of relying only on the associated
  link record for `ip address -s`.
- Add structured monitor filtering and JSON event records; the current stream
  preserves unknown kernel attributes by printing the parsed netlink debug
  value.
- Implement `ip vrf exec` with cgroup v2 hierarchy management and a
  `BPF_CGROUP_INET_SOCK_CREATE` program. This is a privileged cgroup-BPF
  feature rather than a route-netlink operation.

## Deferred protocol families

The full traffic-control (`ip/tc`), XFRM, MPTCP, generic-netlink nexthop,
address-label, multicast-address, netconf, FOU, L2TP, ILA, MACsec policy, and
multicast-route families remain outside the current crate. See the status
document for the reason each group is deferred.
