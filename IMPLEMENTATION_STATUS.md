# `ip-rs` implementation status

This document records the practical Linux networking surface implemented in
this checkout, the commands that remain outside it, and the reasons for the
boundary. It is intentionally more candid than a feature checklist: a
command may be present while a kernel, driver, capability, or packet-crate
limitation still prevents a particular invocation from succeeding.

## Executive summary

There are 12 top-level command families registered by `src/ip/main.rs`:

`link`, `address`, `route`, `neighbour`, `bridge`, `rule`, `ntable`, `stats`,
`token`, `vrf`, `netns`, and `monitor`.

The common route-netlink administration path is now broad enough for normal
interface inventory, address and route configuration, policy routing,
neighbour management, bridge FDB/VLAN work, network namespaces, VRF
inventory, XDP attachment, and event monitoring. This is substantial coverage
of the day-to-day `ip` command, but it is not a claim of complete iproute2
parity. The separate generic-netlink families listed below remain deferred.

## Implemented command map

`Completed: true` means the command has a real implementation in this tree;
it does not mean every kernel-specific option is available.

| Surface | Implemented forms | Completed | Notes |
| --- | --- | --- | --- |
| `ip link` | `show/list`, `add`, `delete`, `set`, `replace`, `property`, `xstats`, `afstats`, `help` | `true` | Includes typed link data for many virtual devices, brief/oneline output, statistics, XDP object/pinned/off modes, and `-n/--netns` selection. |
| `ip address` | `show`, `add`, `delete`, `change`, `replace`, `flush`, `save`, `restore`, `showdump` | `true` | Supports address selectors, protocol values, lifetimes, flags, JSON/YAML, brief/oneline output, and binary dump round-trips. |
| `ip route` | `show`, `flush`, `add`, `delete`, `change`, `replace`, `append`, `prepend`, `get`, `save`, `restore`, `showdump` | `true` | Includes tables, metrics, multipath, `nhid`, `tos`, TTL propagation, flow selectors, `root/match/exact`, VRF selection, MPLS/SEG6/IP6 encap input, and dump round-trips. |
| `ip neighbour` | `show`, `add`, `replace/change`, `delete`, `flush` | `true` | ARP/NDP selectors, NUD states, link resolution, mutation, flushing, and structured output. |
| `ip bridge` | `link show/set`, `fdb show/get/add/append/del/replace/flush`, `vlan show/add/del` | `true` | Bridge-port flags, FDB state, VLAN ranges/flags, multicast-router data, and common bridge mutations. |
| `ip rule` | `show/list`, `add`, `delete`, `flush` | `true` | IPv4/IPv6 policy rules, selectors, actions, UID/port/protocol fields, and route-table references. |
| `ip ntable` | `show/list` | `true` | Reads neighbour-table parameters, configuration, statistics, and family/interface filters using typed raw route-netlink messages. |
| `ip stats` | `show/list` | `true` | `RTM_GETSTATS` link group with RX/TX counters and structured output. |
| `ip token` | `list/get`, `set`, `delete` | `true` | IPv6 tokenized interface identifiers. |
| `ip vrf` | `show/list`, `identify`, `pids` | `true` | Link inventory uses `IFLA_VRF_TABLE`; process queries read cgroup v2 `/vrf/NAME` associations and filter PIDs to the current netns. |
| `ip netns` | `list`, `add`, `delete`, `identify`, `pids`, `exec` | `true` | Named namespaces use the rtnetlink helper; PID/path selectors and inherited-stdio command execution are included. |
| `ip monitor` | link, address, route, rule, neighbour, nsid, stats, nexthop, bridge, mroute, all | `true` | Subscribes to route-netlink multicast groups and preserves events as parsed-message debug records. |

## Important partial surfaces

These are deliberately counted as implemented above, but callers should know
where the behavior is narrower than the C command.

- Route lightweight-tunnel input currently covers `mpls`, `seg6`, and `ip6`.
  The nested attributes are shown losslessly as a debug representation until
  the packet crate exposes a stable structured display API. `seg6local`,
  `ioam6`, `xfrm`, `rpl`, and `ila` are rejected with a clear error.
- `ip link` accepts the common typed link families already modeled by
  `netlink-packet-route`; driver-specific attributes are not guaranteed to be
  complete or portable across kernel versions.
- `ip monitor` accepts object names and all supported multicast groups, but
  does not yet implement iproute2's `label`, `file`, `dev`, or fine-grained
  stream filters. Its current output is intentionally a lossless `Debug`
  form, not a stable event schema.
- `ip stats set` is parsed but returns an explicit unsupported error. The
  currently exposed read-only link group is useful without changing device
  state; hardware/offload groups remain driver-specific.
- `ip vrf exec` is registered in the grammar and reports why it is not run.
  Correct behavior requires creating/managing a cgroup v2 hierarchy and
  loading a `BPF_CGROUP_INET_SOCK_CREATE` program, with capabilities and
  cgroup delegation that a normal route-netlink request does not provide.
- `ip route get vrf NAME` is represented as an output-interface constrained
  lookup. It is useful for normal VRF lookups, but is not a substitute for all
  of iproute2's process/cgroup VRF behavior.
- XDP object loading uses `libbpf-rs` first, so relocations, maps, and normal
  libbpf ELF handling work when the object is compatible with the installed
  libbpf. A small raw ELF loader remains as a fallback for simple objects;
  CO-RE fixture coverage is still follow-up work.

## Commands not implemented here

The following are intentionally outside the present implementation. These are
the blockers, rather than merely missing parser branches.

| Command or feature | Status | Main blocker or reason |
| --- | --- | --- |
| `ip nexthop` object management | Not implemented | Requires a dedicated typed `RTM_*NEXTHOP` API and object lifecycle semantics; route `nhid` references are supported separately. |
| `ip xfrm` | Not implemented | XFRM is a separate netlink family with policy/state/template messages not modeled by the route-netlink API. |
| `ip mptcp` | Not implemented | MPTCP uses generic netlink and has a distinct command/event schema. |
| `ip tc` / qdisc, class, filter, action management | Not implemented | Large traffic-control family with many binary, driver-specific, and nested attributes; it needs a generic-netlink/TC layer or a dedicated crate. |
| `ip addrlabel` | Not implemented | Address-label netlink messages are not exposed by the current high-level API. |
| `ip maddress` | Not implemented | Link multicast-address operations need their own request/attribute mapping. |
| `ip mroute` | Not implemented | Multicast routing uses specialized kernel tables and message semantics beyond ordinary route dumps. |
| `ip netconf` | Not implemented | Per-interface IPv4/IPv6 sysctl-like configuration has a separate netlink attribute family. |
| `ip tunnel` legacy management | Not implemented as a separate command | Common GRE/IPIP/VTI devices can be created through typed `ip link`; legacy tunnel-specific dump/config parity is not complete. |
| `ip fou`, `ip ila`, `ip l2tp` | Not implemented | Specialized generic-netlink families with no stable typed wrapper in this dependency set. |
| `ip macsec` policy/control | Not implemented as a separate command | Some link-level MACsec attributes exist, but full offload/SA/policy management is a different netlink surface. |
| Rich route encap (`seg6local`, `ioam6`, `xfrm`, `rpl`, `ila`) | Not implemented | Public packet types and exact kernel attribute nesting are missing or unstable in the current dependency. |
| `ip vrf exec` | Not implemented | Requires privileged cgroup v2 and cgroup-BPF setup, not just `setns(2)` or route-netlink. |
| `ip stats set` | Not implemented | Hardware statistics control is driver/kernel dependent and is not represented by the read-only `RTM_GETSTATS` path. |

The route-netlink portions that are absent from this list are generally
implemented at least in their common forms. Unsupported individual options
return an error instead of being silently ignored.

## Implementation process and completion fields

This is the coding map used for the current tree. It is kept here so future
work can be reviewed as a sequence of protocol boundaries rather than as a
large unstructured compatibility promise.

### Link and address families

- `ip link` — `[Completed: true]` Decode `RTM_GETLINK` messages into stable
  records; resolve names to indexes; route mutations through typed link
  handles; keep per-link-type parsing isolated in `src/ip/link/ifaces`; add
  stats/XDP/netns behavior at the edge.
- `ip address` — `[Completed: true]` Parse selectors into an address filter;
  use typed address requests for mutations and raw framed messages only for
  save/restore; retain unknown protocol values as hexadecimal output.
- `ip bridge` — `[Completed: true]` Keep bridge link, FDB, and VLAN operations
  separate because they use different message/attribute sets; map interface
  names before mutations and preserve flags in JSON.

### Routing and policy

- `ip route` — `[Completed: true]` Parse the node spec into a route config;
  build one typed route message for simple routes and nested `MultiPath`
  attributes for repeated `nexthop` clauses; use application-side prefix
  matching for `root`, `match`, and `exact`.
- `ip rule` — `[Completed: true]` Convert policy selectors/actions to route
  rule messages and decode both numeric and named tables; issue separate IPv4
  and IPv6 dumps when no family is selected.
- `ip neighbour` — `[Completed: true]` Resolve `dev`/`ifindex`, map NUD and
  neighbour flags, and implement flush as repeated acknowledged deletes.
- `ip ntable` — `[Completed: true]` Use a typed raw route-netlink request for
  neighbour-table messages because the high-level handle does not currently
  expose this operation.

### Namespaces, observability, and helpers

- `ip netns` — `[Completed: true]` Use the rtnetlink namespace helper for
  named create/delete, compare namespace inode pairs for identify/pids, and
  call `setns(2)` only inside a short-lived `exec` child process.
- `ip monitor` — `[Completed: true]` Subscribe to the selected multicast
  groups and print every decoded route-netlink payload, preserving forward
  compatibility with attributes not yet given a custom formatter.
- `ip stats` — `[Completed: true]` Request `RTM_GETSTATS`, decode the link
  group into RX/TX records, and reject mutation requests until a portable
  setter exists.
- `ip token` — `[Completed: true]` Read and update the IPv6 token nested in
  link address-family attributes.
- `ip vrf` — `[Completed: true for show/identify/pids]` Discover VRF links and
  route tables from link info; read cgroup v2 process associations; leave
  cgroup-BPF command execution as an explicit future boundary.

## Toolchain and native dependencies

The system Rust and rustup-managed Rust installations are both Rust 1.93.1
in this workspace. They are deliberately selected by absolute compiler paths
through `/home/avery/.config/zsh/rust-toolchains.zsh`; `RUST_HOME` is not a
toolchain switch and is not used. The helper also gives system and rustup
builds separate Cargo target directories, preventing stale artifacts from
crossing toolchains.

XDP object handling uses:

- the pinned `libbpf-rs = 0.26.0-beta.1` Rust API;
- `default-features = false`, so the crate links to the distro's system
  `libbpf` ABI rather than quietly selecting a second userspace build;
- the installed `libbpf-dev`, LLVM/Clang, and `libbpf-cargo` packages for
  native inspection and future CO-RE fixtures.

No additional apt development package is required for the implemented
route-netlink surface at this point. The deferred generic-netlink families
would benefit from typed packet crates before adding more native libraries.

## Nushell plugin assessment

The request/response portions are a good fit for a Nushell plugin: each
structured record can become a Nu record, and mutations can return an empty
pipeline with a useful error. The awkward cases are long-lived `monitor`
streams, inherited-stdio `netns exec`, binary save/restore, and XDP objects
that depend on external file descriptors and capabilities. Those should stay
available through the standalone binary even after the plugin wraps the
ordinary commands.

Three practical integration choices, scored for ease from 0 (hard) to 100
(easy), are:

1. Wrap the existing binary with a thin Nu plugin adapter — **92/100**.
   This gives immediate command coverage and preserves the Linux privilege
   behavior, at the cost of an extra process for each call.
2. Reuse the Rust request/config modules directly in `nu_plugin_ip` and map
   output structs to Nu values — **78/100**. This gives the best user
   experience but requires a stable internal API and careful async/runtime
   boundaries.
3. Keep the binary for mutations/streams and expose only read-only typed Nu
   commands first — **86/100**. This is the safest incremental rollout for
   monitor, namespace, and XDP edge cases, but it temporarily exposes a
   smaller plugin surface.

## Validation record

The relevant checks for this tree are:

```sh
cargo fmt --all -- --check
cargo check --locked
cargo test --lib --no-run --locked
cargo doc --no-deps --locked
git diff --check
```

Read-only smoke checks include `-j link show`, `-j route show`, `-j rule
show`, `-j ntable show`, `-j stats show`, `-j token list`, `-j vrf show`,
`netns list`, `netns identify self`, and `-n self -j link show`. Mutating
commands should be exercised only in a disposable namespace with the
appropriate capabilities.
