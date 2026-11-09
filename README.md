# `ip-rs`: Linux route-netlink CLI

`ip-rs` is a Linux-focused Rust implementation of the most useful parts of
the `ip` command. It translates compatibility-oriented command lines into
typed `rtnetlink` requests and renders text, JSON, or YAML output. The binary
is intended to be useful both as a standalone command and as a foundation for
the `nu_plugin_ip` Nushell project.

The current implementation covers address, link, route, bridge, neighbour,
policy-rule, neighbour-table, link-statistics, IPv6 token, VRF inventory and
process association, network namespaces, and netlink monitoring. It also
loads XDP programs through `libbpf-rs`, with a small raw-ELF fallback for
objects that the system libbpf cannot open. Kernel capabilities, loaded
modules, cgroup-BPF support, and the active network namespace still determine
which operations can succeed.

See [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) for the command
coverage matrix, remaining gaps, blockers, and the validation commands used
for this release.

## Examples

```sh
ip-rs -j link show
ip-rs -j bridge link show
ip-rs -j rule show
ip-rs -j ntable show
ip-rs -j neighbour show nud all
ip-rs -j stats show dev lo group link
ip-rs -j token list
ip-rs -j vrf show
ip-rs -j vrf identify
ip-rs -n self -j link show
ip-rs monitor link route
```

The XDP loader uses the distribution's `libbpf` through the pinned
`libbpf-rs` API (`default-features = false`), so the system development package
and `libbpf-cargo` are preferred over a second vendored userspace copy. Build
with the repository's selected Rust 1.93 toolchain and run read-only checks
with `target/debug/ip-rs` after a build. Namespace-changing and link/route
mutations require the normal Linux privileges.

Goal of this project:
 * Drop-in replacement of [iproute][iproute_url].
 * Drop-in replacement of [ethtool][ethtool_url].
 * Drop-in replacement of [iw][iw_url].
 * Be catalyst of rust-netlink becomes API stable.
 * Be catalyst of rust-netlink becomes feature complete.
 * Be example code for using rust-netlink crates.

[iproute_url]: https://git.kernel.org/pub/scm/network/iproute2/iproute2.git
[ethtool_url]: https://www.kernel.org/pub/software/network/ethtool/
[iw_url]: https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw.html
