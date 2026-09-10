# `ip-rs` overview

`ip-rs` is a Linux-focused Rust implementation of the most useful parts of
the `ip` command. The diagram below shows the implemented command families,
their functional scope, the primary library or kernel interface behind each
one, and a small sample of the available syntax.

This is an overview rather than an exhaustive grammar. For detailed coverage,
limitations, and deferred command families, see
[`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md).

```mermaid
flowchart LR
    IP["<b>ip-rs</b><br/>Linux route-netlink CLI<br/>typed requests · text / JSON / YAML"]

    subgraph state["Interface and address state"]
        direction LR
        LINK["<b>link</b><br/>interfaces, virtual devices,<br/>XDP, statistics<br/><i>Library:</i> rtnetlink + libbpf-rs<br/><i>Toolchain:</i> [ Rust + XDP ]<br/><i>Taste:</i> show · add · set · xdp · -s"]
        ADDRESS["<b>address</b><br/>IPv4/IPv6 addresses,<br/>lifetimes, filters, dumps<br/><i>Library:</i> rtnetlink<br/><i>Toolchain:</i> [ Rust + route-netlink ]<br/><i>Taste:</i> show · add · replace · flush · proto"]
        BRIDGE["<b>bridge</b><br/>bridge ports, FDB,<br/>VLAN membership<br/><i>Library:</i> rtnetlink + netlink-packet-route<br/><i>Toolchain:</i> [ Rust + bridge netlink ]<br/><i>Taste:</i> link · fdb · vlan · add · flush"]
    end

    subgraph routing["Routing and policy"]
        direction LR
        ROUTE["<b>route</b><br/>routes, gateways, metrics,<br/>multipath, encapsulation<br/><i>Library:</i> rtnetlink + netlink-packet-route<br/><i>Toolchain:</i> [ Rust + route-netlink ]<br/><i>Taste:</i> show · add · get · nexthop · metric"]
        NEIGH["<b>neighbour</b><br/>ARP/NDP entries,<br/>NUD states, MAC mappings<br/><i>Library:</i> rtnetlink<br/><i>Toolchain:</i> [ Rust + route-netlink ]<br/><i>Taste:</i> show · add · replace · nud · flush"]
        RULE["<b>rule</b><br/>policy routing,<br/>marks, UIDs, ports<br/><i>Library:</i> rtnetlink + netlink-packet-route<br/><i>Toolchain:</i> [ Rust + policy routing ]<br/><i>Taste:</i> show · add · del · fwmark · priority"]
        NTABLE["<b>ntable</b><br/>neighbour-table parameters,<br/>thresholds and statistics<br/><i>Library:</i> rtnetlink raw route messages<br/><i>Toolchain:</i> [ Rust + route-netlink ]<br/><i>Taste:</i> show · list · family · dev · name"]
    end

    subgraph helpers["Observability and namespace helpers"]
        direction LR
        STATS["<b>stats</b><br/>RTM_GETSTATS link<br/>RX/TX counters<br/><i>Library:</i> rtnetlink + netlink-packet-route<br/><i>Toolchain:</i> [ Rust + RTM_GETSTATS ]<br/><i>Taste:</i> show · dev · group · subgroup · suite"]
        TOKEN["<b>token</b><br/>IPv6 tokenized<br/>interface identifiers<br/><i>Library:</i> rtnetlink<br/><i>Toolchain:</i> [ Rust + IPv6 link attrs ]<br/><i>Taste:</i> list · get · set · delete · dev"]
        VRF["<b>vrf</b><br/>VRF devices, route tables,<br/>process associations<br/><i>Library:</i> rtnetlink + /proc + cgroup v2<br/><i>Toolchain:</i> [ Rust + VRF + cgroup v2 ]<br/><i>Taste:</i> show · identify · pids · NAME · PID"]
        NETNS["<b>netns</b><br/>named namespaces,<br/>PID lookup, setns exec<br/><i>Library:</i> rtnetlink + nix<br/><i>Toolchain:</i> [ Rust + Linux namespaces ]<br/><i>Taste:</i> list · add · delete · identify · exec"]
        MONITOR["<b>monitor</b><br/>live route-netlink<br/>multicast events<br/><i>Library:</i> rtnetlink multicast connection<br/><i>Toolchain:</i> [ Rust + netlink multicast ]<br/><i>Taste:</i> link · address · route · rule · all"]
    end

    LINK --> IP
    ADDRESS --> IP
    BRIDGE --> IP
    ROUTE --> IP
    NEIGH --> IP
    RULE --> IP
    IP --> NTABLE
    IP --> STATS
    IP --> TOKEN
    IP --> VRF
    IP --> NETNS
    IP --> MONITOR

    classDef core fill:#fff4d6,stroke:#8a6418,stroke-width:3px,color:#201600;
    classDef command fill:#eef6ff,stroke:#42739b,stroke-width:1.5px,color:#10202c;
    classDef stateGroup fill:#f7fbff,stroke:#a9c7dc,stroke-dasharray:5 5,color:#10202c;
    classDef routingGroup fill:#f8f7ff,stroke:#b7afd8,stroke-dasharray:5 5,color:#18132d;
    classDef helperGroup fill:#f7fff8,stroke:#acd0b2,stroke-dasharray:5 5,color:#142318;

    class IP core;
    class LINK,ADDRESS,BRIDGE,ROUTE,NEIGH,RULE,NTABLE,STATS,TOKEN,VRF,NETNS,MONITOR command;
    class state stateGroup;
    class routing routingGroup;
    class helpers helperGroup;
```

## Global options shared by the command families

These are applied at the `ip-rs` level and are intentionally not repeated in
every command box:

| Option | Purpose |
| --- | --- |
| `-j` / `--json` | Structured JSON output. |
| `-y` / `--yaml` | Structured YAML output. |
| `-d` | More interface or route details. |
| `-s` / `--stats` | Statistics where the selected command supports them. |
| `-4`, `-6`, `-B`, `-0` | Select IPv4, IPv6, bridge, or link-layer families. |
| `-o` / `--oneline` | Keep each displayed record on one line. |
| `-b` / `--brief` | Use brief output; `-br` is accepted as an alias. |
| `-n` / `--netns` | Execute the request in a named, PID, or path-selected network namespace. |

The diagram covers implemented command families; specialized families such as
`ip nexthop`, `ip xfrm`, `ip mptcp`, full `ip tc`, `ip mroute`, and `ip vrf
exec` remain documented as deferred in the implementation status file.
