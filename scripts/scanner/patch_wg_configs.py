#!/usr/bin/env python3
"""
patch_wg_configs.py — Inject Table=off + manual ip-rule routing into all
WireGuard configs in /etc/wireguard/.

WHY:
  Scan #55 (2026-05-30) hung at `nft -f /dev/fd/63` for 4+ minutes during
  wg-quick up on a GH Actions Ubuntu runner. wg-quick uses nftables to
  install the ipv4 default-route catchall ("not fwmark 51820 → table
  51820") via an `nft` invocation. nftables can stall on hosted runners
  (kernel module load, lock contention, sandbox restrictions — pick one).

  The same logic works fine with `ip rule` — which is what wg-quick
  already uses for the ipv6 side of the same config (see lines 75-77 of
  the scan #55 bringup log). So we set Table=off (skip wg-quick's auto
  routing entirely) and do everything by hand via PostUp/PreDown.

  No more nft. No hang.

WHY THE STRIP STEP:
  Scan #56 (also 2026-05-30) failed at line 74 of the bringup log:
    iptables -I OUTPUT ! -o us-nyc -m mark ! --mark $(wg show us-nyc fwmark) ...
    iptables v1.8.10 (nf_tables): mark: bad integer value for option "--mark"
  Mullvad's web config generator ships a killswitch PostUp that uses
  $(wg show %i fwmark). With Table=off, wg-quick doesn't set fwmark, so
  the subshell returns "off" and iptables chokes. Also, Mullvad's PostUp
  runs BEFORE ours (their lines appear earlier in the [Interface] block).
  We strip the existing PostUp/PreDown lines from each conf before
  injecting ours — our PostUp sets fwmark first, so even if a killswitch
  is needed later it would have something to work with.

Idempotent: skips files already containing "Table = off".
"""
from __future__ import annotations
import glob
import sys

EXTRAS = """\
Table = off
PostUp = wg set %i fwmark 51820
PostUp = ip -6 rule add not fwmark 51820 table 51820
PostUp = ip -6 rule add table main suppress_prefixlength 0
PostUp = ip -6 route add ::/0 dev %i table 51820
PostUp = ip -4 rule add not fwmark 51820 table 51820
PostUp = ip -4 rule add table main suppress_prefixlength 0
PostUp = ip -4 route add 0.0.0.0/0 dev %i table 51820
PreDown = ip -4 route del 0.0.0.0/0 dev %i table 51820
PreDown = ip -4 rule del table main suppress_prefixlength 0
PreDown = ip -4 rule del not fwmark 51820 table 51820
PreDown = ip -6 route del ::/0 dev %i table 51820
PreDown = ip -6 rule del table main suppress_prefixlength 0
PreDown = ip -6 rule del not fwmark 51820 table 51820
"""


def main() -> int:
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "/etc/wireguard"
    confs = sorted(glob.glob(f"{target_dir}/*.conf"))
    if not confs:
        print(f"no .conf files in {target_dir} — nothing to patch", file=sys.stderr)
        return 1

    patched, skipped = 0, 0
    for path in confs:
        with open(path) as f:
            content = f.read()

        if "Table = off" in content:
            print(f"already patched: {path}")
            skipped += 1
            continue

        if "[Peer]" not in content:
            print(f"WARN: no [Peer] section in {path} — skipping", file=sys.stderr)
            continue

        # Strip any existing PostUp / PreDown lines from the [Interface]
        # block. Mullvad's killswitch PostUp uses $(wg show %i fwmark),
        # which returns "off" when Table=off — and iptables can't parse
        # "off" as a mark integer. We replace them with our own.
        lines = content.splitlines()
        kept: list[str] = []
        stripped_count = 0
        in_interface = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("["):
                in_interface = stripped == "[Interface]"
                kept.append(line)
                continue
            if in_interface and (
                stripped.startswith("PostUp")
                or stripped.startswith("PreUp")
                or stripped.startswith("PreDown")
                or stripped.startswith("PostDown")
                or stripped.startswith("Table")
                # Drop DNS too — we install wg + wg-quick only (no
                # resolvconf, no openresolv). If DNS= is present,
                # wg-quick tries to invoke resolvconf and fails. The
                # runner already has working Azure DNS; we don't need
                # to override it for scan traffic to route through
                # the tunnel.
                or stripped.startswith("DNS")
            ):
                stripped_count += 1
                continue  # drop it
            kept.append(line)
        content = "\n".join(kept)
        if stripped_count:
            print(f"  stripped {stripped_count} existing PostUp/PreDown/Table line(s) from {path}")

        # Insert EXTRAS into the [Interface] section, just before [Peer].
        new_content = content.replace("[Peer]", EXTRAS + "\n[Peer]", 1)

        with open(path, "w") as f:
            f.write(new_content)
        print(f"patched: {path}")
        patched += 1

    print(f"\nsummary: {patched} patched, {skipped} already-patched, "
          f"{len(confs)} total")
    return 0


if __name__ == "__main__":
    sys.exit(main())
