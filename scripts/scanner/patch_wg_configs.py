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
