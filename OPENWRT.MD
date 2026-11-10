# OpenWrt: change the upstream Wi-Fi

DOSSSH lets a DOS PC manage an OpenWrt router over Ethernet, including when
its upstream Wi-Fi hotspot changes. mTCP setup is covered by [mTCP](https://www.brutman.com/mTCP/).

## Dropbear: the 12 KB "optimization"

**DOSSSH requires an `ssh-ed25519` server host key.** OpenWrt disables
Ed25519 by default in Dropbear builds for `SMALL_FLASH` devices, reportedly
to save about **12 KB** on MIPS, while retaining RSA. Twelve kilobytes saved!
A modern, compact algorithm gets thrown overboard; venerable RSA stays.
Outstanding priorities for a secure remote-access service. RSA-SHA2 is not
inherently insecure; **this compatibility decision is the problem**.
Please [raise it with OpenWrt developers](https://openwrt.org/contact).

Sources: [build option](https://git.openwrt.org/openwrt/openwrt/tree/package/network/services/dropbear/Config.in),
[12 KB rationale](https://lists.openwrt.org/pipermail/openwrt-devel/2020-July/030477.html).

Check for a server key via another management connection:

```sh
ls /etc/dropbear/*ed25519*host_key
```

If absent, and the installed Dropbear supports Ed25519, generate it:

```sh
dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key
/etc/init.d/dropbear restart
```

A missing key alone does not prove missing support. If `dropbearkey` does not
support Ed25519, use firmware built with it. Restarting Dropbear may disconnect SSH.

## Change the hotspot

**Connect via Ethernet/LAN**, not through the Wi-Fi being changed:

```bat
DOSSSH.EXE 192.168.2.1 -u root
```

Use your router's LAN IP address. Find its *client* Wi-Fi section:

```sh
uci show wireless | grep '\.mode='
```

Look for `mode='sta'` (client), **not** `mode='ap'` (access point).
In the example below, replace `[1]` with the correct index; some sections
have names instead. Verify the mode before making changes.

```sh
STA='wireless.@wifi-iface[1]'
uci -q get "${STA}.mode"       # must print: sta
cp /etc/config/wireless /etc/config/wireless.bak

uci set "${STA}.ssid=NewHotspot"
uci set "${STA}.key=NewPassword123"
uci set "${STA}.encryption=psk2"
uci -q delete "${STA}.bssid"   # remove old AP MAC binding, if any
uci commit wireless
wifi reload
```

`psk2` is WPA2-Personal. For WPA3 use `sae` if supported; see
[OpenWrt encryption modes](https://openwrt.org/docs/guide-user/network/wifi/encryption).
The Wi-Fi link will reconnect; the Ethernet session should remain available.

Check the result:

```sh
wifi status
uci -q get "${STA}.network"   # often: wwan
ifstatus wwan                 # substitute the actual network name
```

**Rollback if needed** (while still connected over Ethernet):

```sh
cp /etc/config/wireless.bak /etc/config/wireless
wifi reload
```

The backup contains Wi-Fi passwords; do not share it. If DOSSSH reports a
changed SSH host key after reinstalling OpenWrt, verify the new fingerprint
independently before typing `override`.
