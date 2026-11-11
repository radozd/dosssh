DOSSSH - SSH terminal for MS-DOS

DOSSSH is a simple SSHv2 terminal for 386 and newer DOS computers.
It was written to configure an OpenWrt Wi-Fi router directly from DOS,
but it can also connect to other compatible SSH servers.
Its terminal emulation is sufficient for Midnight Commander and
common command-line utilities.

You need MS-DOS 5.0+, an mTCP-compatible packet driver, a working
mTCP configuration and a server offering the supported SSH algorithms.

Supported SSH algorithms (all required on the server):
  Key exchange: curve25519-sha256
  Host key:     ssh-ed25519
  Cipher:       aes128-ctr
  MAC:          hmac-sha2-256

Example:
  SET MTCPCFG=C:\MTCP.CFG
  DOSSSH.EXE 192.168.1.1 -u root

Usage:
  DOSSSH <host[:port]> [-u user] [-debug]

Port 22 is the default. The username and password can be prompted for.
Press Alt+X to disconnect.

DOSSSH must collect random data for SSH. It mixes system and disk timing
information; on first use it also tries mouse movements or irregularly
timed keypresses. Follow the prompts.
Esc cancels the setup. See README.MD for how this works and its limits.

The random seed and trusted host keys are saved in C:\DOSSSH.DAT, or on
the launch drive (A: or B:) if C: is unavailable. Keep the file writable.
Verify the server fingerprint independently before typing yes.
If a saved host key changes, DOSSSH shows the old and new fingerprints.
Verify the new one independently before typing override to replace
the stored key. Typing yes is not enough in this case.

DOSSSH is a hobby project and has not had an independent security audit.
WARNING: -debug writes SECRET session keys to DOSSSH.LOG. Do not share it.

For file transfers, see FTP2P. For details, see README.MD in the
source archive.
