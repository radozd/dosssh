# Origin and credits

DOSSSH is a separate SSH terminal for MS-DOS, built with some code and ideas
from earlier projects.

## mTCP

Networking is based on [mTCP](https://github.com/mbbrutman/mTCP) by Michael B.
Brutman. Its source tree is required for building DOSSSH and retains its own
copyright and license notices. Git checkouts use an mTCP submodule; the source
archive includes the files.

## FTP2P

DOSSSH shares some utility, keyboard, character encoding and screen code with
[FTP2P](https://github.com/radozd/ftp2p) by the same author. The two programs
are independent: FTP2P transfers files; DOSSSH provides an SSH terminal.

## SSH and cryptography

[SSH2DOS](https://github.com/AnttiTakala/SSH2DOS), originally by Daniel Nagy
and later updated by Antti Takala, was a reference for SSH authentication and
channels. The [Toyoyo fork](https://github.com/Toyoyo/ssh2dos) was also used as
a reference for Ed25519 and X25519. DOSSSH is not a port of SSH2DOS.

The Ed25519 field arithmetic comes from the public-domain SUPERCOP/ref10 work
of Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe and Bo-Yin Yang.
See `DOSSSH/SSHCRYPT.CPP` for attribution. The exact history of some
intermediate adaptations is not known.

AI tools assisted with some cryptographic tests during development. This does
not constitute an independent security audit.

## License

The DOSSSH application is available under GPL v3 or later. See `LICENSE`.
mTCP keeps its original notices in `mTCP/LICENSE`.
