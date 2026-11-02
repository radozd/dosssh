# Building DOSSSH

DOSSSH is a 16-bit MS-DOS program built with Open Watcom 1.9. It uses the
large memory model and requires a 386 or newer CPU, but not a 387.

## Requirements

- Open Watcom 1.9 with its environment configured
- the mTCP source tree in `mTCP/`
- an mTCP-compatible packet driver on the target DOS machine

The source archive includes mTCP. If you cloned the Git repository, initialize
the submodule first:

```text
git submodule update --init --recursive
```

## Build

In the `DOSSSH/` directory run:

```bat
BUILD.BAT
```

This removes old build files and runs `wmake dosssh.exe`.
The result is `DOSSSH.EXE` and a linker map.

For an incremental build or cleanup, use:

```bat
wmake -f MAKEFILE
wmake -f MAKEFILE clean
```

The linker picks up all `*.OBJ` files in the build directory, so keep unrelated
object files out of it.

## Running

Copy `DOSSSH.EXE` to the DOS machine, load the packet driver and set `MTCPCFG`
to your mTCP runtime configuration:

```bat
SET MTCPCFG=C:\MTCP.CFG
DOSSSH.EXE 192.168.1.1 -u root
```

`DOSSSH.CFG` in the source directory is a build-time header, not the mTCP
runtime configuration. See [README.MD](README.MD) for usage and limitations.
