/*
	DOSSSH - SSHv2 client for MS-DOS (16-bit real mode).
	Copyright (C) 2026 Konstantin Bortnikov

	This file is part of DOSSSH.

	DOSSSH is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	DOSSSH is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with DOSSSH. If not, see <https://www.gnu.org/licenses/>.
*/

#include <conio.h>
#include <ctype.h>
#include <errno.h>
#include <dos.h>
#include <mem.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "types.h"
#include "utils.h"
#include "timer.h"
#include "inlines.h"

#include "SSHSHA.H"
#include "SSHCRYPT.H"
#include "SSHENT.H"
#include "SSHPKT.H"
#include "SSHSCAN.H"
#include "VT100.H"
#include "SSHNET.H"
#include "CONFIG.H"
#include "UTIL.H"
#include "ENCODING.H"
#include "DEBUG.H"
#include "GLOBALS.H"

#define USERNAME_MAX_LEN (64)

char g_hostArg[HOSTNAME_MAX_LEN];
uint16_t g_portArg;
static char g_userArg[USERNAME_MAX_LEN];
bool g_debugArg = false;

MtcpTransport g_transport;
const char *g_sshReason = "SSH connection failed";

static SSHCRYPT_RNG g_rng;
static SSHSCAN_Session g_session;
static char g_username[129];

/* ------------------------------------------------------------------------- */
static bool ParseHostPort(const char *src)
{
	char tmp[HOSTNAME_MAX_LEN];
	if( strlen(src) >= sizeof(tmp) )
		return false;

	CopyTrunc(tmp, sizeof(tmp), src);

	g_portArg = SSH_DEFAULT_PORT;

	char *colon = strrchr(tmp, ':');
	if( colon != NULL )
	{
		char *p = colon + 1;
		if( *p == '\0' )
			return false;

		while( *p != '\0' )
		{
			if( !isdigit((unsigned char)*p) )
				return false;
			p++;
		}

		long val = atol(colon + 1);
		if( val <= 0 || val > 65535 )
			return false;

		*colon = '\0';
		if( tmp[0] == '\0' )
			return false;

		g_portArg = (uint16_t)val;
	}

	CopyTrunc(g_hostArg, sizeof(g_hostArg), tmp);
	return g_hostArg[0] != '\0';
}

static bool ParseArgs(int argc, char *argv[])
{
	bool host_set = false;

	g_hostArg[0] = '\0';
	g_userArg[0] = '\0';
	g_portArg = SSH_DEFAULT_PORT;
	g_debugArg = false;

	if( argc < 2 )
		return false;

	for( int i = 1; i < argc; i++ )
	{
		const char *arg = argv[i];

		if( strcmp(arg, "-debug") == 0 )
			g_debugArg = true;
		else if( strcmp(arg, "-u") == 0 )
		{
			if( i > argc - 2 )
				return false;

			i++;
			CopyTrunc(g_userArg, sizeof(g_userArg), argv[i]);
			if( g_userArg[0] == '\0' )
				return false;
		}
		else if( arg[0] == '-' )
			return false;
		else
		{
			if( host_set )
				return false;

			if( !ParseHostPort(arg) )
				return false;

			host_set = true;
		}
	}

	return host_set;
}

/* ------------------------------------------------------------------------- */
Vt100 g_terminal;
/* ------------------------------------------------------------------------- */
#include "UISCREEN.CPP"
UiScreen g_screen;
/* ------------------------------------------------------------------------- */
#include "DEBUG.CPP"
/* ------------------------------------------------------------------------- */
#include "UITERM.CPP"
static UiTerminal g_uiTerminal;

void DosTerminalOutput(const unsigned char *bytes, size_t length)
{
	g_uiTerminal.Output(bytes, length);
}

int DosTerminalInput(unsigned char *buffer, size_t capacity)
{
	return g_uiTerminal.Input(buffer, capacity);
}
/* ------------------------------------------------------------------------- */
static void RestoreVideo()
{
	if( g_screen.IsCaptured() )
	{
		g_transport.SetInteractive(false);
		g_screen.Restore();
	}
}

static int SshRun(const char *programPath)
{
	volatile unsigned long far *ticks = (volatile unsigned long far *)MK_FP(0x40, 0x6C);
	unsigned long start = *ticks;
	if( !SshEntropy::Initialize(g_rng, programPath) )
	{
		Log('E', "No usable cryptographic seed; SSH connection cancelled.");
		return 1;
	}

	unsigned long end = *ticks;
	unsigned long entropy_ticks = end >= start ? end - start : TIMER_TICKS_PER_DAY - start + end;
	if( !g_transport.Start() )
	{
		Log('E', "mTCP setup failed. Check MTCPCFG and packet driver.");
		return 1;
	}

	Log('I', "Entropy %lu ticks", entropy_ticks);
	{
		char connect_name[80];
		SprintfTrunc(connect_name, sizeof(connect_name), "Connecting %s", g_hostArg);
		LongOp connect_op(connect_name);
		if( !g_transport.ConnectHost(g_hostArg, g_portArg) )
			return 1;
	}

	char server_ident[SSHSCAN_ID_SIZE];
	if( !SshScanSendIdent(TIMER_SECS_TO_TICKS(5)) )
	{
		Log('E', "Cannot send SSH client identification");
		return 1;
	}
	if( !SshScanIdent(server_ident, sizeof(server_ident), TIMER_SECS_TO_TICKS(15)) )
	{
		Log('E', "Invalid SSH server identification");
		return 1;
	}

	Log('I', "Peer %s", server_ident);
	if( !SshScanExchangeTofu(server_ident, g_rng, g_session, TIMER_SECS_TO_TICKS(30)) )
	{
		Log('E', "SSH initial KEX failed: %s", g_sshReason);
		return 1;
	}

	// One-hour automatic rekey
	g_session.rekeyPeriodTicks = TIMER_SECS_TO_TICKS(3600);
	if( g_userArg[0] )
	{
		if( !DosOemString(g_userArg, g_username, sizeof(g_username)) )
		{
			Log('E', "Invalid username or too long");
			return 1;
		}
	}
	else if( !DosUsername(g_username, sizeof(g_username)) )
	{
		Log('E', "Username entry cancelled");
		return 1;
	}

	Log('I', "Auth user=%s", g_username);
	{
		SshAuthenticator authenticator(g_session, g_rng, g_username, TIMER_SECS_TO_TICKS(30));
		if( !authenticator.Login() )
		{
			Log('E', "Authentication failed: %s", g_sshReason);
			return 1;
		}
	}

	if( !g_screen.Init() )
		return 1;
	if( !g_terminal.Init(g_screen.Cols(), g_screen.Rows()) )
	{
		Log('E', "Cannot initialize DOS text screen");
		return 1;
	}

	g_screen.Capture();
	if( !g_screen.IsCaptured() )
	{
		Log('E', "Cannot initialize DOS text screen");
		return 1;
	}

	g_terminal.Reset();
	g_screen.Draw();

	g_uiTerminal.Start();

	if( DebugEnabled() )
	{
		char memory_report[80];
		ProbeFreeMem(memory_report, sizeof(memory_report));
		Log('I', "Memory %s", memory_report);
	}

	DosFlushKeys();
	g_transport.SetInteractive(true);
	// xterm defines F1-F12 in both video modes. Its basic 8 colours
	// plus bright foreground fit the 16-colour CGA/EGA/VGA palette;
	// UiScreen maps output to monochrome attributes for MDA.
	bool ok = SshScanShell(g_session, g_rng, g_screen.Cols(), g_screen.Rows(),
		"xterm", TIMER_SECS_TO_TICKS(30));

	RestoreVideo();
	Log('I', "Shell result=%d exit=%d code=%lu", ok, g_session.exitStatusReceived, g_session.exitStatus);
	if( !ok )
	{
		Log('E', "Shell failed: %s", g_sshReason);
		return 1;
	}

	return g_session.exitStatusReceived ? (int)(g_session.exitStatus & 255ul) : 0;
}

static void SshCleanup()
{
	RestoreVideo();
	if( g_transport.Aborted() )
		Log('E', "Interrupted");
	g_transport.Stop();
	g_session.Clear();
	g_rng.Clear();
	SshCrypt::Zero(g_username, sizeof(g_username));
}

unsigned int Cpu386();
#pragma aux Cpu386 = \
    "pushf"               \
    "pop bx"              \
    "mov ax, bx"          \
    "xor ax, 4000h"       \
    "push ax"             \
    "popf"                \
    "pushf"               \
    "pop ax"              \
    "xor ax, bx"          \
    "and ax, 4000h"       \
    "push bx"             \
    "popf"                \
    value [ax]            \
    modify exact [ax bx] nomemory;

int main(int argc, char *argv[])
{
	printf("DOSSSH by Konstantin Bortnikov (radozd@ya.ru) (C)opyright 2026\nVersion: " DOSSSH_VERSION ", " __DATE__ "\n");
	if( !Cpu386() )
	{
		printf("DOSSSH requires 80386 or newer CPU.\n");
		return 1;
	}

	if( !ParseArgs(argc, argv) )
	{
		printf("Usage: DOSSSH <host[:port]> [-u user] [-debug]\n");
		printf("  host[:port]  DNS hostname or IPv4 address (default port 22)\n");
		printf("  -u user      Login name (prompted if omitted)\n");
		printf("  Password is always prompted without echo after host verification.\n");
		printf("  -debug       Write SSH events, network counters and SECRET keys to DOSSSH.LOG\n");
		printf("First connection: verify the host fingerprint, then type yes to trust.\n");
		printf("Trust + RNG state: C:\\DOSSSH.DAT (or program drive).\n");
		printf("Alt+X disconnects from the remote shell.\n");
		return 1;
	}

	InitDosCharset();

	InitDebug();
	LongOp::StartTimer();

	int result = SshRun(argv[0]);
	SshCleanup();

	LongOp::StopTimer();
	StopDebug();

	return result;
}
