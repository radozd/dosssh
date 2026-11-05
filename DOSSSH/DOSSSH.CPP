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

#include <bios.h>
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

#define HOSTNAME_MAX_LEN (64)
#define USERNAME_MAX_LEN (64)

static char g_hostArg[HOSTNAME_MAX_LEN];
static uint16_t g_portArg;
static char g_userArg[USERNAME_MAX_LEN];
static bool g_debugArg = false;

/* ------------------------------------------------------------------------- */
#include "UTIL.CPP"

static bool ParseHostPort(const char *src)
{
	char tmp[HOSTNAME_MAX_LEN];
	if( src == NULL || strlen(src) >= sizeof(tmp) )
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


#include "ENCODING.CPP"
/* ------------------------------------------------------------------------- */
static Vt100 g_terminal;
#include "UISCREEN.CPP"
static UiScreen g_screen;
#include "DEBUG.CPP"
/* ------------------------------------------------------------------------- */
#include "UITERM.CPP"
/* ------------------------------------------------------------------------- */
#include "UIAPP.CPP"
static UiApp g_app;

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

	DebugRequest(g_debugArg);
	InitDosCharset();
	DebugOpen();
	LongOp::StartTimer();
	int result = g_app.Run(argv[0]);
	g_app.Cleanup();
	LongOp::StopTimer();
	DebugStopped();

	return result;
}
