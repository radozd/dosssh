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

#ifndef DOSSSH_GLOBALS_H
#define DOSSSH_GLOBALS_H

#include <stddef.h>
#include <stdint.h>

#include "SSHNET.H"
#include "VT100.H"

#define HOSTNAME_MAX_LEN (64)

class UiScreen;

extern char g_hostArg[HOSTNAME_MAX_LEN];
extern uint16_t g_portArg;

extern MtcpTransport g_transport;
extern Vt100 g_terminal;
extern UiScreen g_screen;
extern const char *g_sshReason;

bool DosConfirmHost(const char *host, const char *fingerprint);
bool DosTrustHost(const unsigned char *hostKey, size_t keySize, const unsigned char hash[32]);
bool DosPassword(const char *username, char *password, size_t capacity);
bool DosChallenge(const char *username, const char *prompt, bool echo, char *response, size_t capacity);

/* DOS terminal access. Shell input: 0=idle, -1=detach, -2=fatal. */
void DosTerminalOutput(const unsigned char *bytes, size_t length);
int DosTerminalInput(unsigned char *buffer, size_t capacity);

#endif
