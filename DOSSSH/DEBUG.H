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

#ifndef DOSSSH_DEBUG_H
#define DOSSSH_DEBUG_H

#include <stddef.h>

void DebugRequest(bool enabled);
void DebugOpen();
bool DebugIsOn();
void DebugStopped();

/* All types are written to DOSSSH.LOG only with -debug. Before the
 * screen is captured, only E=error is also printed to the console.
 * I=information, W=warning, N=network, S=stage, P=packet, K=key.
 * LongOp displays its own status independently of -debug. */
void Log(char type, const char *format, ...);

/* A scoped timer. INT 1Ch updates only the digits in text video memory;
 * the destructor leaves the completed line on screen. No user input inside. */
class LongOp
{
public:
	// Hook before mTCP starts; unhook after mTCP stops.
	static void StartTimer();
	static void StopTimer();

	explicit LongOp(const char *name);
	~LongOp();

private:
	static void Show();
	const char *_name;
	LongOp *_previous;
	unsigned long _started;

	LongOp(const LongOp &);
	LongOp &operator=(const LongOp &);
};

void DebugHex(const char *name, const unsigned char *bytes, size_t length);
void DebugPacket(const char *direction, int type, size_t length, unsigned long sequence);

#endif
