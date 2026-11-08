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
#include <dos.h>
#include <string.h>

#include "inlines.h"

#include "INPUT.H"
#include "SSHCRYPT.H"

// Keyboard

int KeyAscii(uint16_t key)
{
	return key & 0x00FF;
}

bool DosKeyReady()
{
	return biosIsKeyReady();
}

uint16_t DosKeyRead()
{
	return biosKeyRead();
}

void DosFlushKeys()
{
	while( DosKeyReady() )
		DosKeyRead();
}

unsigned char KeyboardModifiers()
{
	union REGS regs;
	regs.h.ah = 0x02;
	int86(0x16, &regs, &regs);
	unsigned char flags = regs.h.al;
	return (unsigned char)(((flags & 0x03u) ? VT_KEY_SHIFT : 0u) |
		((flags & 0x04u) ? VT_KEY_CTRL : 0u) |
		((flags & 0x08u) ? VT_KEY_ALT : 0u));
}

BiosKeyBuffer::BiosKeyBuffer()
{
	_head = 0;
	_count = 0;
}

BiosKeyBuffer::~BiosKeyBuffer()
{
	SshCrypt::Zero(_keys, sizeof(_keys));
}

void BiosKeyBuffer::Clear()
{
	SshCrypt::Zero(_keys, sizeof(_keys));
	_head = 0;
	_count = 0;
}

bool BiosKeyBuffer::Push(uint16_t code, unsigned char modifiers)
{
	if( _count == Capacity )
		return false;

	size_t tail = (_head + _count) % Capacity;
	_keys[tail].code = code;
	_keys[tail].modifiers = modifiers;
	_count++;
	return true;
}

int BiosKeyBuffer::Poll()
{
	int result = 0;
	while( DosKeyReady() )
	{
		unsigned char modifiers = KeyboardModifiers();
		uint16_t key = DosKeyRead();
		if( (key & 255u) == 0 && ((key >> 8) & 255u) == 0x2Du )
			return -1; // Alt+X: always local
		if( !Push(key, modifiers) )
			result = 1;
	}
	return result;
}

bool BiosKeyBuffer::Peek(Key &key) const
{
	if( _count == 0 )
		return false;

	key = _keys[_head];
	return true;
}

void BiosKeyBuffer::Pop()
{
	if( _count == 0 )
		return;

	_keys[_head].code = 0;
	_keys[_head].modifiers = 0;
	_head = (_head + 1u) % Capacity;
	_count--;
}

// Mouse

static unsigned int g_mouseCols = 0;
static unsigned int g_mouseRows = 0;
static unsigned int g_mouseX = 0;
static unsigned int g_mouseY = 0;
static unsigned int g_mouseButtons = 0;

struct DosMouseState
{
	unsigned int x;
	unsigned int y;
	unsigned int buttons;
};

bool DosMouseInit()
{
	union REGS regs;
	struct SREGS segregs;
	memset(&regs, 0, sizeof(regs));
	memset(&segregs, 0, sizeof(segregs));
	regs.x.ax = 0x3533;
	intdosx(&regs, &regs, &segregs);
	if( (segregs.es == 0 && regs.x.bx == 0) || *(const unsigned char far *)MK_FP(segregs.es, regs.x.bx) == 0xCF )
		return false;

	memset(&regs, 0, sizeof(regs));
	int86(0x33, &regs, &regs);
	if( regs.x.ax != 0xFFFFu )
		return false;

	return true;
}

void DosMouseCursor(bool visible)
{
	union REGS regs;
	memset(&regs, 0, sizeof(regs));
	regs.x.ax = visible ? 1u : 2u;
	int86(0x33, &regs, &regs);
}

void DosMouseMotion(int &dx, int &dy)
{
	union REGS regs;
	memset(&regs, 0, sizeof(regs));
	regs.x.ax = 0x000B;
	int86(0x33, &regs, &regs);
	dx = (short)regs.x.cx;
	dy = (short)regs.x.dx;
}

static void DosMouseReadState(DosMouseState &state)
{
	union REGS regs;
	memset(&regs, 0, sizeof(regs));
	regs.x.ax = 0x0003;
	int86(0x33, &regs, &regs);
	state.x = regs.x.cx / 8u;
	state.y = regs.x.dx / 8u;
	state.buttons = regs.x.bx & 7u;
	if( g_mouseCols && state.x >= g_mouseCols )
		state.x = g_mouseCols - 1u;
	if( g_mouseRows && state.y >= g_mouseRows )
		state.y = g_mouseRows - 1u;
}

void DosMouseSync()
{
	DosMouseState state;
	DosMouseReadState(state);
	g_mouseX = state.x;
	g_mouseY = state.y;
	g_mouseButtons = state.buttons;
}

bool DosMousePoll(DosMouseEvent &event)
{
	DosMouseState state;
	DosMouseReadState(state);
	unsigned int changed = (g_mouseButtons ^ state.buttons) & 7u;
	event.button = 0;
	if( changed )
	{
		unsigned int bit = (changed & 1u) ? 1u : ((changed & 4u) ? 4u : 2u);
		event.button = bit == 1u ? 0u : (bit == 4u ? 1u : 2u);
		event.type = (state.buttons & bit) ? DOS_MOUSE_PRESS : DOS_MOUSE_RELEASE;
		g_mouseButtons = (g_mouseButtons & ~bit) | (state.buttons & bit);
	}
	else if( state.x != g_mouseX || state.y != g_mouseY )
		event.type = DOS_MOUSE_MOVE;
	else
		return false;

	g_mouseX = state.x;
	g_mouseY = state.y;
	event.x = state.x;
	event.y = state.y;
	event.buttons = g_mouseButtons;
	return true;
}

void DosMouseRange(unsigned int cols, unsigned int rows)
{
	g_mouseCols = cols;
	g_mouseRows = rows;
	union REGS regs;
	memset(&regs, 0, sizeof(regs));
	regs.x.ax = 0x0007;
	regs.x.dx = cols*8u - 1u;
	int86(0x33, &regs, &regs);

	regs.x.ax = 0x0008;
	regs.x.cx = 0;
	regs.x.dx = rows*8u - 1u;
	int86(0x33, &regs, &regs);
}
