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

#ifndef DOSSSH_INPUT_H
#define DOSSSH_INPUT_H

#include <stddef.h>
#include <stdint.h>

enum
{
	VT_KEY_SHIFT = 1,
	VT_KEY_ALT = 2,
	VT_KEY_CTRL = 4
};

int KeyAscii(uint16_t key);
bool DosKeyReady();
uint16_t DosKeyRead();
void DosFlushKeys();
unsigned char KeyboardModifiers();

class BiosKeyBuffer
{
	enum { Capacity = 128 };

public:
	struct Key
	{
		uint16_t code;
		unsigned char modifiers;
	};

	BiosKeyBuffer();
	~BiosKeyBuffer();

	void Clear();
	// -1: Alt+X local exit, 1: queue overflow, 0: normal.
	int Poll();
	bool Peek(Key &key) const;
	void Pop();
	bool Empty() const { return _count == 0; }

private:
	bool Push(uint16_t code, unsigned char modifiers);
	Key _keys[Capacity];
	size_t _head;
	size_t _count;
};

enum DosMouseEventType
{
	DOS_MOUSE_PRESS,
	DOS_MOUSE_RELEASE,
	DOS_MOUSE_MOVE
};

struct DosMouseEvent
{
	unsigned int x;
	unsigned int y;
	unsigned int button;
	unsigned int buttons;
	DosMouseEventType type;
};

bool DosMouseInit();
void DosMouseCursor(bool visible);
void DosMouseMotion(int &dx, int &dy);
void DosMouseRange(unsigned int cols, unsigned int rows);
void DosMouseSync();
bool DosMousePoll(DosMouseEvent &event);

#endif
