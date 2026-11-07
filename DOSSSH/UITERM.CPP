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

#include "inlines.h"

int DosGetKey()
{
	while( !biosIsKeyReady() )
	{
		if( g_transport.Aborted() )
			return -1;
		g_transport.Pump();
	}
	return (int)biosKeyRead();
}

static bool DosUsername(char *username, size_t capacity)
{
	DosFlushKeys();
	printf("login as: ");
	fflush(stdout);
	char oem[65];
	size_t used = 0;
	for( ;; )
	{
		int bios = DosGetKey();
		int c = KeyAscii(bios);
		if( bios == -1 || c == 27 || c == 3 )
		{
			printf("\n");
			return false;
		}
		if( c == 13 )
		{
			printf("\n");
			break;
		}
		if( c == 8 )
		{
			if( used )
			{
				used--;
				printf("\b \b");
				fflush(stdout);
			}
		}
		else if( c >= 33 && c != 127 && used < sizeof(oem)-1 )
		{
			oem[used++] = (char)c;
			printf("%c", c);
			fflush(stdout);
		}
	}
	oem[used] = '\0';
	return DosOemString(oem, username, capacity);
}

// Read a credential only after KEX and host-key verification.
// UTF-8 is sent over SSH; DOS OEM bytes are only used for local echo.
static bool DosReadCredential(const char *username, const char *prompt, bool echo, bool allowEmpty, char *answer, size_t capacity)
{
	DosFlushKeys();
	if( prompt && *prompt )
	{
		int length = strlen(prompt);
		while( length && (prompt[length - 1] == '\r' || prompt[length - 1] == '\n') )
			length--;
		printf("%.*s", length, prompt);
		if( length && prompt[length - 1] != ' ' && prompt[length - 1] != '\t' )
			printf(" ");
	}
	else if( username != NULL )
		printf("%s@%s's password: ", username, g_hostArg);
	else
		printf("password: ");
	fflush(stdout);

	size_t used = 0;
	for( ;; )
	{
		int bios = DosGetKey();
		int ch = KeyAscii(bios);
		if( bios == -1 || ch == 27 || ch == 3 )
		{
			SshCrypt::Zero(answer, capacity);
			printf("\n");
			return false;
		}
		if( ch == 13 )
		{
			answer[used] = '\0';
			printf("\n");
			return used != 0 || allowEmpty;
		}
		if( ch == 8 || ch == 127 )
		{
			if( used )
			{
				do
					used--;
				while( used && ((unsigned char)answer[used] & 0xC0) == 0x80 );

				if( echo )
				{
					printf("\b \b");
					fflush(stdout);
				}
			}
			continue;
		}
		if( ch >= 32 && ch != 127 )
		{
			unsigned char utf[4];
			size_t size = DosOemToUtf8((unsigned char)ch, utf);
			if( used + size < capacity )
			{
				memcpy(answer + used, utf, size);
				used += size;
				if( echo )
				{
					printf("%c", ch);
					fflush(stdout);
				}
			}
		}
	}
}

bool DosPassword(const char *username, char *password, size_t capacity)
{
	return DosReadCredential(username, NULL, false, false, password, capacity);
}

bool DosChallenge(const char *username, const char *prompt, bool echo, char *response, size_t capacity)
{
	return DosReadCredential(username, prompt, echo, true, response, capacity);
}

bool DosConfirmHost(const char *host, const char *fingerprint)
{
	DosFlushKeys();
	printf("The authenticity of host '%s' can't be established.\n", host);
	printf("ED25519 key fingerprint is %s.\n", fingerprint);
	printf("Verify the fingerprint independently before accepting this key.\n");
	printf("Are you sure you want to continue connecting (yes/no)? ");
	fflush(stdout);
	char input[8];
	size_t used = 0;
	for( ;; )
	{
		int bios = DosGetKey();
		int ch = KeyAscii(bios);
		if( bios == -1 || ch == 27 || ch == 3 )
			return false;
		if( ch == 0 )
			continue;
		if( ch == 13 )
		{
			printf("\n");
			break;
		}
		if( ch == 8 )
		{
			if( used )
			{
				used--;
				printf("\b \b");
				fflush(stdout);
			}
			continue;
		}
		if( ch >= 32 && ch <= 126 && used < sizeof(input)-1 )
		{
			input[used++] = (char)ch;
			printf("%c", ch);
			fflush(stdout);
		}
	}
	input[used] = '\0';
	return used == 3 && (input[0] == 'y' || input[0] == 'Y') &&
		(input[1] == 'e' || input[1] == 'E') && (input[2] == 's' || input[2] == 'S');
}

bool DosTrustHost(const unsigned char *hostKey, size_t keySize, const unsigned char hash[32])
{
	bool accepted = SshData::KnownHost(g_hostArg, g_portArg, hostKey, keySize, hash);
	if( !accepted )
		Log('E', "Host key untrusted, changed, or DOSSSH.DAT unavailable. Connection refused.");
	return accepted;
}

class BiosKeyBuffer
{
	enum { Capacity = 128 };

public:
	struct Key
	{
		uint16_t code;
		unsigned char modifiers;
	};

	BiosKeyBuffer()
	{
		_head = 0;
		_count = 0;
	}

	~BiosKeyBuffer()
	{
		SshCrypt::Zero(_keys, sizeof(_keys));
	}

	void Clear()
	{
		SshCrypt::Zero(_keys, sizeof(_keys));
		_head = 0;
		_count = 0;
	}

	bool Push(uint16_t code, unsigned char modifiers)
	{
		if( _count == Capacity )
			return false;

		size_t tail = (_head + _count) % Capacity;
		_keys[tail].code = code;
		_keys[tail].modifiers = modifiers;
		_count++;
		return true;
	}

	bool Peek(Key &key) const
	{
		if( _count == 0 )
			return false;

		key = _keys[_head];
		return true;
	}

	void Pop()
	{
		if( _count == 0 )
			return;

		_keys[_head].code = 0;
		_keys[_head].modifiers = 0;
		_head = (_head + 1u) % Capacity;
		_count--;
	}

	bool Empty() const { return _count == 0; }

private:
	Key _keys[Capacity];
	size_t _head;
	size_t _count;
};

class UiTerminal
{
public:
	UiTerminal()
	{
		_redrawPending = false;
		_lastDrawTick = 0;
		_overflowNotified = false;
	}

	void Start()
	{
		_keys.Clear();
		_redrawPending = false;
		_lastDrawTick = g_transport.Ticks();
		_overflowNotified = false;
	}

	void Output(const unsigned char *bytes, size_t length)
	{
		g_terminal.Feed(bytes, length);
		_redrawPending = true;
		DrawIfDue();
	}

	int Input(unsigned char *buffer, size_t capacity)
	{
		return ReadInput(buffer, capacity);
	}

private:
	bool _redrawPending;
	unsigned long _lastDrawTick;

	BiosKeyBuffer _keys;

	bool _overflowNotified;

	int DrainBiosKeys()
	{
		while( biosIsKeyReady() )
		{
			unsigned char modifiers = KeyboardModifiers();
			uint16_t key = biosKeyRead();
			if( (key & 255u) == 0 && ((key >> 8) & 255u) == 0x2Du )
				return -1; // Alt+X: always local
			if( !_keys.Push(key, modifiers) )
			{
				if( !_overflowNotified )
				{
					printf("\a");
					fflush(stdout);
					_overflowNotified = true;
				}
				continue;
			}
		}
		return 0;
	}

	void DrawIfDue()
	{
		if( !_redrawPending )
			return;

		unsigned long now = g_transport.Ticks();
		// Coalesce full-screen terminal updates (e.g. MC's F3 redraw).
		// At most one VGA update per 55-ms BIOS timer tick.
		if( now - _lastDrawTick < 1ul )
			return;
		g_screen.Draw();
		_redrawPending = false;
		_lastDrawTick = now;
	}

	int ReadInput(unsigned char *buffer, size_t capacity)
	{
		DrawIfDue();
		if( !g_terminal.Ok() )
			return -2;

		if( DrainBiosKeys() == -1 )
			return -1;

		if( capacity == 0 )
			return 0; // command-only probe; never dereference buffer

		size_t count = g_terminal.ReadReply(buffer, capacity);
		if( count )
			return (int)count;

		if( g_transport.TakeCtrlc() )
		{
			buffer[0] = 3;
			return 1;
		}
		BiosKeyBuffer::Key key;
		if( !_keys.Peek(key) )
			return 0;

		int ascii = KeyAscii(key.code);
		unsigned char encoded[12];
		size_t size = 0;
		bool translated = false;

		// Encode BEFORE removing the key: tiny SSH channel windows can
		// accommodate fewer bytes than an xterm escape sequence.
		if( ascii == 0 || ascii == 0xE0 )
		{
			size = g_terminal.KeyToVt(key.code, key.modifiers, encoded, sizeof(encoded));
			// E0 is also a printable OEM byte (Alt+Numpad) if the BIOS
			// supplies no scan code. Only discard unknown extended scans.
			if( ascii == 0 || size > 1u || (ascii == 0xE0 && size == 0 && (key.code & 0xFF00u) != 0) )
				translated = true;
		}
		if( !translated )
		{
			if( ascii >= 128 )
				size = DosOemToUtf8((unsigned char)ascii, encoded);
			else
				size = g_terminal.KeyToVt(key.code, key.modifiers, encoded, sizeof(encoded));
		}
		if( size > capacity )
			return 0; // Wait for SSH WINDOW_ADJUST; keep this key.

		_keys.Pop();
		if( _keys.Empty() )
			_overflowNotified = false;
		if( size )
			memcpy(buffer, encoded, size);

		SshCrypt::Zero(encoded, sizeof(encoded));

		return (int)size;
	}
};
