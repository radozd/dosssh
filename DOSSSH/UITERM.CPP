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
		else if( c >= 33 && c <= 255 && c != 127 && used < sizeof(oem)-1 )
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
static bool DosReadCredential(void *ctx, const char *prompt, bool echo, bool allowEmpty, char *answer, size_t capacity)
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
	else if( ctx != NULL )
		printf("%s@%s's password: ", (const char *)ctx, g_hostArg);
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
		if( ch >= 32 && ch <= 255 && ch != 127 )
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

static bool DosPassword(void *ctx, char *password, size_t capacity)
{
	return DosReadCredential(ctx, NULL, false, false, password, capacity);
}

static bool DosChallenge(void *ctx, const char *prompt, bool echo, char *response, size_t capacity)
{
	return DosReadCredential(ctx, prompt, echo, true, response, capacity);
}

static bool DosConfirmHost(void *, const char *host, const char *fingerprint)
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

static bool DosTrustHost(void *, const unsigned char *hostKey, size_t keySize, const unsigned char hash[32])
{
	bool accepted = SshData::KnownHost(g_hostArg, g_portArg, hostKey, keySize, hash, DosConfirmHost, NULL);
	if( !accepted )
		Log('E', "Host key untrusted, changed, or DOSSSH.DAT unavailable. Connection refused.");
	return accepted;
}

class UiTerminal
{
public:
	UiTerminal()
	{
		_redrawPending = false;
		_lastDrawTick = g_transport.Ticks();
		_keyHead = 0;
		_keyCount = 0;
		_overflowNotified = false;
	}

	~UiTerminal()
	{
		SshCrypt::Zero(_queued, sizeof(_queued));
	}

	static void Output(void *ctx, const unsigned char *bytes, size_t length)
	{
		UiTerminal &self = *(UiTerminal *)ctx;
		g_terminal.Feed(bytes, length);
		self._redrawPending = true;
		self.DrawIfDue();
	}

	static int Input(void *ctx, unsigned char *buffer, size_t capacity)
	{
		return ((UiTerminal *)ctx)->ReadInput(buffer, capacity);
	}

private:
	bool _redrawPending;
	unsigned long _lastDrawTick;

	enum { KeyCapacity = 128 };
	uint16_t _queued[KeyCapacity];

	size_t _keyHead;
	size_t _keyCount;
	bool _overflowNotified;

	int DrainBiosKeys()
	{
		while( biosIsKeyReady() )
		{
			uint16_t key = biosKeyRead();
			if( (key & 255u) == 0 && ((key >> 8) & 255u) == 0x2Du )
				return -1; // Alt+X: always local
			if( _keyCount == KeyCapacity )
			{
				if( !_overflowNotified )
				{
					printf("\a");
					fflush(stdout);
					_overflowNotified = true;
				}
				continue;
			}
			_queued[(_keyHead + _keyCount) % KeyCapacity] = key;
			_keyCount++;
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
			return -2; // a video allocation failure

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
		if( !_keyCount )
			return 0;

		uint16_t bios = _queued[_keyHead];
		int ascii = KeyAscii(bios);
		unsigned char encoded[12];
		size_t size = 0;
		bool translated = false;

		// Encode BEFORE removing the key: tiny SSH channel windows can
		// accommodate fewer bytes than an xterm escape sequence.
		if( ascii == 0 || ascii == 0xE0 )
		{
			size = KeyToVt(bios, encoded, sizeof(encoded), g_terminal.CursorApplication());
			// E0 is also a printable OEM byte (Alt+Numpad) if the BIOS
			// supplies no scan code. Only discard unknown extended scans.
			if( ascii == 0 || size > 1u ||
				(ascii == 0xE0 && size == 0 && (bios & 0xFF00u) != 0) )
				translated = true;
		}
		if( !translated )
		{
			if( ascii >= 128 )
				size = DosOemToUtf8((unsigned char)ascii, encoded);
			else
				size = KeyToVt(bios, encoded, sizeof(encoded), g_terminal.CursorApplication());
		}
		if( size > capacity )
			return 0; // Wait for SSH WINDOW_ADJUST; keep this key.

		_queued[_keyHead] = 0;
		_keyHead = (_keyHead + 1u) % KeyCapacity;
		_keyCount--;
		if( !_keyCount )
			_overflowNotified = false;
		if( size )
			memcpy(buffer, encoded, size);
		SshCrypt::Zero(encoded, sizeof(encoded));
		return (int)size;
	}
};
