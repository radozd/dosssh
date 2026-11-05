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

#ifndef DOSSSH_ENCODING_H
#define DOSSSH_ENCODING_H

#include <stddef.h>

void InitDosCharset();
int DosNormalizeCodePage(int codepage);
unsigned char DosUnicodeOem(int codepage, unsigned long ch);
size_t DosOemToUtf8(int codepage, unsigned char ch, unsigned char out[4]);

class DosUtf8Decoder
{
public:
	// Valid Unicode code points are nonnegative.
	enum
	{
		PendingByte = -1,
		Invalid = -2,
		Interrupted = -3
	};

	void Reset();
	bool Pending() const { return _need != 0; }
	bool Start(unsigned char ch);
	long Continue(unsigned char ch);

private:
	unsigned long _value;
	unsigned long _min;
	char _need;
};

#endif
