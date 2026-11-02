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

#ifndef DOSSSH_SSHSHA_H
#define DOSSSH_SSHSHA_H

#include <stddef.h>

struct Sha256State
{
	unsigned long h[8];
	unsigned char block[64];
	size_t used;
	unsigned long bytesLo;
	unsigned long bytesHi;

	void Init();
	void Bytes(const unsigned char *p, size_t bytes);
	void Final(unsigned char digest[32]);
	static void Simple(const unsigned char *p, size_t bytes, unsigned char digest[32]);

private:
	void Block(const unsigned char *bytes);
};

struct Sha512State
{
	unsigned __int64 h[8];
	unsigned char block[128];
	size_t used;
	unsigned long bytesLo;
	unsigned long bytesHi;

	void Init();
	void Bytes(const unsigned char *p, size_t bytes);
	void Final(unsigned char digest[64]);
	static void Simple(const unsigned char *p, size_t bytes, unsigned char digest[64]);

private:
	void Block(const unsigned char *bytes);
};

void Sha256HMAC(const unsigned char *key, size_t keyLength, const unsigned char *msg, size_t length, unsigned char digest[32]);

#endif
