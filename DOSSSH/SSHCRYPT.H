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

/* The ref10 arithmetic is public domain; see SSHCRYPT.CPP and ORIGIN.MD
 * for the original authors and adaptations used by DOSSSH. */

#ifndef DOSSSH_SSHCRYPT_H
#define DOSSSH_SSHCRYPT_H
#include <stddef.h>

class SshCurve
{
public:
	static void ScalarMult(unsigned char *result, const unsigned char *scalar,
							const unsigned char *point);
	static bool VerifyEd25519(const unsigned char *publicKey, const unsigned char *signature,
								const unsigned char *message, size_t messageLength);
};

class SshCrypt
{
public:
	static void Zero(void *ptr, size_t count);
	static bool Equal(const unsigned char *a, const unsigned char *b, size_t count);
};

struct SSHCRYPT_AES
{
	unsigned char round[176];
	unsigned char counter[16];
	unsigned char block[16];
	size_t used;

	void Init(const unsigned char key[16], const unsigned char iv[16]);
	void Xor(unsigned char *bytes, size_t length);
	void EncryptBlock(unsigned char bytes[16]) const;
};

struct SSHCRYPT_RNG
{
	unsigned char key[32];
	unsigned char value[32];
	unsigned char padding[512];
	size_t paddingUsed;
	bool initialized;

	void Init(const unsigned char seed[64]);
	bool Generate(unsigned char *p, size_t len);
	void GeneratePadding(unsigned char *p, size_t len);
	void Clear();

private:
	void Update(const unsigned char *seed, size_t length);
};

#endif
