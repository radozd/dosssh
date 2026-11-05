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

#ifndef DOSSSH_CLIENT_CONFIG_H
#define DOSSSH_CLIENT_CONFIG_H

#include <stddef.h>

#define SSH_DEFAULT_PORT (22)

class SshData
{
public:
	static bool Select(unsigned char launchedDrive);
	static unsigned char Drive();
	static bool LoadSeed(unsigned char seed[64], bool &present);
	static bool RotateSeed(const unsigned char seed[64]);
	static bool KnownHost(const char *host, unsigned int port, const unsigned char *key,
		size_t keySize, const unsigned char digest[32],
		bool (*confirm)(void *, const char *, const char *), void *ctx);
};

#endif
