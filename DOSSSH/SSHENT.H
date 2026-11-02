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

/* Disk contents and the volume serial are NOT assumed to be secret.
 * Timing variation may contain entropy on physical hard disks, but
 * there is no portable lower bound for CF adapters or DOS emulators. */

#ifndef DOSSSH_SSHENT_H
#define DOSSSH_SSHENT_H

#include <stddef.h>
#include "SSHCRYPT.H"
#include "SSHSHA.H"

class SshEntropy
{
public:
	SshEntropy();

	void AddState(const unsigned char *bytes, size_t length);
	void AddVolume(unsigned char drive, unsigned long serial, unsigned long totalSectors);
	void AddSector(const unsigned char sector[512], unsigned long sectorNumber, unsigned long beforeTick, unsigned long afterTick);
	void Final(unsigned char seed[64]);

	unsigned int SampleCount() const { return _samples; }

	static unsigned long NextSelector(unsigned long previous, unsigned long readDuration, unsigned long sampleStamp, unsigned long lastSector);
	static unsigned long PickSector(unsigned long firstSector, unsigned long sectorCount, unsigned long selector);
	static bool Initialize(SSHCRYPT_RNG &rng, const char *programPath);

private:
	Sha256State _hash;
	unsigned int _samples;
};

#endif
