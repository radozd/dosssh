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

#ifndef DOSSSH_SSHNET_H
#define DOSSSH_SSHNET_H

#include <stddef.h>

class TcpSocket;

class MtcpTransport
{
public:
	MtcpTransport();
	bool Start();
	bool ConnectHost(const char *host, unsigned int port);
	// Positive byte count: progress; zero: would block; negative: closed/error.
	int ReadSome(unsigned char *dst, size_t length);
	int WriteSome(const unsigned char *src, size_t length);
	void Pump();
	unsigned long Ticks() const;
	bool Aborted() const;
	void SetInteractive(bool enabled);
	bool TakeCtrlc();
	void Stop();

private:
	struct Stats
	{
		unsigned long driverDrops;
		unsigned long tcpDrops;
		unsigned long tcpSeqErrors;
		unsigned long tcpResends;
		unsigned long driverRetries;
		unsigned long driverErrors;
	};

	static Stats ReadStats();
	void DebugStats(bool force);
	TcpSocket *_socket;
	bool _stackStarted;
	unsigned long _statsTick;
	Stats _stats;
};


#endif
