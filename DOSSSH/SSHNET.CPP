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

#include <dos.h>
#include <stdio.h>
#include <string.h>

#include "types.h"
#include "utils.h"
#include "packet.h"
#include "arp.h"
#include "udp.h"
#include "dns.h"
#include "tcp.h"
#include "tcpsockm.h"
#include "timer.h"

#include "SSHNET.H"
#include "DEBUG.H"

/* DOS interrupt handlers need file-scope state; the connection itself
 * belongs to the one MtcpTransport instance. */
static volatile bool s_cancelled = false;
static volatile bool s_shellMode = false;
static volatile bool s_ctrlC = false;

MtcpTransport::MtcpTransport()
{
	_socket = NULL;
	_stackStarted = false;
	_statsTick = 0;
	memset(&_stats, 0, sizeof(_stats));
}

MtcpTransport::Stats MtcpTransport::ReadStats()
{
	Stats s;
	s.driverDrops = Packets_dropped;
	s.tcpDrops = Tcp::Packets_DroppedNoSpace;
	s.tcpSeqErrors = Tcp::Packets_SeqOrAckError;
	s.tcpResends = Tcp::Packets_Retransmitted;
	s.driverRetries = Packets_send_retries;
	s.driverErrors = Packets_send_errs;
	return s;
}

void MtcpTransport::DebugStats(bool force)
{
	if( !DebugEnabled() )
		return;

	unsigned long now = Ticks();
	if( !force && now - _statsTick < TIMER_SECS_TO_TICKS(1) )
		return;

	_statsTick = now;

	Stats s = ReadStats();
	if( force || s.driverDrops != _stats.driverDrops || s.tcpDrops != _stats.tcpDrops ||
		s.tcpSeqErrors != _stats.tcpSeqErrors || s.tcpResends != _stats.tcpResends ||
		s.driverRetries != _stats.driverRetries || s.driverErrors != _stats.driverErrors )
	{
		Log('N', "TCP drops driver=%lu (+%lu) full=%lu (+%lu)",
			s.driverDrops, s.driverDrops - _stats.driverDrops, s.tcpDrops, s.tcpDrops - _stats.tcpDrops);
		Log('N', "TCP seq=%lu (+%lu) resend=%lu (+%lu) retry=%lu (+%lu) err=%lu (+%lu)",
			s.tcpSeqErrors, s.tcpSeqErrors - _stats.tcpSeqErrors, s.tcpResends, s.tcpResends - _stats.tcpResends,
			s.driverRetries, s.driverRetries - _stats.driverRetries, s.driverErrors, s.driverErrors - _stats.driverErrors);
	}
	_stats = s;
}

static void __interrupt __far OnBreak()
{
	s_cancelled = true;
}

static void __interrupt __far OnCtrlC()
{
	if( s_shellMode )
		s_ctrlC = true;
	else
		s_cancelled = true;
}

bool MtcpTransport::Aborted() const
{
	return s_cancelled;
}

void MtcpTransport::SetInteractive(bool enabled)
{
	s_shellMode = enabled;
	s_ctrlC = false;
}

bool MtcpTransport::TakeCtrlc()
{
	bool result = s_ctrlC;
	s_ctrlC = false;
	return result;
}

unsigned long MtcpTransport::Ticks() const
{
	return TIMER_GET_CURRENT();
}

void MtcpTransport::Pump()
{
	if( !_stackStarted )
		return;

	/* mTCP recommends batched polling for bursty interactive traffic. */
	PACKET_PROCESS_MULT(5);
	Arp::driveArp();
	Tcp::drivePackets();
	DebugStats(false);
}

bool MtcpTransport::Start()
{
	s_cancelled = false;
	s_shellMode = false;
	s_ctrlC = false;
	if( Utils::parseEnv() != 0 )
		return false;
	if( Utils::initStack(1, 6, OnBreak, OnCtrlC) != 0 )
		return false;
	_stackStarted = true;
	_statsTick = Ticks();
	_stats = ReadStats();
	Log('N', "mTCP started free=%d", Buffer_lowFreeCount);
	return true;
}

bool MtcpTransport::ConnectHost(const char *host, unsigned int port)
{
	if( !_stackStarted )
		return false;

	IpAddr_t address;
	Log('N', "DNS %s:%u", host, port);
	int8_t rc = Dns::resolve(host, address, 1);
	if( rc != 0 && rc != 1 )
	{
		if( rc == -2 )
			Log('E', "DNS nameserver is not configured");
		else if( rc == 2 )
			Log('E', "DNS resolver is busy");
		else
			Log('E', "DNS request failed (code %d)", rc);
		return false;
	}

	while( Dns::isQueryPending() && !s_cancelled )
	{
		PACKET_PROCESS_SINGLE;
		Arp::driveArp();
		Dns::drivePendingQuery();
		DebugStats(false);
	}
	if( s_cancelled )
	{
		Log('E', "DNS resolution cancelled");
		return false;
	}
	if( rc == 1 && Dns::getQueryRc() != Good )
	{
		if( Dns::getQueryRc() == Timeout )
			Log('E', "DNS query timed out");
		else
			Log('E', "DNS query failed (response code %d)", Dns::getQueryRc());
		return false;
	}
	if( Dns::resolve(host, address, 0) != 0 )
	{
		Log('E', "DNS name not found in resolver cache");
		return false;
	}

	Log('N', "DNS OK %s", host);
	_socket = TcpSocketMgr::getSocket();
	if( _socket == NULL )
	{
		Log('E', "mTCP: no socket available");
		return false;
	}
	if( _socket->setRecvBuffer(16384) != TCP_RC_GOOD )
	{
		Log('E', "mTCP: receive buffer allocation failed");
		return false;
	}

	const uint16_t local_port = 20000u + (TIMER_GET_CURRENT() % 30000u);
	rc = _socket->connectNonBlocking(local_port, address, port);
	if( rc == TCP_RC_GOOD )
	{
		clockTicks_t start = TIMER_GET_CURRENT();
		while( !s_cancelled && !_socket->isConnectComplete() && !_socket->isClosed() )
		{
			Pump();
			if( Timer_diff(start, TIMER_GET_CURRENT()) >= TIMER_SECS_TO_TICKS(15) )
			{
				rc = TCP_RC_TIMEOUT;
				break;
			}
		}
	}
	if( !s_cancelled && rc == TCP_RC_GOOD && _socket->isConnectComplete() )
		return true;

	Log('N', "TCP fail rc=%d reason=%d cancelled=%d", rc, _socket->closeReason, s_cancelled);
	if( s_cancelled )
		Log('E', "TCP connection cancelled");
	else if( _socket->closeReason == 1 )
		Log('E', "TCP connection refused");
	else if( rc == TCP_RC_TIMEOUT )
		Log('E', "TCP connection timed out");
	else
		Log('E', "TCP connection failed");
	return false;
}

int MtcpTransport::ReadSome(unsigned char *dest, size_t length)
{
	if( _socket == NULL || s_cancelled || dest == NULL || length > 32767u )
		return -1;

	int16_t result = _socket->recv(dest, length);
	if( result < 0 || (result == 0 && _socket->isRemoteClosed()) )
	{
		Log('W', "TCP recv=%d closed=%d", result, _socket->isRemoteClosed());
		return -1;
	}
	return result;
}

int MtcpTransport::WriteSome(const unsigned char *source, size_t length)
{
	if( _socket == NULL || s_cancelled || source == NULL || length > 32767u )
		return -1;
	// mTCP returns BYTES QUEUED, possibly zero, not a POSIX success code.
	int16_t result = _socket->send((uint8_t *)source, length);
	if( result < 0 )
		Log('E', "TCP send rc=%d", result);
	return result;
}

void MtcpTransport::Stop()
{
	DebugStats(true);
	Log('N', "mTCP stopped");
	if( _socket != NULL )
	{
		_socket->close();
		TcpSocketMgr::freeSocket(_socket);
		_socket = NULL;
	}
	if( _stackStarted )
	{
		Utils::endStack();
		_stackStarted = false;
	}
}
