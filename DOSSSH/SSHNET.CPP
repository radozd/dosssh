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
static volatile bool g_cancelled = false;
static volatile bool g_shellMode = false;
static volatile bool g_ctrlC = false;

MtcpTransport::MtcpTransport()
{
	_socket = NULL;
	_stackStarted = false;
	_statsTick = 0;
	_driverDrops = 0;
	_tcpDrops = 0;
	_tcpSeqErrors = 0;
	_tcpResends = 0;
	_driverRetries = 0;
	_driverErrors = 0;
}

/* Use the public mTCP counters; at most one poll per second. */
void MtcpTransport::DebugStats(bool force)
{
	if( !DebugEnabled() )
		return;

	unsigned long now = Ticks();
	if( !force && now - _statsTick < TIMER_SECS_TO_TICKS(1) )
		return;

	_statsTick = now;

	uint32_t driver_drops = Packets_dropped;
	uint32_t tcp_drops = Tcp::Packets_DroppedNoSpace;
	uint32_t seq_errors = Tcp::Packets_SeqOrAckError;
	uint32_t resends = Tcp::Packets_Retransmitted;
	uint32_t retries = Packets_send_retries;
	uint32_t errors = Packets_send_errs;
	if( force || driver_drops != _driverDrops || tcp_drops != _tcpDrops ||
		seq_errors != _tcpSeqErrors || resends != _tcpResends ||
		retries != _driverRetries || errors != _driverErrors )
	{
		Log('N', "TCP drops driver=%lu (+%lu) full=%lu (+%lu)",
			driver_drops, driver_drops - _driverDrops, tcp_drops, tcp_drops - _tcpDrops);
		Log('N', "TCP seq=%lu (+%lu) resend=%lu (+%lu) retry=%lu (+%lu) err=%lu (+%lu)",
			seq_errors, seq_errors - _tcpSeqErrors, resends, resends - _tcpResends,
			retries, retries - _driverRetries, errors, errors - _driverErrors);
	}
	_driverDrops = driver_drops;
	_tcpDrops = tcp_drops;
	_tcpSeqErrors = seq_errors;
	_tcpResends = resends;
	_driverRetries = retries;
	_driverErrors = errors;
}

static void __interrupt __far OnBreak()
{
	g_cancelled = true;
}

static void __interrupt __far OnCtrlC()
{
	if( g_shellMode )
		g_ctrlC = true;
	else
		g_cancelled = true;
}

bool MtcpTransport::Aborted() const
{
	return g_cancelled;
}

void MtcpTransport::SetInteractive(bool enabled)
{
	g_shellMode = enabled;
	g_ctrlC = false;
}

bool MtcpTransport::TakeCtrlc()
{
	bool result = g_ctrlC;
	g_ctrlC = false;
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
	g_cancelled = false;
	g_shellMode = false;
	g_ctrlC = false;
	if( Utils::parseEnv() != 0 )
		return false;
	if( Utils::initStack(1, 6, OnBreak, OnCtrlC) != 0 )
		return false;
	_stackStarted = true;
	_statsTick = Ticks();
	_driverDrops = Packets_dropped;
	_tcpDrops = Tcp::Packets_DroppedNoSpace;
	_tcpSeqErrors = Tcp::Packets_SeqOrAckError;
	_tcpResends = Tcp::Packets_Retransmitted;
	_driverRetries = Packets_send_retries;
	_driverErrors = Packets_send_errs;
	Log('N', "mTCP started free=%d", Buffer_lowFreeCount);
	return true;
}

bool MtcpTransport::ConnectHost(const char *host, unsigned int port)
{
	if( !_stackStarted || host == NULL || strlen(host) >= 128u )
		return false;

	IpAddr_t address;
	int8_t rc;
	Log('N', "DNS %s:%u", host, port);
	rc = Dns::resolve(host, address, 1);
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

	/* Match the mTCP FTP/FTP2P resolver: during a DNS lookup, drive
	 * packets, ARP and DNS retransmissions, not the TCP socket loop.
	 * Dns::drivePendingQuery() owns the retry and timeout policy. */
	while( Dns::isQueryPending() && !g_cancelled )
	{
		PACKET_PROCESS_SINGLE;
		Arp::driveArp();
		Dns::drivePendingQuery();
		DebugStats(false);
	}
	if( g_cancelled )
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
		while( !g_cancelled && !_socket->isConnectComplete() && !_socket->isClosed() )
		{
			Pump();
			if( Timer_diff(start, TIMER_GET_CURRENT()) >= TIMER_SECS_TO_TICKS(15) )
			{
				rc = TCP_RC_TIMEOUT;
				break;
			}
		}
	}
	if( !g_cancelled && rc == TCP_RC_GOOD && _socket->isConnectComplete() )
		return true;

	Log('N', "TCP fail rc=%d reason=%d cancelled=%d", rc, _socket->closeReason, g_cancelled);
	if( g_cancelled )
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
	if( _socket == NULL || g_cancelled || dest == NULL || length > 32767u )
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
	if( _socket == NULL || g_cancelled || source == NULL || length > 32767u )
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
