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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "SSHSCAN.H"
#include "SSHSHA.H"
#include "SSHPKT.H"
#include "DEBUG.H"

static void SshScanDebugKeys(const char *phase, const SSHPKT_Keys &keys)
{
	if( DebugIsOn() )
	{
		Log('I', "%s AES128/HMAC256 keys", phase);
		DebugHex("client_to_server.iv", keys.clientIV, sizeof(keys.clientIV));
		DebugHex("server_to_client.iv", keys.serverIV, sizeof(keys.serverIV));
		DebugHex("client_to_server.aes128", keys.clientKey, sizeof(keys.clientKey));
		DebugHex("server_to_client.aes128", keys.serverKey, sizeof(keys.serverKey));
		DebugHex("client_to_server.hmac256", keys.clientMac, sizeof(keys.clientMac));
		DebugHex("server_to_client.hmac256", keys.serverMac, sizeof(keys.serverMac));
	}
}

/* File-scope constant avoids COMDAT iterated-data in inline methods. */
static const unsigned char basepoint[32] = {9};

/* One fixed buffer; also accommodates the 4-byte SSH packet length. */
static unsigned char g_sshFrame[SSHPKT_MAX_WIRE];
/* Hold original I_S while ECDH_REPLY overwrites the input frame. */
static unsigned char g_serverKex[8192];
static unsigned char g_clientKex[512];
/* Separate TX buffer: live RX frames may be only partially received. */
static unsigned char g_sshTxFrame[1536];
static unsigned char g_sshMessage[1024];

/* A byte is 0..255; -1 means a timeout or transport failure. */
static int ReadIdentByte(unsigned long start, unsigned long deadline)
{
	unsigned long elapsed = (unsigned long)(g_transport.Ticks() - start);
	if( elapsed >= deadline )
		return -1;
	unsigned char byte;
	return DosSshReadExact(&byte, 1, deadline - elapsed) ? (int)byte : -1;
}

bool SshScanIdent(char *server, size_t capacity, unsigned long deadline)
{
	if( server == NULL || capacity < SSHSCAN_ID_SIZE || deadline == 0 || deadline >= 0x80000000ul )
		return false;

	unsigned long start = g_transport.Ticks();
	for( int lines = 0; lines < 16; lines++ )
	{
		size_t used = 0;
		for( ;; )
		{
			int ch = ReadIdentByte(start, deadline);
			if( ch < 0 )
				return false;
			if( ch == '\n' )
				break;
			if( ch == 0 || (ch < 32 && ch != '\r' && ch != '\t') || ch > 126 || used >= SSHSCAN_ID_SIZE - 2 )
				return false;
			server[used++] = (char)ch;
		}
		if( used && server[used - 1] == '\r' )
			used--;
		server[used] = '\0';
		if( used > 8 && strncmp(server, "SSH-2.0-", 8) == 0 )
			return true;
		if( used >= 4 && strncmp(server, "SSH-", 4) == 0 )
			return false;
	}
	return false;
}

bool SshScanSendIdent(unsigned long timeout)
{
	const char msg[] = SSHSCAN_CLIENT_ID;
	return DosSshWriteAll((const unsigned char *)msg, sizeof(msg) - 1, timeout);
}

/* Initial key exchange owns its ephemeral secrets and the provisional
 * session.  No caller can forget the failure path: the destructor erases
 * sensitive state and a failed session even on an early return. */
class SshInitialExchange
{
public:
	SshInitialExchange(const char *serverIdent, SSHSCAN_HostTrust trust, void *trustCtx,
		SSHCRYPT_RNG &rng, SSHSCAN_Session &session, const char **reason, unsigned long timeout)
		: _rng(rng), _session(session)
	{
		_serverIdent = serverIdent;
		_trust = trust;
		_trustCtx = trustCtx;
		_reason = reason;
		_timeout = timeout;
		_sequenceOut = 0;
		_sequenceIn = 0;
		_success = false;
	}

	~SshInitialExchange()
	{
		SshCrypt::Zero(&_keys, sizeof(_keys));
		SshCrypt::Zero(_ephemeral, sizeof(_ephemeral));
		SshCrypt::Zero(_shared, sizeof(_shared));
		SshCrypt::Zero(_cookie, sizeof(_cookie));
		SshCrypt::Zero(_digest, sizeof(_digest));
		SshCrypt::Zero(_hostDigest, sizeof(_hostDigest));
		SshCrypt::Zero(_publicKey, sizeof(_publicKey));
		if( !_success )
			_session.Clear();
	}

	bool Run()
	{
		SetReason("KEX failed");
		if( !SendKexinit() || !ReceiveKexinit() || !ExchangeEcdh() || !AuthenticateHost() || !InstallKeys() || !RequestService() )
			return false;

		_session.inSequence = _sequenceIn;
		_session.outSequence = _sequenceOut;
		_session.inEpochPackets = 1;
		_session.outEpochPackets = 1;
		_session.inEpochBytes = sizeof(s_service);
		_session.outEpochBytes = sizeof(s_service);
		_session.lastKexTicks = g_transport.Ticks();
		SetReason("Authenticated KEX + encrypted service accepted");
		_success = true;
		return true;
	}

private:
	const char *_serverIdent;
	SSHSCAN_HostTrust _trust;
	void *_trustCtx;
	SSHCRYPT_RNG &_rng;
	SSHSCAN_Session &_session;
	const char **_reason;
	unsigned long _timeout;
	const unsigned char *_payload;
	size_t _length;
	size_t _clientKexLength;
	size_t _serverKexLength;
	unsigned long _sequenceOut;
	unsigned long _sequenceIn;
	SshEcdhReply _reply;
	SshExchange _exchange;
	SSHPKT_Keys _keys;
	unsigned char _cookie[16];
	unsigned char _ephemeral[32];
	unsigned char _publicKey[32];
	unsigned char _shared[32];
	unsigned char _digest[32];
	unsigned char _hostDigest[32];
	unsigned char _ecdhInit[37];
	bool _success;

	static const unsigned char s_service[17];

	void SetReason(const char *message)
	{
		if( _reason )
			*_reason = message;
	}

	bool SendPlain(const unsigned char *payload, size_t length)
	{
		size_t padding = SshPktPaddingSize(length);
		if( padding == 0 || padding > 32 )
			return false;

		unsigned char noise[32];
		bool generated = _rng.Generate(noise, padding);
		size_t frame_length = generated ? SshPktEncodePlain(payload, length, noise, padding, g_sshFrame, sizeof(g_sshFrame)) : 0;
		bool success = frame_length != 0 && SshPktWritePlain(g_sshFrame, frame_length, _timeout, &_sequenceOut);
		SshCrypt::Zero(noise, sizeof(noise));
		if( success )
			DebugPacket("send plain", payload[0], length, _sequenceOut - 1ul);
		return success;
	}

	bool ReceivePlain()
	{
		_payload = SshPktReadPlain(g_sshFrame, sizeof(g_sshFrame), _length, _timeout, &_sequenceIn);
		if( _payload == NULL )
			return false;

		DebugPacket("recv plain", _payload[0], _length, _sequenceIn - 1ul);
		return true;
	}

	bool ReceiveSecure()
	{
		_payload = SshPktReadSecure(_session.decrypt, g_sshFrame, sizeof(g_sshFrame), _length, _timeout, _sequenceIn);
		if( _payload == NULL )
			return false;

		DebugPacket("recv encrypted", _payload[0], _length, _sequenceIn - 1ul);
		return true;
	}

	bool SendKexinit()
	{
		if( !_rng.Generate(_cookie, sizeof(_cookie)) )
			return false;
		_clientKexLength = SshPktMakeKexinit(_cookie, g_clientKex, sizeof(g_clientKex));

		DebugHex("initial.kex_cookie", _cookie, sizeof(_cookie));
		SetReason("Cannot send client SSH_MSG_KEXINIT");
		return _clientKexLength != 0 && SendPlain(g_clientKex, _clientKexLength);
	}

	bool ReceiveKexinit()
	{
		SetReason("Invalid server SSH_MSG_KEXINIT");
		bool found = false;
		for( int i = 0; i < 8; i++ )
		{
			if( !ReceivePlain() )
				return false;

			if( _payload[0] == 20 )
			{
				found = true;
				break;
			}
			if( _payload[0] != 2 && _payload[0] != 4 )
				return false;
		}
		if( !found || _length > sizeof(g_serverKex) )
			return false;

		memcpy(g_serverKex, _payload, _length);
		_serverKexLength = _length;
		int discard = DosSshNegotiateKexinit(g_serverKex, _serverKexLength, _reason);
		if( discard < 0 )
			return false;

		Log('I', "KEX curve25519 ed25519 aes128-ctr hmac256 guess=%d", discard);
		if( discard )
		{
			SetReason("Server guessed packet missing");
			return ReceivePlain();
		}
		return true;
	}

	bool ExchangeEcdh()
	{
		{
			LongOp key_op("X25519 key");
			_rng.Generate(_ephemeral, sizeof(_ephemeral));
			SshCurve::ScalarMult(_publicKey, _ephemeral, basepoint);
		}
		size_t kex_size = SshPktMakeEcdhInit(_publicKey, _ecdhInit, sizeof(_ecdhInit));
		DebugHex("initial.x25519.private", _ephemeral, sizeof(_ephemeral));
		DebugHex("initial.x25519.public", _publicKey, sizeof(_publicKey));
		SetReason("Could not send SSH_MSG_KEX_ECDH_INIT");
		if( kex_size == 0 || !SendPlain(_ecdhInit, kex_size) )
			return false;

		SetReason("Invalid SSH_MSG_KEX_ECDH_REPLY");
		bool found = false;
		for( int i = 0; i < 8; i++ )
		{
			if( !ReceivePlain() )
				return false;

			if( _payload[0] == 31 )
			{
				found = true;
				break;
			}
			if( _payload[0] != 2 && _payload[0] != 4 )
				return false;
		}
		if( !found || !_reply.Parse(_payload, _length) )
			return false;

		DebugHex("initial.server.x25519.public", _reply.ServerPublic(), 32);
		DebugHex("initial.server.ed25519.public", _reply.HostPublic(), 32);
		DebugHex("initial.server.ed25519.signature", _reply.Signature(), 64);
		DebugHex("initial.server.hostkey_blob", _reply.HostKey(), _reply.HostKeyLength());
		return true;
	}

	bool AuthenticateHost()
	{
		{
			LongOp shared_op("X25519 secret");
			SshCurve::ScalarMult(_shared, _ephemeral, _reply.ServerPublic());
		}
		SshCrypt::Zero(_ephemeral, sizeof(_ephemeral));
		_exchange.SetIdentifiers((const unsigned char *)SSHSCAN_CLIENT_ID, sizeof(SSHSCAN_CLIENT_ID) - 3, (const unsigned char *)_serverIdent, strlen(_serverIdent));
		_exchange.SetKexinit(g_clientKex, _clientKexLength, g_serverKex, _serverKexLength);
		_exchange.SetEcdh(_reply, _publicKey, _shared);

		DebugHex("initial.x25519.shared_secret", _shared, sizeof(_shared));
		SetReason("Exchange hash / X25519 shared secret invalid");
		if( !_exchange.Hash(_digest) )
			return false;

		DebugHex("initial.exchange_hash", _digest, sizeof(_digest));

		Sha256State::Simple(_reply.HostKey(), _reply.HostKeyLength(), _hostDigest);
		DebugHex("initial.hostkey_sha256", _hostDigest, sizeof(_hostDigest));
		SetReason("Server Ed25519 signature verification failed");
		{
			LongOp verify_op("Ed25519 verify");
			if( !SshCurve::VerifyEd25519(_reply.HostPublic(), _reply.Signature(),
				_digest, sizeof(_digest)) )
				return false;
		}

		SetReason("Server host key rejected or DOSSSH.DAT cannot be saved");
		if( !_trust(_trustCtx, _reply.HostKey(), _reply.HostKeyLength(), _hostDigest) )
			return false;

		// Rekey must retain the first H and the authenticated host key.
		memcpy(_session.sessionId, _digest, sizeof(_session.sessionId));
		DebugHex("session.id", _session.sessionId, sizeof(_session.sessionId));
		memcpy(_session.serverHostKey, _reply.HostKey(), _reply.HostKeyLength());
		_session.serverHostKeyLength = _reply.HostKeyLength();
		strcpy(_session.serverIdent, _serverIdent);
		return true;
	}

	bool InstallKeys()
	{
		static const unsigned char newkeys[] = {21};

		SshPktDeriveKeys(_shared, _digest, _keys);
		SshScanDebugKeys("initial", _keys);

		SshCrypt::Zero(_shared, sizeof(_shared));
		SshPktCipherInit(_session.encrypt, _keys.clientKey, _keys.clientIV, _keys.clientMac);
		SshPktCipherInit(_session.decrypt, _keys.serverKey, _keys.serverIV, _keys.serverMac);
		SshCrypt::Zero(&_keys, sizeof(_keys));

		SetReason("Sending SSH_MSG_NEWKEYS failed");
		if( !SendPlain(newkeys, sizeof(newkeys)) )
			return false;

		SetReason("Missing SSH_MSG_NEWKEYS from server");
		return ReceivePlain() && _length == 1 && _payload[0] == 21;
	}

	bool RequestService()
	{
		SetReason("Encrypted SSH userauth service request failed");
		if( !SshPktWriteSecure(_session.encrypt, _rng, g_sshFrame, sizeof(g_sshFrame), s_service, sizeof(s_service), _timeout, _sequenceOut) )
			return false;

		DebugPacket("send encrypted", s_service[0], sizeof(s_service), _sequenceOut - 1ul);

		SetReason("Invalid SSH MAC, ciphertext, or service reply");
		for( int i = 0; i < 8; i++ )
		{
			if( !ReceiveSecure() )
				return false;
			if( _length == sizeof(s_service) && _payload[0] == 6 &&
				memcmp(_payload + 1, s_service + 1, sizeof(s_service) - 1) == 0 )
				return true;
			if( !_length || (_payload[0] != 2 && _payload[0] != 4 && _payload[0] != 7) )
				return false;
		}
		return false;
	}
};

const unsigned char SshInitialExchange::s_service[17] = {
	5, 0, 0, 0, 12, 's', 's', 'h', '-', 'u', 's', 'e', 'r', 'a', 'u', 't', 'h'
};

bool SshScanExchangeTofu(const char *serverIdent, SSHCRYPT_RNG &rng,
	SSHSCAN_Session &session, SSHSCAN_HostTrust trust, void *trustCtx,
	const char **reason, unsigned long timeout)
{
	if( reason )
		*reason = "KEX failed";
	session.Clear();
	if( !serverIdent || !trust || !rng.initialized || !timeout || timeout >= 0x80000000ul )
		return false;

	SshInitialExchange exchange(serverIdent, trust, trustCtx, rng, session, reason, timeout);
	return exchange.Run();
}

void SSHSCAN_Session::Clear()
{
	SshCrypt::Zero(this, sizeof(*this));
}

void SSHSCAN_Session::RecordSent(size_t length)
{
	outEpochPackets++;
	outEpochBytes += length;
}

void SSHSCAN_Session::RecordReceived(size_t length)
{
	inEpochPackets++;
	inEpochBytes += length;
}

class SshScanWriter
{
public:
	void Begin(unsigned char type)
	{
		_used = 1;
		_good = true;
		g_sshMessage[0] = type;
	}

	void Bytes(const unsigned char *bytes, size_t size)
	{
		if( !_good )
			return;

		if( size > sizeof(g_sshMessage) - _used )
		{
			_good = false;
			return;
		}

		memcpy(g_sshMessage + _used, bytes, size);
		_used += size;
	}

	void Byte(unsigned char value)
	{
		Bytes(&value, 1);
	}

	void U32(unsigned long value)
	{
		unsigned char encoded[4];
		encoded[0] = (unsigned char)(value >> 24);
		encoded[1] = (unsigned char)(value >> 16);
		encoded[2] = (unsigned char)(value >> 8);
		encoded[3] = (unsigned char)value;
		Bytes(encoded, sizeof(encoded));
	}

	void String(const unsigned char *bytes, size_t size)
	{
		U32((unsigned long)size);
		Bytes(bytes, size);
	}

	void Literal(const char *value)
	{
		String((const unsigned char *)value, strlen(value));
	}

	bool Good() const { return _good; }
	size_t Size() const { return _used; }

private:
	size_t _used;
	bool _good;
};

class SshScanReader
{
public:
	SshScanReader(const unsigned char *packet, size_t packetSize, size_t start = 0)
	{
		_packet = packet;
		_size = packetSize;
		_offset = start;
	}

	bool Done() const { return _offset == _size; }

	bool U32(unsigned long &value)
	{
		if( _size - _offset < 4 )
			return false;

		const unsigned char *bytes = _packet + _offset;
		value = ((unsigned long)bytes[0] << 24) | ((unsigned long)bytes[1] << 16) |
				((unsigned long)bytes[2] << 8) | (unsigned long)bytes[3];
		_offset += 4;

		return true;
	}

	const unsigned char *String(size_t &length)
	{
		unsigned long size;
		if( !U32(size) || size > (unsigned long)(_size - _offset) )
			return NULL;

		const unsigned char *bytes = _packet + _offset;
		length = (size_t)size;
		_offset += (size_t)size;
		return bytes;
	}

	/* -1 = malformed, 0 = false, 1 = true. */
	int Flag()
	{
		if( _offset >= _size || _packet[_offset] > 1 )
			return -1;
		return _packet[_offset++];
	}

private:
	const unsigned char *_packet;
	size_t _size;
	size_t _offset;
};

static bool SshScanIs(const unsigned char *s, size_t n, const char *word)
{
	size_t wanted = strlen(word);
	return n == wanted && memcmp(s, word, wanted) == 0;
}

static bool SshScanNameListHas(const unsigned char *s, size_t n, const char *name)
{
	size_t i = 0;
	size_t start;
	while( i < n )
	{
		start = i;
		while( i < n && s[i] != ',' )
			i++;
		if( SshScanIs(s + start, i - start, name) )
			return true;
		i++;
	}
	return false;
}

static bool SshScanSendSecure(SSHSCAN_Session &session, SSHCRYPT_RNG &rng, SshScanWriter &writer,
	unsigned long timeout)
{
	if( !writer.Good() )
		return false;

	if( !SshPktWriteSecure(session.encrypt, rng, g_sshTxFrame, sizeof(g_sshTxFrame), g_sshMessage, writer.Size(), timeout, session.outSequence) )
		return false;

	session.RecordSent(writer.Size());
	DebugPacket("send encrypted", g_sshMessage[0], writer.Size(), session.outSequence - 1ul);
	return true;
}

static const unsigned char *SshScanReadSecure(SSHSCAN_Session &session,
	size_t &size, unsigned long timeout)
{
	const unsigned char *payload = SshPktReadSecure(session.decrypt, g_sshFrame,
		sizeof(g_sshFrame), size, timeout, session.inSequence);
	if( payload == NULL )
		return NULL;

	session.RecordReceived(size);
	DebugPacket("recv encrypted", payload[0], size, session.inSequence - 1ul);
	return payload;
}

static bool SshScanGlobalRequest(SSHSCAN_Session &session, SSHCRYPT_RNG &rng,
	const unsigned char *p, size_t length, unsigned long timeout)
{
	SshScanReader reader(p, length, 1);
	size_t name_size;
	const unsigned char *name = reader.String(name_size);
	if( name == NULL )
		return false;
	int want_reply = reader.Flag();
	if( want_reply < 0 )
		return false;

	/* RFC 4254 allows arbitrary global-request data after want-reply. */
	if( want_reply == 0 )
		return true;

	SshScanWriter w;
	w.Begin(82); /* SSH_MSG_REQUEST_FAILURE */
	return SshScanSendSecure(session, rng, w, timeout);
}

class SshScanChannel;
static bool SshScanRekey(SSHSCAN_Session &session, SSHCRYPT_RNG &rng,
						const unsigned char *firstKex, size_t firstKexLength,
						SshScanChannel *channel, SSHSCAN_Output display, void *ctx,
						const char **reason, unsigned long timeout);

static const unsigned char *SshScanReadControl(SSHSCAN_Session &session, SSHCRYPT_RNG &rng,
							size_t &length, unsigned long timeout)
{
	for( int i = 0; i < 32; i++ )
	{
		const unsigned char *payload = SshScanReadSecure(session, length, timeout);
		if( payload == NULL )
			return NULL;
		if( payload[0] == 2 || payload[0] == 4 || payload[0] == 7 )
		{
			Log('W', "Ignored control type=%d", payload[0]);
			continue; /* IGNORE / DEBUG / EXT_INFO */
		}
		if( payload[0] == 20 )
		{
			if( !SshScanRekey(session, rng, payload, length, NULL, NULL, NULL, NULL, timeout) )
				return NULL;
			continue;
		}
		if( payload[0] == 80 )
		{ /* GLOBAL_REQUEST */
			if( !SshScanGlobalRequest(session, rng, payload, length, timeout) )
				return NULL;
			continue;
		}
		if( payload[0] == 1 )
			return NULL;
		return payload;
	}
	return NULL;
}

SshAuthenticator::SshAuthenticator(SSHSCAN_Session &session, SSHCRYPT_RNG &rng,
	const char *username, SSHSCAN_Password password, SSHSCAN_Challenge challenge,
	void *promptCtx, const char **reason, unsigned long timeout)
	: _session(session), _rng(rng)
{
	_username = username;
	_password = password;
	_challenge = challenge;
	_promptCtx = promptCtx;
	_reason = reason;
	_timeout = timeout;
	_methods = 0;
	_partial = false;
	memset(_secret, 0, sizeof(_secret));
}

SshAuthenticator::~SshAuthenticator()
{
	SshCrypt::Zero(_secret, sizeof(_secret));
	SshCrypt::Zero(g_sshMessage, sizeof(g_sshMessage));
}

bool SshAuthenticator::Login()
{
	if( !_rng.initialized || !_username || !_password || !_timeout || _timeout >= 0x80000000ul )
	{
		SetReason("Invalid SSH authentication parameters");
		return false;
	}

	size_t user_size = strlen(_username);
	if( user_size == 0 || user_size > 64 || !SshScanUtf8Valid((const unsigned char *)_username, user_size) )
		return false;

	for( size_t i = 0; i < user_size; i++ )
		if( (unsigned char)_username[i] <= 32 || (unsigned char)_username[i] == 127 )
			return false;

	if( !SendRequest("none") )
		return false;

	int result = WaitResult(false);
	if( result == 1 )
		return Complete();
	if( result != 0 )
		return false;

	int password_attempts = 0;
	int interactive_attempts = 0;
	for( int attempt = 0; attempt < 8; attempt++ )
	{
		if( (_methods & 1u) && password_attempts < 3 )
		{
			password_attempts++;
			Log('I', "Auth password #%d", password_attempts);
			result = SendPassword();
		}
		else if( (_methods & 2u) && interactive_attempts < 4 )
		{
			interactive_attempts++;
			Log('I', "Auth interactive #%d", interactive_attempts);
			result = SendInteractive();
		}
		else
		{
			SetReason("No supported authentication method remains");
			return false;
		}

		if( result == 1 )
			return Complete();
		if( result < 0 )
			return false;

		/* SSH_MSG_USERAUTH_FAILURE: do not report a successful partial factor
		 * as a wrong password. The initial "none" probe is handled above. */
		if( result == 0 && !_partial )
		{
			if( ((_methods & 1u) && password_attempts < 3) ||
				((_methods & 2u) && interactive_attempts < 4) )
				Log('E', "Permission denied, please try again.");
			else
			{
				SetReason("Permission denied");
				return false;
			}
		}

		if( _partial )
		{
			password_attempts = 3;
			interactive_attempts = 0;
		}
	}

	SetReason("Authentication attempt limit reached");
	return false;
}

void SshAuthenticator::SetReason(const char *message)
{
	if( _reason )
		*_reason = message;
}

bool SshAuthenticator::Complete()
{
	_session.authenticated = true;
	SetReason("SSH user successfully authenticated");
	return true;
}

bool SshAuthenticator::SendRequest(const char *method)
{
	SshScanWriter writer;
	writer.Begin(50);
	writer.Literal(_username);
	writer.Literal("ssh-connection");
	writer.Literal(method);

	SetReason("Cannot send SSH authentication request");
	return SshScanSendSecure(_session, _rng, writer, _timeout);
}

bool SshAuthenticator::ValidResponse(const char *answer)
{
	size_t size = strlen(answer);
	if( size >= sizeof(_secret) || !SshScanUtf8Valid((const unsigned char *)answer, size) )
		return false;

	for( size_t i = 0; i < size; i++ )
		if( (unsigned char)answer[i] < 32 || (unsigned char)answer[i] == 127 )
			return false;

	return true;
}

int SshAuthenticator::WaitResult(bool interactive)
{
	for( int i = 0; i < 32; i++ )
	{
		const unsigned char *packet;
		size_t length;
		SetReason("Invalid authentication response or MAC");
		packet = SshScanReadControl(_session, _rng, length, _timeout);
		if( packet == NULL )
			return -1;

		if( length == 1 && packet[0] == 52 )
			return 1;
		if( packet[0] == 53 )
			continue;
		if( packet[0] == 60 && interactive )
		{
			if( !AnswerChallenge(packet, length) )
				return -1;
			return 2;
		}
		if( packet[0] == 60 )
		{
			SetReason("Server requested an unsupported password change");
			return -1;
		}
		if( packet[0] != 51 )
			return -1;

		SshScanReader reader(packet, length, 1);
		size_t methods_length;
		const unsigned char *methods = reader.String(methods_length);
		if( methods == NULL )
			return -1;
		int partial = reader.Flag();
		if( partial < 0 || !reader.Done() )
			return -1;

		_partial = partial != 0;
		_methods = (SshScanNameListHas(methods, methods_length, "password") ? 1u : 0u) |
			(SshScanNameListHas(methods, methods_length, "keyboard-interactive") ? 2u : 0u);
		return 0;
	}

	SetReason("Too many SSH authentication messages");
	return -1;
}

int SshAuthenticator::SendPassword()
{
	SetReason("Password entry cancelled");
	SshCrypt::Zero(_secret, sizeof(_secret));
	if( !_password(_promptCtx, _secret, sizeof(_secret)) )
		return -1;

	_secret[sizeof(_secret) - 1] = '\0';
	if( !ValidResponse(_secret) || _secret[0] == '\0' )
		return -1;

	SshScanWriter writer;
	writer.Begin(50);
	writer.Literal(_username);
	writer.Literal("ssh-connection");
	writer.Literal("password");
	writer.Byte(0);
	writer.String((const unsigned char *)_secret, strlen(_secret));
	SshCrypt::Zero(_secret, sizeof(_secret));

	SetReason("Cannot transmit encrypted password");
	bool sent = SshScanSendSecure(_session, _rng, writer, _timeout);
	SshCrypt::Zero(g_sshMessage, writer.Size());
	return sent ? WaitResult(false) : -1;
}

int SshAuthenticator::SendInteractive()
{
	SshScanWriter writer;
	writer.Begin(50);
	writer.Literal(_username);
	writer.Literal("ssh-connection");
	writer.Literal("keyboard-interactive");
	writer.Literal(""); /* language */
	writer.Literal(""); /* submethods */

	SetReason("Cannot request keyboard-interactive authentication");
	if( !SshScanSendSecure(_session, _rng, writer, _timeout) )
		return -1;

	for( int i = 0; i < 8; i++ )
	{
		int result = WaitResult(true);
		if( result != 2 )
			return result;
	}

	SetReason("Too many keyboard-interactive challenge rounds");
	return -1;
}

bool SshAuthenticator::AnswerChallenge(const unsigned char *packet, size_t length)
{
	SshScanReader reader(packet, length, 1);
	size_t size;
	const unsigned char *field;

	/* Name, instruction and language are SSH strings, not C strings. */
	for( int i = 0; i < 3; i++ )
	{
		field = reader.String(size);
		if( field == NULL )
			return false;
	}

	unsigned long prompts;
	if( !reader.U32(prompts) || prompts > 4u )
		return false;

	SshScanWriter writer;
	writer.Begin(61); /* SSH_MSG_USERAUTH_INFO_RESPONSE */
	writer.U32(prompts);

	for( unsigned long i = 0; i < prompts; i++ )
	{
		field = reader.String(size);
		if( field == NULL || size > 160u )
			return false;
		int echo = reader.Flag();
		if( echo < 0 )
			return false;

		char prompt[161];
		for( size_t j = 0; j < size; j++ )
			prompt[j] = field[j] >= 32 && field[j] < 127 ? (char)field[j] : '?';
		prompt[size] = '\0';

		SshCrypt::Zero(_secret, sizeof(_secret));
		SetReason("Keyboard-interactive response cancelled");
		bool entered = _challenge ? _challenge(_promptCtx, prompt, echo, _secret, sizeof(_secret)) :
			(!echo && _password(_promptCtx, _secret, sizeof(_secret)));
		_secret[sizeof(_secret) - 1] = '\0';
		if( !entered || !ValidResponse(_secret) )
			return false;

		writer.String((const unsigned char *)_secret, strlen(_secret));
		SshCrypt::Zero(_secret, sizeof(_secret));
	}

	/* No trailing garbage, including additional unrequested prompts. */
	if( !reader.Done() || !writer.Good() )
		return false;

	SetReason("Cannot transmit keyboard-interactive response");
	bool sent = SshScanSendSecure(_session, _rng, writer, _timeout);
	SshCrypt::Zero(g_sshMessage, writer.Size());
	return sent;
}

class SshScanChannel
{
public:
	SshScanChannel()
	{
		_remote = 0;
		_remoteWindow = 0;
		_remoteMax = 0;
		_localWindow = 65536ul;
		_eof = false;
		_closeSent = false;
		_closeReceived = false;
		_pendingFailures = 0;
	}

	void Open(unsigned long remote, unsigned long window, unsigned long maxPacket)
	{
		_remote = remote;
		_remoteWindow = window;
		_remoteMax = maxPacket;
	}

	unsigned long Remote() const { return _remote; }
	bool Eof() const { return _eof; }
	bool CloseSent() const { return _closeSent; }
	bool CloseReceived() const { return _closeReceived; }
	unsigned long PendingFailures() const { return _pendingFailures; }
	void MarkEof() { _eof = true; }
	void MarkCloseSent() { _closeSent = true; }
	void MarkCloseReceived() { _closeReceived = true; }
	bool DeferFailure()
	{
		if( _pendingFailures == 0xFFFFFFFFul )
			return false;
		_pendingFailures++;
		return true;
	}
	void CompleteFailure() { _pendingFailures--; }

	bool AddRemoteWindow(unsigned long amount)
	{
		if( amount > 0xFFFFFFFFul - _remoteWindow )
			return false;

		_remoteWindow += amount;
		return true;
	}

	size_t SendLimit(size_t capacity) const
	{
		unsigned long limit = _remoteWindow;
		if( limit > _remoteMax )
			limit = _remoteMax;
		if( limit > capacity )
			limit = capacity;

		return (size_t)limit;
	}

	void Sent(size_t amount)
	{
		_remoteWindow -= amount; /* amount <= SendLimit() by construction */
	}

	bool Received(size_t amount)
	{
		if( (unsigned long)amount > _localWindow || _eof )
			return false;

		_localWindow -= amount;
		return true;
	}

	bool NeedsCredit() const { return _localWindow <= 32768ul; }
	unsigned long Credit() const { return 65536ul - _localWindow; }
	void Replenish() { _localWindow = 65536ul; }

private:
	unsigned long _remote;
	unsigned long _remoteWindow;
	unsigned long _remoteMax;
	unsigned long _localWindow;
	bool _eof;
	bool _closeSent;
	bool _closeReceived;
	unsigned long _pendingFailures;
};

static bool SshScanSendChannel(SSHSCAN_Session &session, SSHCRYPT_RNG &rng,
	unsigned char message, unsigned long remote, unsigned long timeout)
{
	SshScanWriter w;
	w.Begin(message);
	w.U32(remote);
	return SshScanSendSecure(session, rng, w, timeout);
}

static bool SshScanExpectChannel(SSHSCAN_Session &session, SSHCRYPT_RNG &rng,
	SshScanChannel &channel, const char **reason, unsigned long timeout)
{
	for( int i = 0; i < 32; i++ )
	{
		const unsigned char *packet;
		size_t length;
		packet = SshScanReadControl(session, rng, length, timeout);
		if( packet == NULL )
			return false;

		SshScanReader reader(packet, length, 1);
		unsigned long recipient;

		if( packet[0] == 93 ) /* CHANNEL_WINDOW_ADJUST */
		{
			unsigned long delta;
			if( length != 9 || !reader.U32(recipient) || !reader.U32(delta) || !reader.Done() || recipient != 0ul || !channel.AddRemoteWindow(delta) )
				return false;

			continue;
		}

		if( (packet[0] == 99 || packet[0] == 100) && reader.U32(recipient) && reader.Done() && recipient == 0ul )
		{
			if( packet[0] == 99 )
				return true;

			if( reason != NULL )
				*reason = "Server denied SSH channel request";
			return false;
		}

		return false;
	}

	return false;
}

static int SshScanHandleChannel(SSHSCAN_Session &session, SSHCRYPT_RNG &rng,
	SshScanChannel &channel, const unsigned char *packet, size_t length,
	SSHSCAN_Output display, void *ctx, const char **reason, unsigned long timeout,
	bool allowReplies = true)
{
	const unsigned char type = packet[0];
	SshScanReader reader(packet, length, 1);

	if( type == 1 || type == 20 )
	{
		if( reason != NULL )
			*reason = "SSH transport disconnected or unexpected KEX message";
		return -1;
	}

	if( type == 2 || type == 4 || type == 7 || type == 81 || type == 82 )
	{
		Log('W', "Ignored channel type=%d", type);
		return 0;
	}

	if( type == 80 )
		return SshScanGlobalRequest(session, rng, packet, length, timeout) ? 0 : -1;

	SshScanWriter writer;
	if( type == 90 ) /* Reject unsolicited server-initiated channels. */
	{
		if( !allowReplies )
			return -1;
		size_t name_size;
		const unsigned char *name = reader.String(name_size);
		unsigned long sender;
		if( name == NULL || !reader.U32(sender) )
			return -1;

		writer.Begin(92);
		writer.U32(sender);
		writer.U32(1); /* SSH_OPEN_ADMINISTRATIVELY_PROHIBITED */
		writer.Literal("server channels unsupported");
		writer.Literal("");
		return SshScanSendSecure(session, rng, writer, timeout) ? 0 : -1;
	}

	unsigned long recipient;
	if( type < 93 || type > 100 || !reader.U32(recipient) || recipient != 0ul )
		return -1;

	switch( type )
	{
	case 93: /* CHANNEL_WINDOW_ADJUST */
	{
		unsigned long delta;
		if( !reader.U32(delta) || !reader.Done() || !channel.AddRemoteWindow(delta) )
			return -1;
		return 0;
	}

	case 94: /* CHANNEL_DATA */
	case 95: /* CHANNEL_EXTENDED_DATA (stderr) */
	{
		unsigned long data_type = 0;
		if( type == 95 && !reader.U32(data_type) )
			return -1;

		size_t data_size;
		const unsigned char *data = reader.String(data_size);
		if( data == NULL || !reader.Done() || data_size > 32768u || !channel.Received(data_size) )
			return -1;

		if( type == 94 || data_type == 1ul )
			display(ctx, data, data_size);

		if( allowReplies && channel.NeedsCredit() )
		{
			writer.Begin(93);
			writer.U32(channel.Remote());
			writer.U32(channel.Credit());
			if( !SshScanSendSecure(session, rng, writer, timeout) )
				return -1;

			channel.Replenish();
		}
		return 0;
	}

	case 96: /* CHANNEL_EOF */
		if( !reader.Done() )
			return -1;
		channel.MarkEof();
		return 0;

	case 97: /* CHANNEL_CLOSE */
		if( !reader.Done() )
			return -1;
		channel.MarkCloseReceived();
		if( !allowReplies )
			return 0; /* Reply after NEWKEYS. */
		if( !channel.CloseSent() )
		{
			if( !SshScanSendChannel(session, rng, 97, channel.Remote(), timeout) )
				return -1;
			channel.MarkCloseSent();
		}
		return 1;

	case 98: /* CHANNEL_REQUEST: exit-status / exit-signal */
	{
		size_t name_size;
		const unsigned char *name = reader.String(name_size);
		if( name == NULL )
			return -1;
		int want_reply = reader.Flag();
		if( want_reply < 0 )
			return -1;

		if( SshScanIs(name, name_size, "exit-status") )
		{
			unsigned long exit_status;
			if( !reader.U32(exit_status) || !reader.Done() )
				return -1;

			session.exitStatus = exit_status;
			session.exitStatusReceived = true;
		}
		else if( SshScanIs(name, name_size, "exit-signal") )
		{
			const unsigned char *signal_name;
			const unsigned char *error_text;
			const unsigned char *language;
			size_t signal_length;
			size_t error_length;
			size_t lang_length;

			signal_name = reader.String(signal_length);
			if( signal_name == NULL || signal_length == 0 || reader.Flag() < 0 )
				return -1;
			error_text = reader.String(error_length);
			if( error_text == NULL )
				return -1;
			language = reader.String(lang_length);
			if( language == NULL || !reader.Done() )
				return -1;

			session.exitStatus = 128; /* generic signal failure on DOS */
			session.exitStatusReceived = true;
		}

		if( want_reply )
		{
			if( allowReplies )
			{
				if( !SshScanSendChannel(session, rng, 100, channel.Remote(), timeout) )
					return -1;
			}
			else if( !channel.DeferFailure() )
				return -1;
		}
		return 0;
	}

	default: 
		return -1;
	}
}

/* Both directions retain their current keys until their respective NEWKEYS.
 * A single object owns all transient key material and erases it on exit. */
class SshRekey
{
public:
	SshRekey(SSHSCAN_Session &session, SSHCRYPT_RNG &rng,
		SshScanChannel *channel, SSHSCAN_Output display, void *ctx,
		const char **reason, unsigned long timeout)
		: _session(session), _rng(rng)
	{
		_channel = channel;
		_display = display;
		_ctx = ctx;
		_reason = reason;
		_timeout = timeout;
		_serverSize = 0;
		_pendingGlobalFailures = 0;
		_pendingOpenCount = 0;
	}

	~SshRekey()
	{
		SshCrypt::Zero(&_keys, sizeof(_keys));
		SshCrypt::Zero(_ephemeral, sizeof(_ephemeral));
		SshCrypt::Zero(_shared, sizeof(_shared));
		SshCrypt::Zero(_cookie, sizeof(_cookie));
		SshCrypt::Zero(_digest, sizeof(_digest));
		SshCrypt::Zero(_publicKey, sizeof(_publicKey));
	}

	bool Run(const unsigned char *serverKex, size_t serverKexSize)
	{
		SetReason("SSH rekey failed");
		if( !SendKexinit(serverKex, serverKexSize) || !NegotiateKex() || !ExchangeEcdh() || !InstallKeys() )
			return false;

		SetReason("SSH transport rekey completed");
		return true;
	}

private:
	SSHSCAN_Session &_session;
	SSHCRYPT_RNG &_rng;
	SshScanChannel *_channel;
	SSHSCAN_Output _display;
	void *_ctx;
	const char **_reason;
	unsigned long _timeout;
	unsigned long _pendingGlobalFailures;
	unsigned long _pendingOpens[16];
	size_t _pendingOpenCount;
	const unsigned char *_packet;
	size_t _length;
	size_t _serverSize;
	size_t _clientSize;
	size_t _ecdhSize;
	SshEcdhReply _reply;
	SSHPKT_Keys _keys;
	unsigned char _cookie[16];
	unsigned char _ephemeral[32];
	unsigned char _publicKey[32];
	unsigned char _shared[32];
	unsigned char _digest[32];
	unsigned char _ecdhInit[37];

	void SetReason(const char *message)
	{
		if( _reason )
			*_reason = message;
	}

	bool Send(const unsigned char *data, size_t size)
	{
		if( !SshPktWriteSecure(_session.encrypt, _rng, g_sshTxFrame, sizeof(g_sshTxFrame), data, size, _timeout, _session.outSequence) )
			return false;

		_session.RecordSent(size);
		DebugPacket("send encrypted", data[0], size, _session.outSequence - 1ul);
		return true;
	}

	bool Receive(unsigned long timeout = 0)
	{
		_packet = SshScanReadSecure(_session, _length, timeout ? timeout : _timeout);
		return _packet != NULL && _length != 0;
	}

	bool HandleInFlight()
	{
		const unsigned char type = _packet[0];
		if( type == 2 || type == 3 || type == 4 || type == 7 || type == 81 || type == 82 )
			return true;

		SshScanReader reader(_packet, _length, 1);
		if( type == 80 ) /* GLOBAL_REQUEST: reply after NEWKEYS. */
		{
			size_t name_size;
			const unsigned char *name = reader.String(name_size);
			if( name == NULL )
				return false;
			int want_reply = reader.Flag();
			if( want_reply < 0 )
				return false;
			if( want_reply != 0 )
			{
				if( _pendingGlobalFailures == 0xFFFFFFFFul )
					return false;
				_pendingGlobalFailures++;
			}
			return true;
		}

		if( type == 90 ) /* Server-initiated CHANNEL_OPEN: reject later. */
		{
			size_t name_size;
			const unsigned char *name = reader.String(name_size);
			unsigned long sender;
			unsigned long window;
			unsigned long max_packet;
			if( name == NULL || !reader.U32(sender) ||
				!reader.U32(window) || !reader.U32(max_packet) )
				return false;
			if( _pendingOpenCount == sizeof(_pendingOpens) / sizeof(_pendingOpens[0]) )
			{
				SetReason("Too many server channel opens during rekey");
				return false;
			}
			_pendingOpens[_pendingOpenCount++] = sender;
			return true;
		}

		if( !_channel || !_display )
			return false;
		return SshScanHandleChannel(_session, _rng, *_channel, _packet,
			_length, _display, _ctx, _reason, _timeout, false) == 0;
	}

	bool SendKexinit(const unsigned char *serverKex, size_t serverKexSize)
	{
		/* The received KEXINIT belongs to the old inbound cipher and must
		 * survive subsequent reads into the shared receive buffer. */
		if( serverKex )
		{
			if( !serverKexSize || serverKex[0] != 20 || serverKexSize > sizeof(g_serverKex) )
				return false;

			memcpy(g_serverKex, serverKex, serverKexSize);
			_serverSize = serverKexSize;
		}

		if( !_rng.Generate(_cookie, sizeof(_cookie)) )
			return false;
		_clientSize = SshPktMakeKexinit(_cookie, g_clientKex, sizeof(g_clientKex));
		DebugHex("rekey.kex_cookie", _cookie, sizeof(_cookie));

		SetReason("Could not send rekey SSH_MSG_KEXINIT");
		if( _clientSize == 0 || !Send(g_clientKex, _clientSize) )
			return false;

		if( _serverSize )
			return true;

		SetReason("No SSH_MSG_KEXINIT from server during rekey");
		unsigned long start = g_transport.Ticks();
		for( ;; )
		{
			/* There is no packet-count limit on in-flight messages, but
			 * the peer must complete negotiation within the timeout. */
			unsigned long elapsed = (unsigned long)(g_transport.Ticks() - start);
			if( elapsed >= _timeout || !Receive(_timeout - elapsed) )
				return false;

			if( _packet[0] == 20 )
			{
				if( _length > sizeof(g_serverKex) )
					return false;

				memcpy(g_serverKex, _packet, _length);
				_serverSize = _length;
				return true;
			}

			/* Application data sent before the peer KEXINIT is in flight.
			 * No channel or global replies are allowed until NEWKEYS. */
			SetReason("Invalid in-flight message during rekey");
			if( !HandleInFlight() )
				return false;
			SetReason("No SSH_MSG_KEXINIT from server during rekey");
		}
	}

	bool NegotiateKex()
	{
		SetReason("Incompatible or malformed rekey SSH_MSG_KEXINIT");
		int discard = DosSshNegotiateKexinit(g_serverKex, _serverSize, _reason);
		if( discard < 0 )
			return false;
		Log('I', "Rekey negotiated guess=%d", discard);

		/* If the peer guessed incorrectly, discard the first KEX packet. */
		return !discard || Receive();
	}

	bool ExchangeEcdh()
	{
		bool found = false;

		_rng.Generate(_ephemeral, sizeof(_ephemeral));
		DebugHex("rekey.x25519.private", _ephemeral, sizeof(_ephemeral));

		{
			LongOp key_op("X25519 key");
			SshCurve::ScalarMult(_publicKey, _ephemeral, basepoint);
		}
		DebugHex("rekey.x25519.public", _publicKey, sizeof(_publicKey));
		_ecdhSize = SshPktMakeEcdhInit(_publicKey, _ecdhInit, sizeof(_ecdhInit));

		SetReason("Could not send SSH_MSG_KEX_ECDH_INIT during rekey");
		if( _ecdhSize == 0 || !Send(_ecdhInit, _ecdhSize) )
			return false;

		SetReason("Missing or invalid SSH_MSG_KEX_ECDH_REPLY during rekey");
		unsigned long start = g_transport.Ticks();
		for( ;; )
		{
			unsigned long elapsed = (unsigned long)(g_transport.Ticks() - start);
			if( elapsed >= _timeout || !Receive(_timeout - elapsed) )
				return false;

			if( _packet[0] == 31 )
			{
				found = true;
				break;
			}

			if( _packet[0] != 2 && _packet[0] != 3 && _packet[0] != 4 && _packet[0] != 7 )
				return false;
		}

		if( !found || !_reply.Parse(_packet, _length) )
			return false;

		DebugHex("rekey.server.x25519.public", _reply.ServerPublic(), 32);
		DebugHex("rekey.server.ed25519.public", _reply.HostPublic(), 32);
		DebugHex("rekey.server.ed25519.signature", _reply.Signature(), 64);
		DebugHex("rekey.server.hostkey_blob", _reply.HostKey(), _reply.HostKeyLength());

		if( _reply.HostKeyLength() != _session.serverHostKeyLength ||
			memcmp(_reply.HostKey(), _session.serverHostKey, _reply.HostKeyLength()) != 0 )
		{
			SetReason("SSH host key changed during rekey");
			return false;
		}

		{
			LongOp shared_op("X25519 secret");
			SshCurve::ScalarMult(_shared, _ephemeral, _reply.ServerPublic());
		}
		DebugHex("rekey.x25519.shared_secret", _shared, sizeof(_shared));

		SshExchange exchange;
		exchange.SetIdentifiers((const unsigned char *)SSHSCAN_CLIENT_ID,
			sizeof(SSHSCAN_CLIENT_ID) - 3, (const unsigned char *)_session.serverIdent,
			strlen(_session.serverIdent));
		exchange.SetKexinit(g_clientKex, _clientSize, g_serverKex, _serverSize);
		exchange.SetEcdh(_reply, _publicKey, _shared);

		SetReason("Invalid X25519 rekey secret or exchange hash");
		if( !exchange.Hash(_digest) )
			return false;
		DebugHex("rekey.exchange_hash", _digest, sizeof(_digest));

		SetReason("Invalid server Ed25519 signature during rekey");
		LongOp verify_op("Ed25519 verify");
		return SshCurve::VerifyEd25519(_reply.HostPublic(), _reply.Signature(),
			_digest, sizeof(_digest));
	}

	bool InstallKeys()
	{
		static const unsigned char newkeys[1] = {21};

		SshPktDeriveRekey(_shared, _digest, _session.sessionId, _keys);
		SshScanDebugKeys("rekey", _keys);

		/* NEWKEYS leaves using the OLD outbound cipher.  Switch immediately
		 * afterwards; the incoming cipher remains OLD until peer NEWKEYS. */
		SetReason("Cannot transmit SSH_MSG_NEWKEYS during rekey");
		if( !Send(newkeys, sizeof(newkeys)) )
			return false;

		SshPktCipherInit(_session.encrypt, _keys.clientKey, _keys.clientIV, _keys.clientMac);
		_session.outEpochPackets = 0;
		_session.outEpochBytes = 0;

		SetReason("No SSH_MSG_NEWKEYS received during rekey");
		unsigned long start = g_transport.Ticks();
		for( ;; )
		{
			unsigned long elapsed = (unsigned long)(g_transport.Ticks() - start);
			if( elapsed >= _timeout || !Receive(_timeout - elapsed) )
				return false;

			if( _length == 1 && _packet[0] == 21 )
				break;

			if( _packet[0] != 2 && _packet[0] != 3 && _packet[0] != 4 )
				return false;
		}

		SshPktCipherInit(_session.decrypt, _keys.serverKey, _keys.serverIV, _keys.serverMac);
		_session.inEpochPackets = 0;
		_session.inEpochBytes = 0;
		_session.lastKexTicks = g_transport.Ticks();
		_session.rekeyRequested = false;
		Log('S', "Rekey installed rx=%lu tx=%lu", _session.inSequence, _session.outSequence);

		/* Send all deferred application replies using the NEW cipher. */
		while( _pendingGlobalFailures )
		{
			SshScanWriter failure;
			failure.Begin(82); /* REQUEST_FAILURE */
			if( !SshScanSendSecure(_session, _rng, failure, _timeout) )
				return false;
			_pendingGlobalFailures--;
		}

		for( size_t i = 0; i < _pendingOpenCount; i++ )
		{
			SshScanWriter rejected;
			rejected.Begin(92); /* CHANNEL_OPEN_FAILURE */
			rejected.U32(_pendingOpens[i]);
			rejected.U32(1); /* SSH_OPEN_ADMINISTRATIVELY_PROHIBITED */
			rejected.Literal("server channels unsupported");
			rejected.Literal("");
			if( !SshScanSendSecure(_session, _rng, rejected, _timeout) )
				return false;
		}

		if( _channel )
		{
			while( _channel->PendingFailures() )
			{
				if( !SshScanSendChannel(_session, _rng, 100, _channel->Remote(), _timeout) )
					return false;
				_channel->CompleteFailure();
			}
			if( _channel->CloseReceived() && !_channel->CloseSent() )
			{
				if( !SshScanSendChannel(_session, _rng, 97, _channel->Remote(), _timeout) )
					return false;
				_channel->MarkCloseSent();
			}
		}

		/* Flush delayed window credit using the NEW outbound cipher. */
		if( _channel && !_channel->CloseReceived() && _channel->NeedsCredit() )
		{
			SshScanWriter credit;
			credit.Begin(93);
			credit.U32(_channel->Remote());
			credit.U32(_channel->Credit());
			if( !SshScanSendSecure(_session, _rng, credit, _timeout) )
				return false;
			_channel->Replenish();
		}

		return true;
	}
};

static bool SshScanRekey(SSHSCAN_Session &session, SSHCRYPT_RNG &rng,
						const unsigned char *firstKex, size_t firstKexLength,
						SshScanChannel *channel, SSHSCAN_Output display, void *ctx,
						const char **reason, unsigned long timeout)
{
	Log('S', "Rekey %s rx=%lu tx=%lu in=%lu out=%lu",
		firstKex ? "server" : "client", session.inSequence, session.outSequence,
		session.inEpochPackets, session.outEpochPackets);
	SshRekey exchange(session, rng, channel, display, ctx, reason, timeout);
	bool ok = exchange.Run(firstKex, firstKexLength);
	Log('S', "Rekey result=%d %s", ok, reason && *reason ? *reason : "unknown");
	return ok;
}

bool SSHSCAN_Session::NeedsRekey(unsigned long now) const
{
	/* 1 GiB of payload or one million packets in either direction; the
	 * optional 1-hour timer is specified in the caller's native ticks. */
	return rekeyRequested || inEpochPackets >= 1000000ul ||
		outEpochPackets >= 1000000ul || inEpochBytes >= 1073741824ul ||
		outEpochBytes >= 1073741824ul ||
		(rekeyPeriodTicks &&
			(unsigned long)(now - lastKexTicks) >= rekeyPeriodTicks);
}

/* All exits from the interactive loop erase queued input and SSH payloads.
 * The key buffer is borrowed, not copied or dynamically allocated. */
class SshShellCleanup
{
public:
	explicit SshShellCleanup(unsigned char (&keys)[256]) : _keys(keys) {}
	~SshShellCleanup()
	{
		SshCrypt::Zero(_keys, sizeof(_keys));
		SshCrypt::Zero(g_sshMessage, sizeof(g_sshMessage));
	}

private:
	unsigned char (&_keys)[256];
};

/* Local detach does not require channel send-window credit. */
static bool SshScanLocalDetach(SSHSCAN_Session &session,
	SSHCRYPT_RNG &rng, SshScanChannel &channel, const char **reason, unsigned long timeout)
{
	if( !SshScanSendChannel(session, rng, 96, channel.Remote(), timeout) ||
		!SshScanSendChannel(session, rng, 97, channel.Remote(), timeout) )
		return false;
	channel.MarkCloseSent();
	if( reason )
		*reason = "Local terminal disconnected";
	return true;
}

bool SshScanShell(SSHSCAN_Session &session, SSHCRYPT_RNG &rng, int cols,
	int rows, const char *terminalType, SSHSCAN_Input keyboard, SSHSCAN_Output display,
	void *terminalCtx, const char **reason, unsigned long timeout)
{
	if( reason )
		*reason = "SSH channel setup failed";
	if( !session.authenticated || !rng.initialized || !keyboard || !display || !terminalType ||
		(strcmp(terminalType, "xterm") != 0 && strcmp(terminalType, "vt100") != 0) ||
		cols < 40 || cols > 132 || rows < 20 || rows > 50 ||
		timeout == 0 || timeout >= 0x80000000ul )
		return false;

	unsigned char keys[256];
	SshShellCleanup cleanup(keys);
	SshScanChannel channel;
	SshScanWriter writer;
	writer.Begin(90); /* CHANNEL_OPEN session */
	writer.Literal("session");
	writer.U32(0); /* local channel 0 */
	writer.U32(65536ul); /* receive window */
	writer.U32(32768ul); /* maximum channel payload */
	if( reason )
		*reason = "Cannot open SSH session channel";
	if( !SshScanSendSecure(session, rng, writer, timeout) )
		return false;

	const unsigned char *packet;
	size_t length;
	{
		packet = SshScanReadControl(session, rng, length, timeout);
		if( packet == NULL )
			return false;
		if( length < 5 || (packet[0] != 91 && packet[0] != 92) )
			return false;

		SshScanReader confirmation(packet, length, 1);
		unsigned long recipient;
		if( !confirmation.U32(recipient) || recipient != 0ul )
			return false;
		if( packet[0] == 92 )
		{
			if( reason )
				*reason = "Server refused session channel";
			return false;
		}

		unsigned long remote;
		unsigned long window;
		unsigned long max_packet;
		if( !confirmation.U32(remote) || !confirmation.U32(window) ||
			!confirmation.U32(max_packet) || max_packet == 0ul )
			return false;
		channel.Open(remote, window, max_packet);
	}

	writer.Begin(98); /* CHANNEL_REQUEST pty-req */
	writer.U32(channel.Remote());
	writer.Literal("pty-req");
	writer.Byte(1); /* want reply */
	/* The caller selects TERM. xterm (not xterm-256color) supports
	 * F1-F12 and basic/bright ANSI colours on both DOS display types. */
	writer.Literal(terminalType);
	writer.U32(cols);
	writer.U32(rows);
	writer.U32(0); /* pixels: not available in DOS text mode */
	writer.U32(0);
	const unsigned char end_modes[] = {0};
	writer.String(end_modes, sizeof(end_modes)); /* TTY_OP_END */
	if( reason )
		*reason = "PTY request rejected or timed out";
	if( !SshScanSendSecure(session, rng, writer, timeout) ||
		!SshScanExpectChannel(session, rng, channel, reason, timeout) )
		return false;

	writer.Begin(98); /* CHANNEL_REQUEST shell */
	writer.U32(channel.Remote());
	writer.Literal("shell");
	writer.Byte(1);
	if( reason )
		*reason = "Remote shell request rejected or timed out";
	if( !SshScanSendSecure(session, rng, writer, timeout) || !SshScanExpectChannel(session, rng, channel, reason, timeout) )
		return false;

	if( reason )
		*reason = "SSH interactive channel or transport failure";
	SshPacketReader reader;
	for( ;; )
	{
		/* A partially received encrypted frame belongs to the old cipher.
		 * Never start a local rekey before it has been consumed. */
		if( reader.IsIdle() && session.NeedsRekey(g_transport.Ticks()) )
		{
			if( !SshScanRekey(session, rng, NULL, 0, &channel, display, terminalCtx, reason, timeout) )
				return false;
			if( channel.CloseReceived() )
			{
				if( reason )
					*reason = "SSH shell channel closed during rekey";
				return true;
			}
			if( reason )
				*reason = "SSH interactive channel or transport failure";
		}

		int polled = reader.Poll(session.decrypt, g_sshFrame, sizeof(g_sshFrame), &packet, length, session.inSequence);
		if( polled < 0 )
		{
			Log('E', "SSH packet/MAC invalid; disconnected");
			return false;
		}
		if( polled > 0 )
		{
			session.RecordReceived(length);
			DebugPacket("recv encrypted", packet[0], length, session.inSequence - 1ul);
			if( packet[0] == 20 )
			{
				if( !SshScanRekey(session, rng, packet, length, &channel, display, terminalCtx, reason, timeout) )
					return false;
				if( channel.CloseReceived() )
				{
					if( reason )
						*reason = "SSH shell channel closed during rekey";
					return true;
				}
				if( reason )
					*reason = "SSH interactive channel or transport failure";
				continue;
			}

			int status = SshScanHandleChannel(session, rng, channel, packet, length, display, terminalCtx, reason, timeout);
			if( status < 0 )
				return false;
			if( status > 0 )
			{
				if( reason )
					*reason = "SSH shell channel closed";
				return true;
			}
		}

		/* Poll local escape on EVERY iteration, even when the remote SSH
		 * channel window is zero or the server has sent CHANNEL_EOF.
		 * capacity=0 never sends normal input; DOS adapter buffers keys. */
		int command = keyboard(terminalCtx, NULL, 0);
		if( command == -2 )
		{
			if( reason )
				*reason = "DOS terminal out of memory";
			return false;
		}
		if( command == -1 )
			return SshScanLocalDetach(session, rng, channel, reason, timeout);
		if( !channel.Eof() )
		{
			size_t count = channel.SendLimit(sizeof(keys));
			if( count )
			{
				size_t key_count = 0;
				int next_key = 0;

				/* Drain only keys already in the BIOS queue; no added latency. */
				while( key_count < count )
				{
					next_key = keyboard(terminalCtx, keys + key_count, count - key_count);
					if( next_key <= 0 )
						break;
					key_count += (size_t)next_key;
				}

				if( next_key == -2 )
				{
					if( reason )
						*reason = "DOS terminal out of memory";
					return false;
				}
				if( next_key < 0 )
					return SshScanLocalDetach(session, rng, channel, reason, timeout);
				if( key_count > 0 )
				{
					writer.Begin(94); /* CHANNEL_DATA */
					writer.U32(channel.Remote());
					writer.String(keys, key_count);
					if( !SshScanSendSecure(session, rng, writer, timeout) )
						return false;
					/* Interactive input can itself contain secret text. */
					SshCrypt::Zero(keys, key_count);
					SshCrypt::Zero(g_sshMessage, writer.Size());
					channel.Sent(key_count);
				}
			}
		}
		g_transport.Pump();
	}
}

// The SHA256 fingerprint uses OpenSSH's unpadded base64 representation.
static const char g_sshBase64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Exactly 32 input bytes give 43 unpadded base64 characters.
static void SshScanBase64(const unsigned char digest[32], char out[44])
{
	for( size_t i = 0, j = 0; i < 30; i += 3, j += 4 )
	{
		unsigned int a = digest[i];
		unsigned int b = digest[i + 1];
		unsigned int c = digest[i + 2];
		out[j] = g_sshBase64[a >> 2];
		out[j + 1] = g_sshBase64[((a & 3) << 4) | (b >> 4)];
		out[j + 2] = g_sshBase64[((b & 15) << 2) | (c >> 6)];
		out[j + 3] = g_sshBase64[c & 63];
	}
	unsigned int a = digest[30];
	unsigned int b = digest[31];
	out[40] = g_sshBase64[a >> 2];
	out[41] = g_sshBase64[((a & 3) << 4) | (b >> 4)];
	out[42] = g_sshBase64[(b & 15) << 2];
	out[43] = '\0';
}

void SshScanFingerprint(const unsigned char digest[32], char result[52])
{
	memcpy(result, "SHA256:", 7);
	SshScanBase64(digest, result + 7);
}

bool SshScanUtf8Valid(const unsigned char *p, size_t size)
{
	if( !p && size )
		return false;

	size_t i = 0;
	while( i < size )
	{
		unsigned char c = p[i++];
		if( c < 0x80 )
			continue;
		size_t need;
		if( c >= 0xC2 && c <= 0xDF )
			need = 1;
		else if( c >= 0xE0 && c <= 0xEF )
			need = 2;
		else if( c >= 0xF0 && c <= 0xF4 )
			need = 3;
		else
			return false;
		if( need > size - i )
			return false;
		if( c == 0xE0 && p[i] < 0xA0 )
			return false;
		if( c == 0xED && p[i] >= 0xA0 )
			return false;
		if( c == 0xF0 && p[i] < 0x90 )
			return false;
		if( c == 0xF4 && p[i] >= 0x90 )
			return false;
		for( size_t j = 0; j < need; j++ )
			if( (p[i++] & 0xC0) != 0x80 )
				return false;
	}
	return true;
}
