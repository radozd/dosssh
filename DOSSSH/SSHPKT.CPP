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
#include <stddef.h>

#include "SSHPKT.H"
#include "GLOBALS.H"
#include "SSHSHA.H"
#include "DEBUG.H"

static void SshPktPut32(unsigned char *p, unsigned long n)
{
	p[0] = (unsigned char)(n >> 24);
	p[1] = (unsigned char)(n >> 16);
	p[2] = (unsigned char)(n >> 8);
	p[3] = (unsigned char)n;
}

static unsigned long SshPktGet32(const unsigned char *p)
{
	return ((unsigned long)p[0] << 24) | ((unsigned long)p[1] << 16) | ((unsigned long)p[2] << 8) |
			(unsigned long)p[3];
}

size_t SshPktPaddingSize(size_t payloadLength)
{
	if( payloadLength == 0 )
		return 0;

	unsigned long total = (unsigned long)payloadLength + 5ul;
	int pad = (int)(8ul - (total % 8ul));
	if( pad < 4 )
		pad += 8;
	if( (unsigned long)payloadLength + 1ul + pad > SSHPKT_MAX_PACKET )
		return 0;
	return (size_t)pad;
}

size_t SshPktEncodePlain(const unsigned char *payload, size_t payloadLength,
	const unsigned char *randomPad, size_t padLength, unsigned char *frame, size_t capacity)
{
	size_t needed_pad = SshPktPaddingSize(payloadLength);
	if( payload == NULL || randomPad == NULL || frame == NULL || needed_pad == 0 || needed_pad != padLength )
		return 0;

	unsigned long packet_length = (unsigned long)payloadLength + 1ul + padLength;
	if( (unsigned long)capacity < packet_length + 4ul )
		return 0;

	SshPktPut32(frame, packet_length);
	frame[4] = (unsigned char)padLength;
	/* Input buffers must not overlap the destination. */
	memcpy(frame + 5, payload, payloadLength);
	memcpy(frame + 5 + payloadLength, randomPad, padLength);
	return (size_t)(packet_length + 4ul);
}

const unsigned char *SshPktDecodePlain(const unsigned char *frame, size_t frameLength, size_t &payloadLength)
{
	if( frame == NULL || frameLength < 12 || frameLength > SSHPKT_MAX_FRAME )
		return NULL;

	unsigned long packet_length = SshPktGet32(frame);
	if( packet_length < 6 || packet_length > SSHPKT_MAX_PACKET ||
		packet_length + 4ul != (unsigned long)frameLength || ((packet_length + 4ul) & 7ul) != 0 )
	{
		return NULL;
	}

	int pad = frame[4];
	if( pad < 4 || (unsigned long)pad + 1ul >= packet_length )
		return NULL;

	payloadLength = (size_t)(packet_length - 1ul - pad);
	return frame + 5;
}

static bool SshPktReadBefore(unsigned char *out, size_t length, unsigned long started, unsigned long deadline)
{
	unsigned long elapsed = (unsigned long)(g_transport.Ticks() - started);
	if( elapsed >= deadline )
		return false;

	return DosSshReadExact(out, length, deadline - elapsed);
}

const unsigned char *SshPktReadPlain(unsigned char *frame, size_t capacity,
	size_t &payloadLength, unsigned long deadline, unsigned long *sequence)
{
	if( frame == NULL || capacity < 12 || deadline == 0 || deadline >= 0x80000000ul )
		return NULL;

	unsigned long started = g_transport.Ticks();
	if( !SshPktReadBefore(frame, 4, started, deadline) )
		return NULL;

	unsigned long packet_length = SshPktGet32(frame);
	/* Reject a huge packet BEFORE attempting to read it or allocate memory. */
	if( packet_length < 6 || packet_length > SSHPKT_MAX_PACKET || ((packet_length + 4ul) & 7ul) != 0 ||
		packet_length + 4ul > (unsigned long)capacity )
	{
		return NULL;
	}

	if( !SshPktReadBefore(frame + 4, (size_t)packet_length, started, deadline) )
		return NULL;

	const unsigned char *payload = SshPktDecodePlain(frame, (size_t)(packet_length + 4ul), payloadLength);
	if( payload == NULL )
		return NULL;

	if( sequence != NULL )
		*sequence = (*sequence + 1ul) & 0xFFFFFFFFul;
	return payload;
}

bool SshPktWritePlain(const unsigned char *frame, size_t frameLength,
	unsigned long timeout, unsigned long *sequence)
{
	size_t payload_length;
	if( SshPktDecodePlain(frame, frameLength, payload_length) == NULL || timeout == 0 ||
		timeout >= 0x80000000ul || !DosSshWriteAll(frame, frameLength, timeout) )
	{
		return false;
	}
	if( sequence != NULL )
		*sequence = (*sequence + 1ul) & 0xFFFFFFFFul;
	return true;
}

size_t SshPktMakeKexinit(const unsigned char cookie[16], unsigned char *p, size_t capacity)
{
	if( cookie == NULL || p == NULL || capacity < 62 )
		return 0;

	static const char *names[10] = {
		"curve25519-sha256", "ssh-ed25519", "aes128-ctr", "aes128-ctr", "hmac-sha2-256",
		"hmac-sha2-256", "none", "none", "", ""};
	size_t offset = 17;
	for( int i = 0; i < 10; i++ )
	{
		unsigned long n = (unsigned long)strlen(names[i]);
		if( (unsigned long)offset + 4ul + n + 5ul > capacity )
			return 0;
		offset += 4 + (size_t)n;
	}
	p[0] = 20; /* SSH_MSG_KEXINIT */
	memcpy(p + 1, cookie, 16);
	offset = 17;
	for( int i = 0; i < 10; i++ )
	{
		size_t length = strlen(names[i]);
		SshPktPut32(p + offset, (unsigned long)length);
		offset += 4;
		memcpy(p + offset, names[i], length);
		offset += length;
	}
	p[offset++] = 0; /* first_kex_packet_follows = false */
	SshPktPut32(p + offset, 0);
	offset += 4; /* reserved */
	return offset;
}

/* Exact-size SSH 'string' parser: reject 32-bit lengths that overflow the
 * remaining 16-bit payload rather than narrowing them first. */
static const unsigned char *SshPktString(const unsigned char *p, size_t length, size_t &offset, size_t &used)
{
	if( p == NULL || offset > length || length - offset < 4 )
		return NULL;
	unsigned long size = SshPktGet32(p + offset);
	offset += 4;
	if( size > (unsigned long)(length - offset) )
		return NULL;
	const unsigned char *data = p + offset;
	used = (size_t)size;
	offset += used;
	return data;
}

static bool SshPktName(const unsigned char *p, size_t used)
{
	static const char name[] = "ssh-ed25519";
	return used == sizeof(name) - 1 && memcmp(p, name, sizeof(name) - 1) == 0;
}

size_t SshPktMakeEcdhInit(const unsigned char clientPublic[32], unsigned char *payload, size_t capacity)
{
	if( clientPublic == NULL || payload == NULL || capacity < 37 )
		return 0;

	payload[0] = 30; /* SSH_MSG_KEX_ECDH_INIT */
	SshPktPut32(payload + 1, 32);
	memcpy(payload + 5, clientPublic, 32);
	return 37;
}

SshEcdhReply::SshEcdhReply()
{
	_hostKey = NULL;
	_hostKeyLength = 0;
	_hostPublic = NULL;
	_serverPublic = NULL;
	_signature = NULL;
	_valid = false;
}

bool SshEcdhReply::Parse(const unsigned char *packet, size_t packetSize)
{
	_valid = false;

	if( packet == NULL || packetSize < 1 || packetSize > SSHPKT_MAX_PACKET || packet[0] != 31 )
		return false;

	size_t pos = 1;
	size_t host_key_size;
	size_t server_public_size;
	size_t signature_blob_size;
	const unsigned char *host_key;
	const unsigned char *server_public;
	const unsigned char *signature_blob;

	host_key = SshPktString(packet, packetSize, pos, host_key_size);
	if( host_key == NULL )
		return false;
	server_public = SshPktString(packet, packetSize, pos, server_public_size);
	if( server_public == NULL || server_public_size != 32 )
		return false;
	signature_blob = SshPktString(packet, packetSize, pos, signature_blob_size);
	if( signature_blob == NULL || pos != packetSize )
		return false;

	size_t inner_pos = 0;
	size_t algorithm_size;

	const unsigned char *algorithm = SshPktString(host_key, host_key_size, inner_pos, algorithm_size);
	if( algorithm == NULL || !SshPktName(algorithm, algorithm_size) )
		return false;

	size_t host_public_size;
	const unsigned char *host_public = SshPktString(host_key, host_key_size, inner_pos, host_public_size);
	if( host_public == NULL || host_public_size != 32 || inner_pos != host_key_size )
		return false;

	inner_pos = 0;
	algorithm = SshPktString(signature_blob, signature_blob_size, inner_pos, algorithm_size);
	if( algorithm == NULL || !SshPktName(algorithm, algorithm_size) )
		return false;

	size_t signature_size;
	const unsigned char *signature = SshPktString(signature_blob, signature_blob_size, inner_pos, signature_size);
	if( signature == NULL || signature_size != 64 || inner_pos != signature_blob_size )
		return false;

	_hostKey = host_key;
	_hostKeyLength = host_key_size;
	_hostPublic = host_public;
	_serverPublic = server_public;
	_signature = signature;
	_valid = true;
	return true;
}

/* SHA-256 over one RFC 4251 SSH 'string' value. */
static void SshPktHashString(Sha256State &state, const unsigned char *data, size_t length)
{
	unsigned char size[4];
	SshPktPut32(size, (unsigned long)length);
	state.Bytes(size, sizeof(size));
	state.Bytes(data, length);
}

SshExchange::SshExchange()
{
	_clientIdent = NULL;
	_clientIdentLength = 0;
	_serverIdent = NULL;
	_serverIdentLength = 0;
	_clientKex = NULL;
	_clientKexLength = 0;
	_serverKex = NULL;
	_serverKexLength = 0;
	_hostKey = NULL;
	_hostKeyLength = 0;
	_clientPublic = NULL;
	_serverPublic = NULL;
	_sharedSecret = NULL;
}

void SshExchange::SetIdentifiers(const unsigned char *clientIdent, size_t clientLength,
	const unsigned char *serverIdent, size_t serverLength)
{
	_clientIdent = clientIdent;
	_clientIdentLength = clientLength;
	_serverIdent = serverIdent;
	_serverIdentLength = serverLength;
}

void SshExchange::SetKexinit(const unsigned char *clientKex, size_t clientLength,
	const unsigned char *serverKex, size_t serverLength)
{
	_clientKex = clientKex;
	_clientKexLength = clientLength;
	_serverKex = serverKex;
	_serverKexLength = serverLength;
}

void SshExchange::SetEcdh(const SshEcdhReply &reply,
	const unsigned char clientPublic[32], const unsigned char sharedSecret[32])
{
	_hostKey = reply.HostKey();
	_hostKeyLength = reply.HostKeyLength();
	_clientPublic = clientPublic;
	_serverPublic = reply.ServerPublic();
	_sharedSecret = sharedSecret;
}

bool SshExchange::IsIdentificationValid(const unsigned char *ident, size_t length)
{
	if( ident == NULL || length < 8 || length > 255 || memcmp(ident, "SSH-", 4) != 0 )
		return false;

	for( size_t i = 0; i < length; i++ )
		if( ident[i] < 32 || ident[i] > 126 )
			return false;

	return true;
}

bool SshExchange::IsValid() const
{
	if( !IsIdentificationValid(_clientIdent, _clientIdentLength) ||
		!IsIdentificationValid(_serverIdent, _serverIdentLength) )
	{
		return false;
	}

	if( _clientKex == NULL || _serverKex == NULL ||
		_clientKexLength < 62 || _serverKexLength < 62 ||
		_clientKexLength > SSHPKT_MAX_PACKET || _serverKexLength > SSHPKT_MAX_PACKET ||
		_clientKex[0] != 20 || _serverKex[0] != 20 )
	{
		return false;
	}

	if( _hostKey == NULL || _hostKeyLength == 0 || _hostKeyLength > SSHPKT_MAX_PACKET ||
		_clientPublic == NULL || _serverPublic == NULL || _sharedSecret == NULL )
	{
		return false;
	}

	/* RFC 7748: do not accept an all-zero X25519 shared secret. */
	unsigned char nonzero = 0;
	for( int i = 0; i < 32; i++ )
		nonzero |= _sharedSecret[i];

	return nonzero != 0;
}

/* RFC 4253/8731: hash the SSH transcript and the big-endian X25519 mpint.
 * Encoding an mpint is shared with the rekey key-derivation path. */
static size_t SshPktMpint(const unsigned char shared[32], unsigned char out[37]);

bool SshExchange::Hash(unsigned char digest[32]) const
{
	if( digest == NULL || !IsValid() )
		return false;

	unsigned char mpint[37];
	int mpint_size = SshPktMpint(_sharedSecret, mpint);

	Sha256State state;
	state.Init();

	SshPktHashString(state, _clientIdent, _clientIdentLength);
	SshPktHashString(state, _serverIdent, _serverIdentLength);
	SshPktHashString(state, _clientKex, _clientKexLength);
	SshPktHashString(state, _serverKex, _serverKexLength);
	SshPktHashString(state, _hostKey, _hostKeyLength);
	SshPktHashString(state, _clientPublic, 32);
	SshPktHashString(state, _serverPublic, 32);
	state.Bytes(mpint, mpint_size);
	state.Final(digest);

	SshCrypt::Zero(mpint, sizeof(mpint));
	return true;
}

/* RFC4253 key expansion SHA256(mpint(K) || H || letter || session_id).
 * The original session identifier MUST be reused for all later exchanges. */
static size_t SshPktMpint(const unsigned char shared[32], unsigned char out[37])
{
	unsigned char nonzero = 0;
	for( int i = 0; i < 32; i++ )
		nonzero |= shared[i];

	if( !nonzero )
		return 0;

	int first = 0;
	while( first < 32 && shared[first] == 0 )
		first++;
	int n = 32 - first;
	if( shared[first] & 0x80 )
	{
		SshPktPut32(out, n + 1);
		out[4] = 0;
		memcpy(out + 5, shared + first, n);
		return n + 5;
	}
	SshPktPut32(out, n);
	memcpy(out + 4, shared + first, n);
	return n + 4;
}

bool SshPktDeriveRekey(const unsigned char shared[32], const unsigned char H[32],
	const unsigned char sessionId[32], SSHPKT_Keys &keys)
{
	if( shared == NULL || H == NULL || sessionId == NULL )
		return false;

	memset(&keys, 0, sizeof(keys));
	unsigned char mpint[37];
	int ksize = SshPktMpint(shared, mpint);
	if( !ksize )
		return false;

	unsigned char *targets[6];
	const int lengths[6] = {16, 16, 16, 16, 32, 32};
	targets[0] = keys.clientIV;
	targets[1] = keys.serverIV;
	targets[2] = keys.clientKey;
	targets[3] = keys.serverKey;
	targets[4] = keys.clientMac;
	targets[5] = keys.serverMac;
	unsigned char digest[32];

	Sha256State hash;
	for( int i = 0; i < 6; i++ )
	{
		unsigned char letter = (unsigned char)('A' + i);
		hash.Init();
		hash.Bytes(mpint, ksize);
		hash.Bytes(H, 32);
		hash.Bytes(&letter, 1);
		hash.Bytes(sessionId, 32);
		hash.Final(digest);
		memcpy(targets[i], digest, lengths[i]);
	}
	SshCrypt::Zero(mpint, sizeof(mpint));
	SshCrypt::Zero(digest, sizeof(digest));
	return true;
}

bool SshPktDeriveKeys(const unsigned char shared[32], const unsigned char H[32], SSHPKT_Keys &keys)
{
	return SshPktDeriveRekey(shared, H, H, keys);
}

void SshMac::Init(const unsigned char key[32])
{
	unsigned char pad[64];

	for( size_t i = 0; i < sizeof(pad); i++ )
		pad[i] = (i < 32 ? key[i] : 0) ^ 0x36;
	_inner.Init();
	_inner.Bytes(pad, sizeof(pad));

	for( size_t i = 0; i < sizeof(pad); i++ )
		pad[i] = (i < 32 ? key[i] : 0) ^ 0x5C;
	_outer.Init();
	_outer.Bytes(pad, sizeof(pad));

	SshCrypt::Zero(pad, sizeof(pad));
}

/* Preserve the seeded SHA state across packets: only small state copies.
 * Each invocation hashes seq || plaintext packet, then the inner digest. */
void SshMac::Calculate(unsigned long sequence, const unsigned char *packet, size_t packetSize, unsigned char digest[32]) const
{
	unsigned char seq[4];
	unsigned char inner[32];
	Sha256State state = _inner;

	SshPktPut32(seq, sequence);
	state.Bytes(seq, sizeof(seq));
	state.Bytes(packet, packetSize);
	state.Final(inner);

	state = _outer;
	state.Bytes(inner, sizeof(inner));
	state.Final(digest);
	SshCrypt::Zero(inner, sizeof(inner));
}

void SshPktCipherInit(SSHPKT_Cipher &cipher, const unsigned char key[16], const unsigned char iv[16], const unsigned char macKey[32])
{
	cipher.aes.Init(key, iv);
	cipher.mac.Init(macKey);
}

bool SshPktWriteSecure(SSHPKT_Cipher &cipher, SSHCRYPT_RNG &rng, unsigned char *frame,
	size_t capacity, const unsigned char *payload, size_t length, unsigned long deadline, unsigned long &sequence)
{
	if( frame == NULL || payload == NULL || !length || deadline == 0 || deadline >= 0x80000000ul )
		return false;

	int pad = (int)(16ul - (((unsigned long)length + 5ul) % 16ul));
	if( pad < 4 )
		pad += 16;
	unsigned long packet_len = (unsigned long)length + 1ul + pad;
	if( packet_len > SSHPKT_MAX_PACKET || packet_len + 4ul + 32ul > capacity )
		return false;

	size_t total = (size_t)(packet_len + 4ul);
	SshPktPut32(frame, packet_len);
	frame[4] = (unsigned char)pad;
	memcpy(frame + 5, payload, length);
	rng.GeneratePadding(frame + 5 + length, pad);

	cipher.mac.Calculate(sequence, frame, total, frame + total);
	cipher.aes.Xor(frame, total);
	if( !DosSshWriteAll(frame, total + 32u, deadline) )
		return false;

	sequence = (sequence + 1ul) & 0xFFFFFFFFul;
	return true;
}

const unsigned char *SshPktReadSecure(SSHPKT_Cipher &cipher, unsigned char *frame, size_t capacity,
	size_t &length, unsigned long deadline, unsigned long &sequence)
{
	if( frame == NULL || capacity < 16 || deadline == 0 || deadline >= 0x80000000ul )
		return NULL;

	unsigned long started = g_transport.Ticks();
	if( !SshPktReadBefore(frame, 16, started, deadline) )
		return NULL;

	cipher.aes.Xor(frame, 16);
	unsigned long packet_len = SshPktGet32(frame);
	if( packet_len < 12 || packet_len > SSHPKT_MAX_PACKET || ((packet_len + 4ul) & 15ul) != 0 || packet_len + 4ul > capacity )
	{
		Log('E', "SSH invalid encrypted len=%lu seq=%lu", packet_len, sequence);
		return NULL;
	}

	size_t total = (size_t)(packet_len + 4ul);
	if( !SshPktReadBefore(frame + 16, total - 16, started, deadline) )
		return NULL;

	cipher.aes.Xor(frame + 16, total - 16);
	unsigned char incoming[32];
	if( !SshPktReadBefore(incoming, 32, started, deadline) )
		return NULL;

	unsigned char expected[32];
	cipher.mac.Calculate(sequence, frame, total, expected);
	if( !SshCrypt::Equal(expected, incoming, 32) )
	{
		Log('E', "SSH HMAC mismatch seq=%lu", sequence);
		SshCrypt::Zero(expected, sizeof(expected));
		return NULL;
	}

	SshCrypt::Zero(expected, sizeof(expected));
	if( frame[4] < 4 || (unsigned long)frame[4] + 1ul >= packet_len )
		return NULL;

	length = (size_t)(packet_len - 1ul - frame[4]);
	sequence = (sequence + 1ul) & 0xFFFFFFFFul;
	return frame + 5;
}

SshPacketReader::SshPacketReader()
{
	Reset();
}

void SshPacketReader::Reset()
{
	_used = 0;
	_target = 16;
	_stage = 0;
}

/* The cipher advances only for bytes that belong to this packet. The MAC
 * is verified before the payload is exposed to the SSH session. */
int SshPacketReader::Poll(SSHPKT_Cipher &cipher,
	unsigned char *frame, size_t capacity, const unsigned char **payload, size_t &length, unsigned long &sequence)
{
	if( frame == NULL || capacity < 16 )
		return -1;

	for( ;; )
	{
		size_t remaining = _target - _used;
		if( remaining )
		{
			int count = remaining > 2048u ? 2048u : remaining;
			unsigned char *destination = _stage == 2 ? _mac : frame;
			int received = g_transport.ReadSome( destination + _used, count);
			if( received < 0 || received > count )
				return -1;
			if( received == 0 )
				return 0;

			_used += (size_t)received;
			if( _used < _target )
				continue;
		}

		if( _stage == 0 )
		{
			cipher.aes.Xor(frame, 16);
			unsigned long packet_length = SshPktGet32(frame);
			if( packet_length < 12 || packet_length > SSHPKT_MAX_PACKET ||
				((packet_length + 4ul) & 15ul) != 0 || packet_length + 4ul > capacity )
			{
				Log('E', "SSH invalid len=%lu seq=%lu", packet_length, sequence);
				return -1;
			}

			_stage = 1;
			_target = (size_t)(packet_length + 4ul);
			_used = 16;
		}
		else if( _stage == 1 )
		{
			cipher.aes.Xor(frame + 16, _target - 16);
			_stage = 2;
			_target = 32;
			_used = 0;
		}
		else
		{
			unsigned long packet_length = SshPktGet32(frame);
			unsigned char expected[32];
			cipher.mac.Calculate(sequence, frame, (size_t)(packet_length + 4ul), expected);
			bool authenticated = SshCrypt::Equal(expected, _mac, sizeof(_mac));
			SshCrypt::Zero(expected, sizeof(expected));
			if( !authenticated || frame[4] < 4 || (unsigned long)frame[4] + 1ul >= packet_length )
			{
				Log('E', "SSH MAC/padding failed seq=%lu", sequence);
				return -1;
			}

			*payload = frame + 5;
			length = (size_t)(packet_length - 1ul - frame[4]);
			sequence = (sequence + 1ul) & 0xFFFFFFFFul;
			Reset();
			return 1;
		}
	}
}

bool DosSshReadExact(unsigned char *buf, size_t length, unsigned long timeout)
{
	if( (length && buf == NULL) || timeout >= 0x80000000ul )
		return false;

	size_t done = 0;
	unsigned long start = g_transport.Ticks();
	while( done < length )
	{
		/* mTCP uses a signed 16-bit return count. Never pass a full
		 * 34K SSH frame to a single read operation. */
		size_t chunk = length - done;
		if( chunk > 16384u )
			chunk = 16384u;
		int received = g_transport.ReadSome( buf + done, chunk);
		if( received < 0 || (size_t)received > chunk )
		{
			Log('E', "SSH read rc=%d got=%lu", received, (unsigned long)done);
			return false;
		}
		done += (size_t)received;
		if( done == length )
			return true;
		if( (unsigned long)(g_transport.Ticks() - start) >= timeout )
		{
			Log('E', "SSH read timeout got=%lu need=%lu ticks=%lu",
				(unsigned long)done, (unsigned long)length, (unsigned long)(g_transport.Ticks() - start));
			return false;
		}
		g_transport.Pump();
	}
	return true;
}

bool DosSshWriteAll(const unsigned char *buf, size_t length, unsigned long timeout)
{
	if( (length && buf == NULL) || timeout >= 0x80000000ul )
		return false;

	size_t done = 0;
	unsigned long start = g_transport.Ticks();
	while( done < length )
	{
		size_t chunk = length - done;
		if( chunk > 16384u )
			chunk = 16384u;
		int sent = g_transport.WriteSome( buf + done, chunk);
		if( sent < 0 || (size_t)sent > chunk )
		{
			Log('E', "SSH write rc=%d sent=%lu", sent, (unsigned long)done);
			return false;
		}
		done += (size_t)sent;
		if( done == length )
			return true;

		if( (unsigned long)(g_transport.Ticks() - start) >= timeout )
		{
			Log('E', "SSH write timeout sent=%lu need=%lu ticks=%lu",
				(unsigned long)done, (unsigned long)length, (unsigned long)(g_transport.Ticks() - start));
			return false;
		}
		g_transport.Pump();
	}
	return true;
}

/* A name-list owns its syntax rules. The byte span belongs to the input
 * packet and is only accessed after the outer KEXINIT was length-checked. */
class SshNameList
{
public:
	bool Set(const unsigned char *data, size_t length)
	{
		_data = data;
		_length = length;
		return IsValid();
	}

	bool IsValid() const
	{
		if( _data == NULL )
			return false;

		if( _length && (_data[0] == ',' || _data[_length - 1] == ',') )
			return false;

		for( size_t i = 0; i < _length; i++ )
		{
			if( _data[i] < 33 || _data[i] > 126 )
				return false;

			if( i && _data[i] == ',' && _data[i - 1] == ',' )
				return false;
		}

		return true;
	}

	bool Contains(const char *name) const
	{
		size_t begin = 0;
		size_t wanted = strlen(name);

		for( size_t i = 0; i <= _length; i++ )
		{
			if( i == _length || _data[i] == ',' )
			{
				if( i > begin && i - begin == wanted && memcmp(_data + begin, name, wanted) == 0 )
					return true;

				begin = i + 1;
			}
		}

		return false;
	}

	bool FirstIs(const char *name) const
	{
		size_t i = 0;
		while( i < _length && _data[i] != ',' )
			i++;

		size_t wanted = strlen(name);
		return i == wanted && memcmp(_data, name, wanted) == 0;
	}

private:
	const unsigned char *_data;
	size_t _length;
};

/* RFC 4253 KEXINIT is a coherent message, not ten unrelated arrays.
 * Once IsValid() succeeds, negotiation does not recheck individual fields. */
class SshKexinit
{
public:
	SshKexinit(const unsigned char *packet, size_t size)
	{
		_valid = Parse(packet, size);
	}

	bool IsValid() const { return _valid; }

	int Negotiate() const
	{
		static const char *required[8] = {
			"curve25519-sha256", "ssh-ed25519", "aes128-ctr", "aes128-ctr",
			"hmac-sha2-256", "hmac-sha2-256", "none", "none"
		};
		static const char *missing[8] = {
			"No curve25519-sha256 offer", "No ssh-ed25519 host-key offer",
			"No aes128-ctr C->S offer", "No aes128-ctr S->C offer",
			"No hmac-sha2-256 C->S offer", "No hmac-sha2-256 S->C offer",
			"No compression=none C->S offer", "No compression=none S->C offer"
		};

		g_sshReason = "Malformed SSH_MSG_KEXINIT";
		if( !IsValid() )
			return -1;

		for( int i = 0; i < 8; i++ )
		{
			if( !_lists[i].Contains(required[i]) )
			{
				g_sshReason = missing[i];
				return -1;
			}
		}

		g_sshReason = "Compatible offers (exchange NOT complete)";
		return _firstKexPacketFollows && (!_lists[0].FirstIs(required[0]) || !_lists[1].FirstIs(required[1])) ? 1 : 0;
	}

private:
	SshNameList _lists[10];
	bool _valid;
	bool _firstKexPacketFollows;

	bool Parse(const unsigned char *packet, size_t size)
	{
		if( packet == NULL || size < 62 || size > 8192 || packet[0] != 20 )
			return false;

		size_t offset = 17;
		for( int i = 0; i < 10; i++ )
		{
			if( size - offset < 4 )
				return false;

			unsigned long length = SshPktGet32(packet + offset);
			offset += 4;
			if( length > (unsigned long)(size - offset) )
				return false;

			if( !_lists[i].Set(packet + offset, (size_t)length) )
				return false;

			offset += (size_t)length;
		}

		if( size - offset != 5 || packet[offset] > 1 || SshPktGet32(packet + offset + 1) != 0 )
			return false;

		_firstKexPacketFollows = packet[offset] != 0;
		return true;
	}
};

int DosSshNegotiateKexinit(const unsigned char *packet, size_t packetSize)
{
	SshKexinit kexinit(packet, packetSize);
	return kexinit.Negotiate();
}
