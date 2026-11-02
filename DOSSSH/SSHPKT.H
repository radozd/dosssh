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

#ifndef DOSSSH_SSHPKT_H
#define DOSSSH_SSHPKT_H

#include <stddef.h>
#include "SSHNET.H"
#include "SSHCRYPT.H"
#include "SSHSHA.H"

#define SSHPKT_MAX_PACKET 34816u
#define SSHPKT_MAX_FRAME (SSHPKT_MAX_PACKET + 4u)
#define SSHPKT_MAC_SIZE 32u
#define SSHPKT_MAX_WIRE (SSHPKT_MAX_FRAME + SSHPKT_MAC_SIZE)

/* Bounded nonblocking read/write with timeouts, using the concrete transport. */
bool DosSshReadExact(unsigned char *buffer, size_t size, unsigned long timeoutTicks);
bool DosSshWriteAll(const unsigned char *buffer, size_t size, unsigned long timeoutTicks);

/* A packet can contain a 32K payload; plain packets are 8-byte aligned. */
/* Padding is 4..11 bytes; zero means an invalid payload length. */
size_t SshPktPaddingSize(size_t payloadLength);
/* Return the written frame length, or zero if the frame cannot be encoded. */
size_t SshPktEncodePlain(const unsigned char *payload, size_t payloadLength,
	const unsigned char *randomPad, size_t padLength, unsigned char *frame, size_t frameCapacity);
/* The returned pointer borrows frame storage; NULL means malformed frame. */
const unsigned char *SshPktDecodePlain(const unsigned char *frame, size_t frameLength, size_t &payloadLength);
const unsigned char *SshPktReadPlain(unsigned char *frame, size_t capacity,
	size_t &payloadLength, unsigned long timeoutTicks, unsigned long *sequence);
bool SshPktWritePlain(const unsigned char *frame, size_t frameLength,
	unsigned long timeoutTicks, unsigned long *sequence);

/* -1 = incompatible, 0 = compatible, 1 = discard server's guessed packet. */
int DosSshNegotiateKexinit(const unsigned char *payload, size_t payloadLength, const char **reason);
/* Encoded payload sizes are nonzero; zero indicates insufficient space. */
size_t SshPktMakeKexinit(const unsigned char cookie[16], unsigned char *payload, size_t capacity);

/* ECDH_REPLY is parsed once. All returned pointers borrow packet storage. */
class SshEcdhReply
{
public:
	SshEcdhReply();
	bool Parse(const unsigned char *packet, size_t packetSize);
	bool IsValid() const { return _valid; }

	const unsigned char *HostKey() const { return _hostKey; }
	size_t HostKeyLength() const { return _hostKeyLength; }
	const unsigned char *HostPublic() const { return _hostPublic; }
	const unsigned char *ServerPublic() const { return _serverPublic; }
	const unsigned char *Signature() const { return _signature; }

private:
	const unsigned char *_hostKey;
	size_t _hostKeyLength;
	const unsigned char *_hostPublic;
	const unsigned char *_serverPublic;
	const unsigned char *_signature;
	bool _valid;
};

size_t SshPktMakeEcdhInit(const unsigned char clientPublic[32], unsigned char *payload,
						size_t capacity);

/* Owns the authenticated key-exchange transcript. Input blobs are borrowed,
 * never copied: they must remain alive until Hash() returns. */
class SshExchange
{
public:
	SshExchange();

	void SetIdentifiers(const unsigned char *clientIdent, size_t clientLength, const unsigned char *serverIdent, size_t serverLength);
	void SetKexinit(const unsigned char *clientKex, size_t clientLength, const unsigned char *serverKex, size_t serverLength);
	void SetEcdh(const SshEcdhReply &reply, const unsigned char clientPublic[32], const unsigned char sharedSecret[32]);

	bool IsValid() const;
	bool Hash(unsigned char digest[32]) const;

private:
	static bool IsIdentificationValid(const unsigned char *ident, size_t length);

	const unsigned char *_clientIdent;
	size_t _clientIdentLength;
	const unsigned char *_serverIdent;
	size_t _serverIdentLength;
	const unsigned char *_clientKex;
	size_t _clientKexLength;
	const unsigned char *_serverKex;
	size_t _serverKexLength;
	const unsigned char *_hostKey;
	size_t _hostKeyLength;
	const unsigned char *_clientPublic;
	const unsigned char *_serverPublic;
	const unsigned char *_sharedSecret;
};

struct SSHPKT_Keys
{
	unsigned char clientIV[16];
	unsigned char serverIV[16];
	unsigned char clientKey[16];
	unsigned char serverKey[16];
	unsigned char clientMac[32];
	unsigned char serverMac[32];
};

/* SHA-256 ipad and opad states are prepared once per transport key. */
class SshMac
{
public:
	void Init(const unsigned char key[32]);
	void Calculate(unsigned long sequence, const unsigned char *packet, size_t packetSize, unsigned char digest[32]) const;

private:
	Sha256State _inner;
	Sha256State _outer;
};

struct SSHPKT_Cipher
{
	SSHCRYPT_AES aes;
	SshMac mac;
};

bool SshPktDeriveKeys(const unsigned char shared[32], const unsigned char H[32], SSHPKT_Keys &keys);
bool SshPktDeriveRekey(const unsigned char shared[32], const unsigned char exchangeHash[32],
	const unsigned char sessionId[32], SSHPKT_Keys &keys);
void SshPktCipherInit(SSHPKT_Cipher &cipher, const unsigned char aesKey[16],
	const unsigned char iv[16], const unsigned char macKey[32]);

/* Owns partial packet state and prevents a caller from disturbing the AES
 * stream while an authenticated frame is still arriving. */
class SshPacketReader
{
public:
	SshPacketReader();

	bool IsIdle() const { return _stage == 0 && _used == 0; }

	/* -1 = invalid packet or I/O error, 0 = incomplete, 1 = verified frame. */
	int Poll(SSHPKT_Cipher &cipher, unsigned char *frame,
		size_t capacity, const unsigned char **payload, size_t &length, unsigned long &sequence);

	/* Start a new stream. Never continue with the same cipher after a MAC error. */
	void Reset();

private:
	size_t _used;
	size_t _target;
	unsigned char _stage;
	unsigned char _mac[32];
};

bool SshPktWriteSecure(SSHPKT_Cipher &cipher, SSHCRYPT_RNG &rng,
	unsigned char *frame, size_t capacity, const unsigned char *payload,
	size_t length, unsigned long deadline, unsigned long &sequence);
/* Return the authenticated payload within frame, or NULL on error. */
const unsigned char *SshPktReadSecure(SSHPKT_Cipher &cipher, unsigned char *frame,
	size_t capacity, size_t &length, unsigned long deadline, unsigned long &sequence);

#endif
