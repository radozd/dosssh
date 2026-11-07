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

#include "SSHSHA.H"

const unsigned long SHA_WORD32 = 0xFFFFFFFFul;

static unsigned long Sha32(unsigned long n)
{
	return n & SHA_WORD32;
}

unsigned long ShaRor32(unsigned long value, int bits);
#pragma aux ShaRor32 = \
    ".386"               \
    "shl edx, 16"        \
    "mov dx, ax"         \
    "ror edx, cl"        \
    "mov eax, edx"       \
    "shr edx, 16"        \
    parm [ax dx] [cx] nomemory \
    value [ax dx]        \
    modify exact [ax dx] nomemory;

unsigned __int64 ShaRor64(unsigned __int64 value, int bits);
#pragma aux ShaRor64 = \
    ".386"               \
    "shl eax, 16"        \
    "mov ax, bx"         \
    "shl ecx, 16"        \
    "mov cx, dx"         \
    "mov edx, eax"       \
    "mov eax, ecx"       \
    "mov cx, si"         \
    "test si, 32"        \
    "jz short ror_small"  \
    "xchg eax, edx"      \
    "ror_small: mov ebx, eax" \
    "shrd eax, edx, cl"  \
    "shrd edx, ebx, cl"  \
    "mov ecx, eax"       \
    "shr ecx, 16"        \
    "mov bx, dx"         \
    "shr edx, 16"        \
    "xchg ax, dx"        \
    parm [ax bx cx dx] [si] nomemory \
    value [ax bx cx dx]   \
    modify exact [ax bx cx dx] nomemory;

unsigned __int64 ShaShr64(unsigned __int64 value, int bits);
#pragma aux ShaShr64 = \
    ".386"               \
    "shl eax, 16"        \
    "mov ax, bx"         \
    "shl ecx, 16"        \
    "mov cx, dx"         \
    "mov edx, ecx"       \
    "mov cx, si"         \
    "shrd edx, eax, cl"  \
    "shr eax, cl"        \
    "mov bx, ax"         \
    "shr eax, 16"        \
    "mov ecx, edx"       \
    "mov dx, cx"         \
    "shr ecx, 16"        \
    parm [ax bx cx dx] [si] nomemory \
    value [ax bx cx dx]   \
    modify exact [ax bx cx dx] nomemory;

static void ShaStore32(unsigned char *p, unsigned long value)
{
	p[0] = (unsigned char)(value >> 24);
	p[1] = (unsigned char)(value >> 16);
	p[2] = (unsigned char)(value >> 8);
	p[3] = (unsigned char)value;
}

static unsigned long ShaLoad32(const unsigned char *p)
{
	return ((unsigned long)p[0] << 24) | ((unsigned long)p[1] << 16) | ((unsigned long)p[2] << 8) | (unsigned long)p[3];
}

static void ShaStore64(unsigned char *p, unsigned __int64 value)
{
	ShaStore32(p, (unsigned long)(value >> 32));
	ShaStore32(p + 4, (unsigned long)value);
}

static unsigned __int64 ShaLoad64(const unsigned char *p)
{
	return ((unsigned __int64)ShaLoad32(p) << 32) | ShaLoad32(p + 4);
}

static void ShaWipe(void *data, size_t length)
{
	volatile unsigned char *p = (volatile unsigned char *)data;
	while( length-- )
		*p++ = 0;
}

static void ShaCount(unsigned long &low, unsigned long &high, size_t bytes)
{
	unsigned long old = low;
	low = Sha32(old + (unsigned long)bytes);
	if( low < old )
		high = Sha32(high + 1ul);
}

void Sha256State::Block(const unsigned char *block)
{
	static const unsigned long k[64] = {
		0x428A2F98ul, 0x71374491ul, 0xB5C0FBCFul, 0xE9B5DBA5ul, 0x3956C25Bul, 0x59F111F1ul, 0x923F82A4ul,
		0xAB1C5ED5ul, 0xD807AA98ul, 0x12835B01ul, 0x243185BEul, 0x550C7DC3ul, 0x72BE5D74ul, 0x80DEB1FEul,
		0x9BDC06A7ul, 0xC19BF174ul, 0xE49B69C1ul, 0xEFBE4786ul, 0x0FC19DC6ul, 0x240CA1CCul, 0x2DE92C6Ful,
		0x4A7484AAul, 0x5CB0A9DCul, 0x76F988DAul, 0x983E5152ul, 0xA831C66Dul, 0xB00327C8ul, 0xBF597FC7ul,
		0xC6E00BF3ul, 0xD5A79147ul, 0x06CA6351ul, 0x14292967ul, 0x27B70A85ul, 0x2E1B2138ul, 0x4D2C6DFCul,
		0x53380D13ul, 0x650A7354ul, 0x766A0ABBul, 0x81C2C92Eul, 0x92722C85ul, 0xA2BFE8A1ul, 0xA81A664Bul,
		0xC24B8B70ul, 0xC76C51A3ul, 0xD192E819ul, 0xD6990624ul, 0xF40E3585ul, 0x106AA070ul, 0x19A4C116ul,
		0x1E376C08ul, 0x2748774Cul, 0x34B0BCB5ul, 0x391C0CB3ul, 0x4ED8AA4Aul, 0x5B9CCA4Ful, 0x682E6FF3ul,
		0x748F82EEul, 0x78A5636Ful, 0x84C87814ul, 0x8CC70208ul, 0x90BEFFFAul, 0xA4506CEBul, 0xBEF9A3F7ul,
		0xC67178F2ul};

	unsigned long w[64];
	for( int i = 0; i < 16; i++ )
		w[i] = ShaLoad32(block + 4*i);

	for( int i = 16; i < 64; i++ )
	{
		unsigned long u = w[i - 15];
		unsigned long v = w[i - 2];
		unsigned long s0 = ShaRor32(u, 7) ^ ShaRor32(u, 18) ^ (u >> 3);
		unsigned long s1 = ShaRor32(v, 17) ^ ShaRor32(v, 19) ^ (v >> 10);
		w[i] = Sha32(w[i - 16] + s0 + w[i - 7] + s1);
	}

	unsigned long a = this->h[0];
	unsigned long b = this->h[1];
	unsigned long c = this->h[2];
	unsigned long d = this->h[3];
	unsigned long e = this->h[4];
	unsigned long f = this->h[5];
	unsigned long g = this->h[6];
	unsigned long h = this->h[7];
	for( int i = 0; i < 64; i++ )
	{
		unsigned long big1 = ShaRor32(e, 6) ^ ShaRor32(e, 11) ^ ShaRor32(e, 25);
		unsigned long big0 = ShaRor32(a, 2) ^ ShaRor32(a, 13) ^ ShaRor32(a, 22);
		unsigned long t1 = Sha32(h + big1 + ((e & f) ^ (~e & g)) + k[i] + w[i]);
		unsigned long t2 = Sha32(big0 + ((a & b) ^ (a & c) ^ (b & c)));
		h = g;
		g = f;
		f = e;
		e = Sha32(d + t1);
		d = c;
		c = b;
		b = a;
		a = Sha32(t1 + t2);
	}

	this->h[0] = Sha32(this->h[0] + a);
	this->h[1] = Sha32(this->h[1] + b);
	this->h[2] = Sha32(this->h[2] + c);
	this->h[3] = Sha32(this->h[3] + d);
	this->h[4] = Sha32(this->h[4] + e);
	this->h[5] = Sha32(this->h[5] + f);
	this->h[6] = Sha32(this->h[6] + g);
	this->h[7] = Sha32(this->h[7] + h);
	ShaWipe(w, sizeof(w));
}

void Sha256State::Init()
{
	static const unsigned long iv[8] = {0x6A09E667ul, 0xBB67AE85ul, 0x3C6EF372ul, 0xA54FF53Aul,
										0x510E527Ful, 0x9B05688Cul, 0x1F83D9ABul, 0x5BE0CD19ul};
	memcpy(h, iv, sizeof(iv));
	used = 0;
	bytesLo = 0;
	bytesHi = 0;
}

void Sha256State::Bytes(const unsigned char *p, size_t bytes)
{
	ShaCount(bytesLo, bytesHi, bytes);
	while( bytes )
	{
		size_t take = 64 - used;
		if( take > bytes )
			take = bytes;
		memcpy(block + used, p, take);
		used += take;
		p += take;
		bytes -= take;
		if( used == 64 )
		{
			Block(block);
			used = 0;
		}
	}
}

void Sha256State::Final(unsigned char digest[32])
{
	unsigned long hi = Sha32((bytesHi << 3) | (bytesLo >> 29));
	unsigned long lo = Sha32(bytesLo << 3);
	block[used++] = 0x80;
	if( used > 56 )
	{
		memset(block + used, 0, 64 - used);
		Block(block);
		used = 0;
	}
	memset(block + used, 0, 56 - used);
	ShaStore32(block + 56, hi);
	ShaStore32(block + 60, lo);
	Block(block);
	for( int i = 0; i < 8; i++ )
		ShaStore32(digest + 4*i, h[i]);
	ShaWipe(this, sizeof(*this));
}

void Sha256State::Simple(const unsigned char *p, size_t bytes, unsigned char digest[32])
{
	Sha256State s;
	s.Init();
	s.Bytes(p, bytes);
	s.Final(digest);
}

void Sha512State::Block(const unsigned char *block)
{
	/* Each K pair is the high and low 32 bits of a SHA-512 round constant. */
	static const unsigned long k[80][2] = {
		{0x428A2F98ul, 0xD728AE22ul}, {0x71374491ul, 0x23EF65CDul}, {0xB5C0FBCFul, 0xEC4D3B2Ful},
		{0xE9B5DBA5ul, 0x8189DBBCul}, {0x3956C25Bul, 0xF348B538ul}, {0x59F111F1ul, 0xB605D019ul},
		{0x923F82A4ul, 0xAF194F9Bul}, {0xAB1C5ED5ul, 0xDA6D8118ul}, {0xD807AA98ul, 0xA3030242ul},
		{0x12835B01ul, 0x45706FBEul}, {0x243185BEul, 0x4EE4B28Cul}, {0x550C7DC3ul, 0xD5FFB4E2ul},
		{0x72BE5D74ul, 0xF27B896Ful}, {0x80DEB1FEul, 0x3B1696B1ul}, {0x9BDC06A7ul, 0x25C71235ul},
		{0xC19BF174ul, 0xCF692694ul}, {0xE49B69C1ul, 0x9EF14AD2ul}, {0xEFBE4786ul, 0x384F25E3ul},
		{0x0FC19DC6ul, 0x8B8CD5B5ul}, {0x240CA1CCul, 0x77AC9C65ul}, {0x2DE92C6Ful, 0x592B0275ul},
		{0x4A7484AAul, 0x6EA6E483ul}, {0x5CB0A9DCul, 0xBD41FBD4ul}, {0x76F988DAul, 0x831153B5ul},
		{0x983E5152ul, 0xEE66DFABul}, {0xA831C66Dul, 0x2DB43210ul}, {0xB00327C8ul, 0x98FB213Ful},
		{0xBF597FC7ul, 0xBEEF0EE4ul}, {0xC6E00BF3ul, 0x3DA88FC2ul}, {0xD5A79147ul, 0x930AA725ul},
		{0x06CA6351ul, 0xE003826Ful}, {0x14292967ul, 0x0A0E6E70ul}, {0x27B70A85ul, 0x46D22FFCul},
		{0x2E1B2138ul, 0x5C26C926ul}, {0x4D2C6DFCul, 0x5AC42AEDul}, {0x53380D13ul, 0x9D95B3DFul},
		{0x650A7354ul, 0x8BAF63DEul}, {0x766A0ABBul, 0x3C77B2A8ul}, {0x81C2C92Eul, 0x47EDAEE6ul},
		{0x92722C85ul, 0x1482353Bul}, {0xA2BFE8A1ul, 0x4CF10364ul}, {0xA81A664Bul, 0xBC423001ul},
		{0xC24B8B70ul, 0xD0F89791ul}, {0xC76C51A3ul, 0x0654BE30ul}, {0xD192E819ul, 0xD6EF5218ul},
		{0xD6990624ul, 0x5565A910ul}, {0xF40E3585ul, 0x5771202Aul}, {0x106AA070ul, 0x32BBD1B8ul},
		{0x19A4C116ul, 0xB8D2D0C8ul}, {0x1E376C08ul, 0x5141AB53ul}, {0x2748774Cul, 0xDF8EEB99ul},
		{0x34B0BCB5ul, 0xE19B48A8ul}, {0x391C0CB3ul, 0xC5C95A63ul}, {0x4ED8AA4Aul, 0xE3418ACBul},
		{0x5B9CCA4Ful, 0x7763E373ul}, {0x682E6FF3ul, 0xD6B2B8A3ul}, {0x748F82EEul, 0x5DEFB2FCul},
		{0x78A5636Ful, 0x43172F60ul}, {0x84C87814ul, 0xA1F0AB72ul}, {0x8CC70208ul, 0x1A6439ECul},
		{0x90BEFFFAul, 0x23631E28ul}, {0xA4506CEBul, 0xDE82BDE9ul}, {0xBEF9A3F7ul, 0xB2C67915ul},
		{0xC67178F2ul, 0xE372532Bul}, {0xCA273ECEul, 0xEA26619Cul}, {0xD186B8C7ul, 0x21C0C207ul},
		{0xEADA7DD6ul, 0xCDE0EB1Eul}, {0xF57D4F7Ful, 0xEE6ED178ul}, {0x06F067AAul, 0x72176FBAul},
		{0x0A637DC5ul, 0xA2C898A6ul}, {0x113F9804ul, 0xBEF90DAEul}, {0x1B710B35ul, 0x131C471Bul},
		{0x28DB77F5ul, 0x23047D84ul}, {0x32CAAB7Bul, 0x40C72493ul}, {0x3C9EBE0Aul, 0x15C9BEBCul},
		{0x431D67C4ul, 0x9C100D4Cul}, {0x4CC5D4BEul, 0xCB3E42B6ul}, {0x597F299Cul, 0xFC657E2Aul},
		{0x5FCB6FABul, 0x3AD6FAECul}, {0x6C44198Cul, 0x4A475817ul}};

	unsigned __int64 w[80];
	for( int i = 0; i < 16; i++ )
		w[i] = ShaLoad64(block + 8*i);

	for( int i = 16; i < 80; i++ )
	{
		unsigned __int64 x = w[i - 15], y = w[i - 2];
		unsigned __int64 s0 = ShaRor64(x, 1) ^ ShaRor64(x, 8) ^ ShaShr64(x, 7);
		unsigned __int64 s1 = ShaRor64(y, 19) ^ ShaRor64(y, 61) ^ ShaShr64(y, 6);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	unsigned __int64 a = this->h[0];
	unsigned __int64 b = this->h[1];
	unsigned __int64 c = this->h[2];
	unsigned __int64 d = this->h[3];
	unsigned __int64 e = this->h[4];
	unsigned __int64 f = this->h[5];
	unsigned __int64 g = this->h[6];
	unsigned __int64 h = this->h[7];

	for( int i = 0; i < 80; i++ )
	{
		unsigned __int64 big1 = ShaRor64(e, 14) ^ ShaRor64(e, 18) ^ ShaRor64(e, 41);
		unsigned __int64 big0 = ShaRor64(a, 28) ^ ShaRor64(a, 34) ^ ShaRor64(a, 39);
		unsigned __int64 t1 = h + big1 + ((e & f) ^ (~e & g)) + (((unsigned __int64)k[i][0] << 32) | (unsigned __int64)k[i][1]) + w[i];
		unsigned __int64 t2 = big0 + ((a & b) ^ (a & c) ^ (b & c));
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}
	this->h[0] += a;
	this->h[1] += b;
	this->h[2] += c;
	this->h[3] += d;
	this->h[4] += e;
	this->h[5] += f;
	this->h[6] += g;
	this->h[7] += h;
	ShaWipe(w, sizeof(w));
}

void Sha512State::Init()
{
	static const unsigned long iv[8][2] = {
		{0x6A09E667ul, 0xF3BCC908ul}, {0xBB67AE85ul, 0x84CAA73Bul},
		{0x3C6EF372ul, 0xFE94F82Bul}, {0xA54FF53Aul, 0x5F1D36F1ul},
		{0x510E527Ful, 0xADE682D1ul}, {0x9B05688Cul, 0x2B3E6C1Ful},
		{0x1F83D9ABul, 0xFB41BD6Bul}, {0x5BE0CD19ul, 0x137E2179ul}};

	for( int i = 0; i < 8; i++ )
		h[i] = ((unsigned __int64)iv[i][0] << 32) | (unsigned __int64)iv[i][1];

	used = 0;
	bytesLo = 0;
	bytesHi = 0;
}

void Sha512State::Bytes(const unsigned char *p, size_t bytes)
{
	ShaCount(bytesLo, bytesHi, bytes);
	while( bytes )
	{
		size_t take = 128 - used;
		if( take > bytes )
			take = bytes;
		memcpy(block + used, p, take);
		used += take;
		p += take;
		bytes -= take;
		if( used == 128 )
		{
			Block(block);
			used = 0;
		}
	}
}

void Sha512State::Final(unsigned char digest[64])
{
	unsigned __int64 bits = (((unsigned __int64)bytesHi << 32) | (unsigned __int64)bytesLo);
	unsigned __int64 hi = bits >> 61;
	unsigned __int64 lo = bits << 3;
	block[used++] = 0x80;
	if( used > 112 )
	{
		memset(block + used, 0, 128 - used);
		Block(block);
		used = 0;
	}
	memset(block + used, 0, 112 - used);
	ShaStore64(block + 112, hi);
	ShaStore64(block + 120, lo);
	Block(block);
	for( int i = 0; i < 8; i++ )
		ShaStore64(digest + 8*i, h[i]);
	ShaWipe(this, sizeof(*this));
}

void Sha512State::Simple(const unsigned char *p, size_t bytes, unsigned char digest[64])
{
	Sha512State s;
	s.Init();
	s.Bytes(p, bytes);
	s.Final(digest);
}

void Sha256HMAC(const unsigned char *key, size_t keyLength, const unsigned char *msg, size_t length, unsigned char digest[32])
{
	unsigned char hashed_key[32];
	if( keyLength > 64 )
	{
		Sha256State::Simple(key, keyLength, hashed_key);
		key = hashed_key;
		keyLength = 32;
	}

	unsigned char pad[64];
	memset(pad, 0x36, sizeof(pad));
	for( size_t i = 0; i < keyLength; i++ )
		pad[i] ^= key[i];

	Sha256State state;
	state.Init();
	state.Bytes(pad, sizeof(pad));
	state.Bytes(msg, length);

	unsigned char inner[32];
	state.Final(inner);

	memset(pad, 0x5C, sizeof(pad));
	for( size_t i = 0; i < keyLength; i++ )
		pad[i] ^= key[i];

	state.Init();
	state.Bytes(pad, sizeof(pad));
	state.Bytes(inner, sizeof(inner));
	state.Final(digest);
	ShaWipe(inner, sizeof(inner));
	ShaWipe(hashed_key, sizeof(hashed_key));
	ShaWipe(pad, sizeof(pad));
}
