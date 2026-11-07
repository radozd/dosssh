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

/*
 * Based on the ref10 implementation from SUPERCOP by
 * Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe,
 * Bo-Yin Yang. Public domain.
 * See ORIGIN.MD for the related Toyoyo/SSH2DOS adaptation.
 */

#include <string.h>

#include "SSHSHA.H"
#include "SSHCRYPT.H"

// Signed 32 * signed 32 -> signed 64, exact result.
// Watcom 16-bit: a in DX:AX, b in CX:BX.
// Auxiliary value [ax bx cx dx] means high to low 16-bit words.
__int64 Mul32(long a, long b);
#pragma aux Mul32 = \
    ".386"               \
    "shl edx, 16"        \
    "mov dx, ax"         \
    "shl ecx, 16"        \
    "mov cx, bx"         \
    "mov eax, edx"       \
    "imul ecx"           \
    "mov ebx, edx"       \
    "mov ecx, eax"       \
    "shr ecx, 16"        \
    "shr edx, 16"        \
    "xchg ax, dx"        \
    parm [ax dx] [bx cx]  \
    value [ax bx cx dx]   \
    modify exact [ax bx cx dx] nomemory;

// Signed carry shifts are always between 1 and 31 bits.
__int64 Sar64(__int64 value, int bits);
#pragma aux Sar64 = \
    ".386"               \
    "shl eax, 16"        \
    "mov ax, bx"         \
    "shl ecx, 16"        \
    "mov cx, dx"         \
    "mov edx, ecx"       \
    "mov cx, si"         \
    "shrd edx, eax, cl"  \
    "sar eax, cl"        \
    "mov bx, ax"         \
    "shr eax, 16"        \
    "mov ecx, edx"       \
    "mov dx, cx"         \
    "shr ecx, 16"        \
    parm [ax bx cx dx] [si] nomemory \
    value [ax bx cx dx]   \
    modify exact [ax bx cx dx] nomemory;

__int64 Shl64(__int64 value, int bits);
#pragma aux Shl64 = \
    ".386"               \
    "shl eax, 16"        \
    "mov ax, bx"         \
    "shl ecx, 16"        \
    "mov cx, dx"         \
    "mov edx, ecx"       \
    "mov cx, si"         \
    "shld eax, edx, cl"  \
    "shl edx, cl"        \
    "mov bx, ax"         \
    "shr eax, 16"        \
    "mov ecx, edx"       \
    "mov dx, cx"         \
    "shr ecx, 16"        \
    parm [ax bx cx dx] [si] nomemory \
    value [ax bx cx dx]   \
    modify exact [ax bx cx dx] nomemory;

static unsigned long Load3(const unsigned char *in)
{
	unsigned long result;
	result = (unsigned long)in[0];
	result |= ((unsigned long)in[1]) << 8;
	result |= ((unsigned long)in[2]) << 16;
	return result;
}

static unsigned long Load4(const unsigned char *in)
{
	unsigned long result;
	result = (unsigned long)in[0];
	result |= ((unsigned long)in[1]) << 8;
	result |= ((unsigned long)in[2]) << 16;
	result |= ((unsigned long)in[3]) << 24;
	return result;
}

struct FieldElement
{
	long v[10];

	void Zero();
	void One();
	void Copy(const FieldElement *f);
	void Add(const FieldElement *f, const FieldElement *g);
	void Sub(const FieldElement *f, const FieldElement *g);
	void Neg(const FieldElement *f);
	void FromBytes(const unsigned char *s);
	void ToBytes(unsigned char *s) const;
	bool IsNegative() const;
	bool IsNonzero() const;
	void Mul(const FieldElement *f, const FieldElement *g);
	void Square(const FieldElement *f);
	void Square2(const FieldElement *f);
	void Invert(const FieldElement *z);
	void Pow2523(const FieldElement *z);
	void ConditionalSwap(FieldElement *g, int b);
	void Mul121666(const FieldElement *f);

private:
	static void Mul121666Limb(long &remainder, long &carry, long value, long extra, int bits);
};

void FieldElement::Zero()
{
	for( int i = 0; i < 10; i++ )
		v[i] = 0;
}

void FieldElement::One()
{
	v[0] = 1;
	v[1] = 0;
	v[2] = 0;
	v[3] = 0;
	v[4] = 0;
	v[5] = 0;
	v[6] = 0;
	v[7] = 0;
	v[8] = 0;
	v[9] = 0;
}

void FieldElement::Copy(const FieldElement *f)
{
	for( int i = 0; i < 10; i++ )
		v[i] = f->v[i];
}

void FieldElement::Add(const FieldElement *f, const FieldElement *g)
{
	for( int i = 0; i < 10; i++ )
		v[i] = f->v[i] + g->v[i];
}

void FieldElement::Sub(const FieldElement *f, const FieldElement *g)
{
	for( int i = 0; i < 10; i++ )
		v[i] = f->v[i] - g->v[i];
}

void FieldElement::Neg(const FieldElement *f)
{
	for( int i = 0; i < 10; i++ )
		v[i] = -f->v[i];
}

bool FieldElement::IsNegative() const
{
	unsigned char s[32];
	ToBytes(s);
	return s[0] & 1;
}

bool FieldElement::IsNonzero() const
{
	unsigned char s[32];
	unsigned char r = 0;
	ToBytes(s);
	for( int i = 0; i < 32; i++ )
		r |= s[i];
	return r != 0;
}

void FieldElement::FromBytes(const unsigned char *s)
{
	__int64 h0 = Load4(s);
	__int64 h1 = Load3(s + 4) << 6;
	__int64 h2 = Load3(s + 7) << 5;
	__int64 h3 = Load3(s + 10) << 3;
	__int64 h4 = Load3(s + 13) << 2;
	__int64 h5 = Load4(s + 16);
	__int64 h6 = Load3(s + 20) << 7;
	__int64 h7 = Load3(s + 23) << 5;
	__int64 h8 = Load3(s + 26) << 4;
	__int64 h9 = (Load3(s + 29) & 8388607) << 2;

	__int64 carry9 = Sar64(h9 + (1L << 24), 25);
	h0 += carry9 * 19;
	h9 -= Shl64(carry9, 25);
	__int64 carry1 = Sar64(h1 + (1L << 24), 25);
	h2 += carry1;
	h1 -= Shl64(carry1, 25);
	__int64 carry3 = Sar64(h3 + (1L << 24), 25);
	h4 += carry3;
	h3 -= Shl64(carry3, 25);
	__int64 carry5 = Sar64(h5 + (1L << 24), 25);
	h6 += carry5;
	h5 -= Shl64(carry5, 25);
	__int64 carry7 = Sar64(h7 + (1L << 24), 25);
	h8 += carry7;
	h7 -= Shl64(carry7, 25);
	__int64 carry0 = Sar64(h0 + (1L << 25), 26);
	h1 += carry0;
	h0 -= Shl64(carry0, 26);
	__int64 carry2 = Sar64(h2 + (1L << 25), 26);
	h3 += carry2;
	h2 -= Shl64(carry2, 26);
	__int64 carry4 = Sar64(h4 + (1L << 25), 26);
	h5 += carry4;
	h4 -= Shl64(carry4, 26);
	__int64 carry6 = Sar64(h6 + (1L << 25), 26);
	h7 += carry6;
	h6 -= Shl64(carry6, 26);
	__int64 carry8 = Sar64(h8 + (1L << 25), 26);
	h9 += carry8;
	h8 -= Shl64(carry8, 26);

	v[0] = (long)h0;
	v[1] = (long)h1;
	v[2] = (long)h2;
	v[3] = (long)h3;
	v[4] = (long)h4;
	v[5] = (long)h5;
	v[6] = (long)h6;
	v[7] = (long)h7;
	v[8] = (long)h8;
	v[9] = (long)h9;
}

void FieldElement::ToBytes(unsigned char *s) const
{
	long h0 = v[0];
	long h1 = v[1];
	long h2 = v[2];
	long h3 = v[3];
	long h4 = v[4];
	long h5 = v[5];
	long h6 = v[6];
	long h7 = v[7];
	long h8 = v[8];
	long h9 = v[9];

	long q = (19 * h9 + (((long)1) << 24)) >> 25;
	q = (h0 + q) >> 26;
	q = (h1 + q) >> 25;
	q = (h2 + q) >> 26;
	q = (h3 + q) >> 25;
	q = (h4 + q) >> 26;
	q = (h5 + q) >> 25;
	q = (h6 + q) >> 26;
	q = (h7 + q) >> 25;
	q = (h8 + q) >> 26;
	q = (h9 + q) >> 25;

	h0 += 19 * q;

	h1 += h0 >> 26;
	h0 &= 0x3FFFFFF;
	h2 += h1 >> 25;
	h1 &= 0x1FFFFFF;
	h3 += h2 >> 26;
	h2 &= 0x3FFFFFF;
	h4 += h3 >> 25;
	h3 &= 0x1FFFFFF;
	h5 += h4 >> 26;
	h4 &= 0x3FFFFFF;
	h6 += h5 >> 25;
	h5 &= 0x1FFFFFF;
	h7 += h6 >> 26;
	h6 &= 0x3FFFFFF;
	h8 += h7 >> 25;
	h7 &= 0x1FFFFFF;
	h9 += h8 >> 26;
	h8 &= 0x3FFFFFF;
	h9 &= 0x1FFFFFF;

	s[0] = (unsigned char)(h0);
	s[1] = (unsigned char)(h0 >> 8);
	s[2] = (unsigned char)(h0 >> 16);
	s[3] = (unsigned char)((h0 >> 24) | (((unsigned long)h1 << 2)));
	s[4] = (unsigned char)(h1 >> 6);
	s[5] = (unsigned char)(h1 >> 14);
	s[6] = (unsigned char)((h1 >> 22) | (((unsigned long)h2 << 3)));
	s[7] = (unsigned char)(h2 >> 5);
	s[8] = (unsigned char)(h2 >> 13);
	s[9] = (unsigned char)((h2 >> 21) | (((unsigned long)h3 << 5)));
	s[10] = (unsigned char)(h3 >> 3);
	s[11] = (unsigned char)(h3 >> 11);
	s[12] = (unsigned char)((h3 >> 19) | (((unsigned long)h4 << 6)));
	s[13] = (unsigned char)(h4 >> 2);
	s[14] = (unsigned char)(h4 >> 10);
	s[15] = (unsigned char)(h4 >> 18);
	s[16] = (unsigned char)(h5);
	s[17] = (unsigned char)(h5 >> 8);
	s[18] = (unsigned char)(h5 >> 16);
	s[19] = (unsigned char)((h5 >> 24) | (((unsigned long)h6 << 1)));
	s[20] = (unsigned char)(h6 >> 7);
	s[21] = (unsigned char)(h6 >> 15);
	s[22] = (unsigned char)((h6 >> 23) | (((unsigned long)h7 << 3)));
	s[23] = (unsigned char)(h7 >> 5);
	s[24] = (unsigned char)(h7 >> 13);
	s[25] = (unsigned char)((h7 >> 21) | (((unsigned long)h8 << 4)));
	s[26] = (unsigned char)(h8 >> 4);
	s[27] = (unsigned char)(h8 >> 12);
	s[28] = (unsigned char)((h8 >> 20) | (((unsigned long)h9 << 6)));
	s[29] = (unsigned char)(h9 >> 2);
	s[30] = (unsigned char)(h9 >> 10);
	s[31] = (unsigned char)(h9 >> 18);
}

void FieldElement::Mul(const FieldElement *f, const FieldElement *g)
{
	long f0 = f->v[0];
	long f1 = f->v[1];
	long f2 = f->v[2];
	long f3 = f->v[3];
	long f4 = f->v[4];
	long f5 = f->v[5];
	long f6 = f->v[6];
	long f7 = f->v[7];
	long f8 = f->v[8];
	long f9 = f->v[9];
	long g0 = g->v[0];
	long g1 = g->v[1];
	long g2 = g->v[2];
	long g3 = g->v[3];
	long g4 = g->v[4];
	long g5 = g->v[5];
	long g6 = g->v[6];
	long g7 = g->v[7];
	long g8 = g->v[8];
	long g9 = g->v[9];

	long g1_19 = 19 * g1;
	long g2_19 = 19 * g2;
	long g3_19 = 19 * g3;
	long g4_19 = 19 * g4;
	long g5_19 = 19 * g5;
	long g6_19 = 19 * g6;
	long g7_19 = 19 * g7;
	long g8_19 = 19 * g8;
	long g9_19 = 19 * g9;

	long f1_2 = 2 * f1;
	long f3_2 = 2 * f3;
	long f5_2 = 2 * f5;
	long f7_2 = 2 * f7;
	long f9_2 = 2 * f9;

	__int64 h0 = Mul32(f0, g0) + Mul32(f1_2, g9_19) + Mul32(f2, g8_19) + Mul32(f3_2, g7_19) + Mul32(f4, g6_19) + Mul32(f5_2, g5_19) + Mul32(f6, g4_19) + Mul32(f7_2, g3_19) + Mul32(f8, g2_19) + Mul32(f9_2, g1_19);
	__int64 h1 = Mul32(f0, g1) + Mul32(f1, g0) + Mul32(f2, g9_19) + Mul32(f3, g8_19) + Mul32(f4, g7_19) + Mul32(f5, g6_19) + Mul32(f6, g5_19) + Mul32(f7, g4_19) + Mul32(f8, g3_19) + Mul32(f9, g2_19);
	__int64 h2 = Mul32(f0, g2) + Mul32(f1_2, g1) + Mul32(f2, g0) + Mul32(f3_2, g9_19) + Mul32(f4, g8_19) + Mul32(f5_2, g7_19) + Mul32(f6, g6_19) + Mul32(f7_2, g5_19) + Mul32(f8, g4_19) + Mul32(f9_2, g3_19);
	__int64 h3 = Mul32(f0, g3) + Mul32(f1, g2) + Mul32(f2, g1) + Mul32(f3, g0) + Mul32(f4, g9_19) + Mul32(f5, g8_19) + Mul32(f6, g7_19) + Mul32(f7, g6_19) + Mul32(f8, g5_19) + Mul32(f9, g4_19);
	__int64 h4 = Mul32(f0, g4) + Mul32(f1_2, g3) + Mul32(f2, g2) + Mul32(f3_2, g1) + Mul32(f4, g0) + Mul32(f5_2, g9_19) + Mul32(f6, g8_19) + Mul32(f7_2, g7_19) + Mul32(f8, g6_19) + Mul32(f9_2, g5_19);
	__int64 h5 = Mul32(f0, g5) + Mul32(f1, g4) + Mul32(f2, g3) + Mul32(f3, g2) + Mul32(f4, g1) + Mul32(f5, g0) + Mul32(f6, g9_19) + Mul32(f7, g8_19) + Mul32(f8, g7_19) + Mul32(f9, g6_19);
	__int64 h6 = Mul32(f0, g6) + Mul32(f1_2, g5) + Mul32(f2, g4) + Mul32(f3_2, g3) + Mul32(f4, g2) + Mul32(f5_2, g1) + Mul32(f6, g0) + Mul32(f7_2, g9_19) + Mul32(f8, g8_19) + Mul32(f9_2, g7_19);
	__int64 h7 = Mul32(f0, g7) + Mul32(f1, g6) + Mul32(f2, g5) + Mul32(f3, g4) + Mul32(f4, g3) + Mul32(f5, g2) + Mul32(f6, g1) + Mul32(f7, g0) + Mul32(f8, g9_19) + Mul32(f9, g8_19);
	__int64 h8 = Mul32(f0, g8) + Mul32(f1_2, g7) + Mul32(f2, g6) + Mul32(f3_2, g5) + Mul32(f4, g4) + Mul32(f5_2, g3) + Mul32(f6, g2) + Mul32(f7_2, g1) + Mul32(f8, g0) + Mul32(f9_2, g9_19);
	__int64 h9 = Mul32(f0, g9) + Mul32(f1, g8) + Mul32(f2, g7) + Mul32(f3, g6) + Mul32(f4, g5) + Mul32(f5, g4) + Mul32(f6, g3) + Mul32(f7, g2) + Mul32(f8, g1) + Mul32(f9, g0);

	__int64 carry0 = Sar64(h0 + (1L << 25), 26);
	h1 += carry0;
	h0 -= Shl64(carry0, 26);
	__int64 carry4 = Sar64(h4 + (1L << 25), 26);
	h5 += carry4;
	h4 -= Shl64(carry4, 26);
	__int64 carry1 = Sar64(h1 + (1L << 24), 25);
	h2 += carry1;
	h1 -= Shl64(carry1, 25);
	__int64 carry5 = Sar64(h5 + (1L << 24), 25);
	h6 += carry5;
	h5 -= Shl64(carry5, 25);
	__int64 carry2 = Sar64(h2 + (1L << 25), 26);
	h3 += carry2;
	h2 -= Shl64(carry2, 26);
	__int64 carry6 = Sar64(h6 + (1L << 25), 26);
	h7 += carry6;
	h6 -= Shl64(carry6, 26);
	__int64 carry3 = Sar64(h3 + (1L << 24), 25);
	h4 += carry3;
	h3 -= Shl64(carry3, 25);
	__int64 carry7 = Sar64(h7 + (1L << 24), 25);
	h8 += carry7;
	h7 -= Shl64(carry7, 25);
	carry4 = Sar64(h4 + (1L << 25), 26);
	h5 += carry4;
	h4 -= Shl64(carry4, 26);
	__int64 carry8 = Sar64(h8 + (1L << 25), 26);
	h9 += carry8;
	h8 -= Shl64(carry8, 26);
	__int64 carry9 = Sar64(h9 + (1L << 24), 25);
	h0 += carry9 * 19;
	h9 -= Shl64(carry9, 25);
	carry0 = Sar64(h0 + (1L << 25), 26);
	h1 += carry0;
	h0 -= Shl64(carry0, 26);

	v[0] = (long)h0;
	v[1] = (long)h1;
	v[2] = (long)h2;
	v[3] = (long)h3;
	v[4] = (long)h4;
	v[5] = (long)h5;
	v[6] = (long)h6;
	v[7] = (long)h7;
	v[8] = (long)h8;
	v[9] = (long)h9;
}

void FieldElement::Square(const FieldElement *f)
{
	long f0 = f->v[0];
	long f1 = f->v[1];
	long f2 = f->v[2];
	long f3 = f->v[3];
	long f4 = f->v[4];
	long f5 = f->v[5];
	long f6 = f->v[6];
	long f7 = f->v[7];
	long f8 = f->v[8];
	long f9 = f->v[9];

	long f0_2 = 2 * f0;
	long f1_2 = 2 * f1;
	long f2_2 = 2 * f2;
	long f3_2 = 2 * f3;
	long f4_2 = 2 * f4;
	long f5_2 = 2 * f5;
	long f6_2 = 2 * f6;
	long f7_2 = 2 * f7;
	long f5_38 = 38 * f5;
	long f6_19 = 19 * f6;
	long f7_38 = 38 * f7;
	long f8_19 = 19 * f8;
	long f9_38 = 38 * f9;

	__int64 h0 = Mul32(f0, f0) + Mul32(f1_2, f9_38) + Mul32(f2_2, f8_19) + Mul32(f3_2, f7_38) + Mul32(f4_2, f6_19) + Mul32(f5, f5_38);
	__int64 h1 = Mul32(f0_2, f1) + Mul32(f2, f9_38) + Mul32(f3_2, f8_19) + Mul32(f4, f7_38) + Mul32(f5_2, f6_19);
	__int64 h2 = Mul32(f0_2, f2) + Mul32(f1_2, f1) + Mul32(f3_2, f9_38) + Mul32(f4_2, f8_19) + Mul32(f5_2, f7_38) + Mul32(f6, f6_19);
	__int64 h3 = Mul32(f0_2, f3) + Mul32(f1_2, f2) + Mul32(f4, f9_38) + Mul32(f5_2, f8_19) + Mul32(f6, f7_38);
	__int64 h4 = Mul32(f0_2, f4) + Mul32(f1_2, f3_2) + Mul32(f2, f2) + Mul32(f5_2, f9_38) + Mul32(f6_2, f8_19) + Mul32(f7, f7_38);
	__int64 h5 = Mul32(f0_2, f5) + Mul32(f1_2, f4) + Mul32(f2_2, f3) + Mul32(f6, f9_38) + Mul32(f7_2, f8_19);
	__int64 h6 = Mul32(f0_2, f6) + Mul32(f1_2, f5_2) + Mul32(f2_2, f4) + Mul32(f3_2, f3) + Mul32(f7_2, f9_38) + Mul32(f8, f8_19);
	__int64 h7 = Mul32(f0_2, f7) + Mul32(f1_2, f6) + Mul32(f2_2, f5) + Mul32(f3_2, f4) + Mul32(f8, f9_38);
	__int64 h8 = Mul32(f0_2, f8) + Mul32(f1_2, f7_2) + Mul32(f2_2, f6) + Mul32(f3_2, f5_2) + Mul32(f4, f4) + Mul32(f9, f9_38);
	__int64 h9 = Mul32(f0_2, f9) + Mul32(f1_2, f8) + Mul32(f2_2, f7) + Mul32(f3_2, f6) + Mul32(f4_2, f5);

	__int64 carry0 = Sar64(h0 + (1L << 25), 26);
	h1 += carry0;
	h0 -= Shl64(carry0, 26);
	__int64 carry4 = Sar64(h4 + (1L << 25), 26);
	h5 += carry4;
	h4 -= Shl64(carry4, 26);
	__int64 carry1 = Sar64(h1 + (1L << 24), 25);
	h2 += carry1;
	h1 -= Shl64(carry1, 25);
	__int64 carry5 = Sar64(h5 + (1L << 24), 25);
	h6 += carry5;
	h5 -= Shl64(carry5, 25);
	__int64 carry2 = Sar64(h2 + (1L << 25), 26);
	h3 += carry2;
	h2 -= Shl64(carry2, 26);
	__int64 carry6 = Sar64(h6 + (1L << 25), 26);
	h7 += carry6;
	h6 -= Shl64(carry6, 26);
	__int64 carry3 = Sar64(h3 + (1L << 24), 25);
	h4 += carry3;
	h3 -= Shl64(carry3, 25);
	__int64 carry7 = Sar64(h7 + (1L << 24), 25);
	h8 += carry7;
	h7 -= Shl64(carry7, 25);
	carry4 = Sar64(h4 + (1L << 25), 26);
	h5 += carry4;
	h4 -= Shl64(carry4, 26);
	__int64 carry8 = Sar64(h8 + (1L << 25), 26);
	h9 += carry8;
	h8 -= Shl64(carry8, 26);
	__int64 carry9 = Sar64(h9 + (1L << 24), 25);
	h0 += carry9 * 19;
	h9 -= Shl64(carry9, 25);
	carry0 = Sar64(h0 + (1L << 25), 26);
	h1 += carry0;
	h0 -= Shl64(carry0, 26);

	v[0] = (long)h0;
	v[1] = (long)h1;
	v[2] = (long)h2;
	v[3] = (long)h3;
	v[4] = (long)h4;
	v[5] = (long)h5;
	v[6] = (long)h6;
	v[7] = (long)h7;
	v[8] = (long)h8;
	v[9] = (long)h9;
}

void FieldElement::Square2(const FieldElement *f)
{
	long f0 = f->v[0];
	long f1 = f->v[1];
	long f2 = f->v[2];
	long f3 = f->v[3];
	long f4 = f->v[4];
	long f5 = f->v[5];
	long f6 = f->v[6];
	long f7 = f->v[7];
	long f8 = f->v[8];
	long f9 = f->v[9];

	long f0_2 = 2 * f0;
	long f1_2 = 2 * f1;
	long f2_2 = 2 * f2;
	long f3_2 = 2 * f3;
	long f4_2 = 2 * f4;
	long f5_2 = 2 * f5;
	long f6_2 = 2 * f6;
	long f7_2 = 2 * f7;
	long f5_38 = 38 * f5;
	long f6_19 = 19 * f6;
	long f7_38 = 38 * f7;
	long f8_19 = 19 * f8;
	long f9_38 = 38 * f9;

	__int64 h0 = Mul32(f0, f0) + Mul32(f1_2, f9_38) + Mul32(f2_2, f8_19) + Mul32(f3_2, f7_38) + Mul32(f4_2, f6_19) + Mul32(f5, f5_38);
	__int64 h1 = Mul32(f0_2, f1) + Mul32(f2, f9_38) + Mul32(f3_2, f8_19) + Mul32(f4, f7_38) + Mul32(f5_2, f6_19);
	__int64 h2 = Mul32(f0_2, f2) + Mul32(f1_2, f1) + Mul32(f3_2, f9_38) + Mul32(f4_2, f8_19) + Mul32(f5_2, f7_38) + Mul32(f6, f6_19);
	__int64 h3 = Mul32(f0_2, f3) + Mul32(f1_2, f2) + Mul32(f4, f9_38) + Mul32(f5_2, f8_19) + Mul32(f6, f7_38);
	__int64 h4 = Mul32(f0_2, f4) + Mul32(f1_2, f3_2) + Mul32(f2, f2) + Mul32(f5_2, f9_38) + Mul32(f6_2, f8_19) + Mul32(f7, f7_38);
	__int64 h5 = Mul32(f0_2, f5) + Mul32(f1_2, f4) + Mul32(f2_2, f3) + Mul32(f6, f9_38) + Mul32(f7_2, f8_19);
	__int64 h6 = Mul32(f0_2, f6) + Mul32(f1_2, f5_2) + Mul32(f2_2, f4) + Mul32(f3_2, f3) + Mul32(f7_2, f9_38) + Mul32(f8, f8_19);
	__int64 h7 = Mul32(f0_2, f7) + Mul32(f1_2, f6) + Mul32(f2_2, f5) + Mul32(f3_2, f4) + Mul32(f8, f9_38);
	__int64 h8 = Mul32(f0_2, f8) + Mul32(f1_2, f7_2) + Mul32(f2_2, f6) + Mul32(f3_2, f5_2) + Mul32(f4, f4) + Mul32(f9, f9_38);
	__int64 h9 = Mul32(f0_2, f9) + Mul32(f1_2, f8) + Mul32(f2_2, f7) + Mul32(f3_2, f6) + Mul32(f4_2, f5);

	h0 += h0;
	h1 += h1;
	h2 += h2;
	h3 += h3;
	h4 += h4;
	h5 += h5;
	h6 += h6;
	h7 += h7;
	h8 += h8;
	h9 += h9;

	__int64 carry0 = Sar64(h0 + (1L << 25), 26);
	h1 += carry0;
	h0 -= Shl64(carry0, 26);
	__int64 carry4 = Sar64(h4 + (1L << 25), 26);
	h5 += carry4;
	h4 -= Shl64(carry4, 26);
	__int64 carry1 = Sar64(h1 + (1L << 24), 25);
	h2 += carry1;
	h1 -= Shl64(carry1, 25);
	__int64 carry5 = Sar64(h5 + (1L << 24), 25);
	h6 += carry5;
	h5 -= Shl64(carry5, 25);
	__int64 carry2 = Sar64(h2 + (1L << 25), 26);
	h3 += carry2;
	h2 -= Shl64(carry2, 26);
	__int64 carry6 = Sar64(h6 + (1L << 25), 26);
	h7 += carry6;
	h6 -= Shl64(carry6, 26);
	__int64 carry3 = Sar64(h3 + (1L << 24), 25);
	h4 += carry3;
	h3 -= Shl64(carry3, 25);
	__int64 carry7 = Sar64(h7 + (1L << 24), 25);
	h8 += carry7;
	h7 -= Shl64(carry7, 25);
	carry4 = Sar64(h4 + (1L << 25), 26);
	h5 += carry4;
	h4 -= Shl64(carry4, 26);
	__int64 carry8 = Sar64(h8 + (1L << 25), 26);
	h9 += carry8;
	h8 -= Shl64(carry8, 26);
	__int64 carry9 = Sar64(h9 + (1L << 24), 25);
	h0 += carry9 * 19;
	h9 -= Shl64(carry9, 25);
	carry0 = Sar64(h0 + (1L << 25), 26);
	h1 += carry0;
	h0 -= Shl64(carry0, 26);

	v[0] = (long)h0;
	v[1] = (long)h1;
	v[2] = (long)h2;
	v[3] = (long)h3;
	v[4] = (long)h4;
	v[5] = (long)h5;
	v[6] = (long)h6;
	v[7] = (long)h7;
	v[8] = (long)h8;
	v[9] = (long)h9;
}

void FieldElement::Invert(const FieldElement *z)
{
	FieldElement t0, t1, t2, t3;

	t0.Square(z);
	t1.Square(&t0);
	t1.Square(&t1);
	t1.Mul(z, &t1);
	t0.Mul(&t0, &t1);
	t2.Square(&t0);
	t1.Mul(&t1, &t2);
	t2.Square(&t1);
	for( int i = 1; i < 5; i++ )
		t2.Square(&t2);
	t1.Mul(&t2, &t1);
	t2.Square(&t1);
	for( int i = 1; i < 10; i++ )
		t2.Square(&t2);
	t2.Mul(&t2, &t1);
	t3.Square(&t2);
	for( int i = 1; i < 20; i++ )
		t3.Square(&t3);
	t2.Mul(&t3, &t2);
	t2.Square(&t2);
	for( int i = 1; i < 10; i++ )
		t2.Square(&t2);
	t1.Mul(&t2, &t1);
	t2.Square(&t1);
	for( int i = 1; i < 50; i++ )
		t2.Square(&t2);
	t2.Mul(&t2, &t1);
	t3.Square(&t2);
	for( int i = 1; i < 100; i++ )
		t3.Square(&t3);
	t2.Mul(&t3, &t2);
	t2.Square(&t2);
	for( int i = 1; i < 50; i++ )
		t2.Square(&t2);
	t1.Mul(&t2, &t1);
	t1.Square(&t1);
	for( int i = 1; i < 5; i++ )
		t1.Square(&t1);
	Mul(&t1, &t0);
}

void FieldElement::Pow2523(const FieldElement *z)
{
	FieldElement t0, t1, t2;

	t0.Square(z);
	t1.Square(&t0);
	t1.Square(&t1);
	t1.Mul(z, &t1);
	t0.Mul(&t0, &t1);
	t0.Square(&t0);
	t0.Mul(&t1, &t0);
	t1.Square(&t0);
	for( int i = 1; i < 5; i++ )
		t1.Square(&t1);
	t0.Mul(&t1, &t0);
	t1.Square(&t0);
	for( int i = 1; i < 10; i++ )
		t1.Square(&t1);
	t1.Mul(&t1, &t0);
	t2.Square(&t1);
	for( int i = 1; i < 20; i++ )
		t2.Square(&t2);
	t1.Mul(&t2, &t1);
	t1.Square(&t1);
	for( int i = 1; i < 10; i++ )
		t1.Square(&t1);
	t0.Mul(&t1, &t0);
	t1.Square(&t0);
	for( int i = 1; i < 50; i++ )
		t1.Square(&t1);
	t1.Mul(&t1, &t0);
	t2.Square(&t1);
	for( int i = 1; i < 100; i++ )
		t2.Square(&t2);
	t1.Mul(&t2, &t1);
	t1.Square(&t1);
	for( int i = 1; i < 50; i++ )
		t1.Square(&t1);
	t0.Mul(&t1, &t0);
	t0.Square(&t0);
	t0.Square(&t0);
	Mul(&t0, z);
}

struct GroupP2
{
	FieldElement X;
	FieldElement Y;
	FieldElement Z;
};
struct GroupP3
{
	FieldElement X;
	FieldElement Y;
	FieldElement Z;
	FieldElement T;
};
struct GroupP1P1
{
	FieldElement X;
	FieldElement Y;
	FieldElement Z;
	FieldElement T;
};
struct GroupPrecomp
{
	FieldElement yplusx;
	FieldElement yminusx;
	FieldElement xy2d;
};
struct GroupCached
{
	FieldElement YplusX;
	FieldElement YminusX;
	FieldElement Z;
	FieldElement T2d;
};

static const FieldElement Ed25519D = {
	{-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116}};
static const FieldElement Ed25519D2 = {
	{-21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199}};
static const FieldElement Ed25519SqrtM1 = {
	{-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482}};

/* Precomputed odd multiples of the basepoint for verification:
 * Bi[i] = (2*i+1)*B in GroupPrecomp format (yplusx, yminusx, xy2d) */
static const GroupPrecomp Bi[8] = {
	{{25967493, -14356035, 29566456, 3660896, -12694345, 4014787, 27544626, -11754271, -6079156, 2047605},
		{-12545711, 934262, -2722910, 3049990, -727428, 9406986, 12720692, 5043384, 19500929, -15469378},
		{-8738181, 4489570, 9688441, -14785194, 10184609, -12363380, 29287919, 11864899, -24514362, -4438546}},
	{{15636291, -9688557, 24204773, -7912398, 616977, -16685262, 27787600, -14772189, 28944400, -1550024},
		{16568933, 4717097, -11556148, -1102322, 15682896, -11807043, 16354577, -11775962, 7689662, 11199574},
		{30464156, -5976125, -11779434, -15670865, 23220365, 15915852, 7512774, 10017326, -17749093, -9920357}},
	{{10861363, 11473154, 27284546, 1981175, -30064349, 12577861, 32867885, 14515107, -15438304, 10819380},
		{4708026, 6336745, 20377586, 9066809, -11272109, 6594696, -25653668, 12483688, -12668491, 5581306},
		{19563160, 16186464, -29386857, 4097519, 10237984, -4348115, 28542350, 13850243, -23678021, -15815942}},
	{{5153746, 9909285, 1723747, -2777874, 30523605, 5516873, 19480852, 5230134, -23952439, -15175766},
		{-30269007, -3463509, 7665486, 10083793, 28475525, 1649722, 20654025, 16520125, 30598449, 7715701},
		{28881845, 14381568, 9657904, 3680757, -20181635, 7843316, -31400660, 1370708, 29794553, -1409300}},
	{{-22518993, -6692182, 14201702, -8745502, -23510406, 8844726, 18474211, -1361450, -13062696, 13821877},
		{-6455177, -7839871, 3374702, -4740862, -27098617, -10571707, 31655028, -7212327, 18853322, -14220951},
		{4566830, -12963868, -28974889, -12240689, -7602672, -2830569, -8514358, -10431137, 2207753, -3209784}},
	{{-25154831, -4185821, 29681144, 7868801, -6854661, -9423865, -12437364, -663000, -31111463, -16132436},
		{25576264, -2703214, 7349804, -11814844, 16472782, 9300885, 3844789, 15725684, 171356, 6466918},
		{23103977, 13316479, 9739013, -16149481, 817875, -15038942, 8965339, -14088058, -30714912, 16193877}},
	{{-33521811, 3180713, -2394130, 14003687, -16903474, -16270840, 17238398, 4729455, -18074513, 9256800},
		{-25182317, -4174131, 32336398, 5036987, -21236817, 11360617, 22616405, 9761698, -19827198, 630305},
		{-13720693, 2639453, -24237460, -7406481, 9494427, -5774029, -6554551, -15960994, -2449256, -14291300}},
	{{-3151181, -5046075, 9282714, 6866145, -31907062, -863023, -18940575, 15033784, 25105118, -7894876},
		{-24326370, 15950226, -31801215, -14592823, -11662737, -5090925, 1573892, -2625887, 2198790, -15804619},
		{-3099351, 10324967, -2241613, 7453183, -5446979, -2735503, -13812022, -16236442, -32461234,
			-12290683}}};

static void GeP1P1ToP2(GroupP2 *r, const GroupP1P1 *p)
{
	r->X.Mul(&p->X, &p->T);
	r->Y.Mul(&p->Y, &p->Z);
	r->Z.Mul(&p->Z, &p->T);
}

static void GeP1P1ToP3(GroupP3 *r, const GroupP1P1 *p)
{
	r->X.Mul(&p->X, &p->T);
	r->Y.Mul(&p->Y, &p->Z);
	r->Z.Mul(&p->Z, &p->T);
	r->T.Mul(&p->X, &p->Y);
}

static void GeP2Zero(GroupP2 *h)
{
	h->X.Zero();
	h->Y.One();
	h->Z.One();
}

static void GeP3ToCached(GroupCached *r, const GroupP3 *p)
{
	r->YplusX.Add(&p->Y, &p->X);
	r->YminusX.Sub(&p->Y, &p->X);
	r->Z.Copy(&p->Z);
	r->T2d.Mul(&p->T, &Ed25519D2);
}

static void GeP3ToP2(GroupP2 *r, const GroupP3 *p)
{
	r->X.Copy(&p->X);
	r->Y.Copy(&p->Y);
	r->Z.Copy(&p->Z);
}

static void GeP2Double(GroupP1P1 *r, const GroupP2 *p)
{
	FieldElement t0;
	r->X.Square(&p->X);
	r->Z.Square(&p->Y);
	r->T.Square2(&p->Z);
	r->Y.Add(&p->X, &p->Y);
	t0.Square(&r->Y);
	r->Y.Add(&r->Z, &r->X);
	r->Z.Sub(&r->Z, &r->X);
	r->X.Sub(&t0, &r->Y);
	r->T.Sub(&r->T, &r->Z);
}

static void GeMixedAdd(GroupP1P1 *r, const GroupP3 *p, const GroupPrecomp *q)
{
	FieldElement t0;
	r->X.Add(&p->Y, &p->X);
	r->Y.Sub(&p->Y, &p->X);
	r->Z.Mul(&r->X, &q->yplusx);
	r->Y.Mul(&r->Y, &q->yminusx);
	r->T.Mul(&q->xy2d, &p->T);
	t0.Add(&p->Z, &p->Z);
	r->X.Sub(&r->Z, &r->Y);
	r->Y.Add(&r->Z, &r->Y);
	r->Z.Add(&t0, &r->T);
	r->T.Sub(&t0, &r->T);
}

static void GeMixedSub(GroupP1P1 *r, const GroupP3 *p, const GroupPrecomp *q)
{
	FieldElement t0;
	r->X.Add(&p->Y, &p->X);
	r->Y.Sub(&p->Y, &p->X);
	r->Z.Mul(&r->X, &q->yminusx);
	r->Y.Mul(&r->Y, &q->yplusx);
	r->T.Mul(&q->xy2d, &p->T);
	t0.Add(&p->Z, &p->Z);
	r->X.Sub(&r->Z, &r->Y);
	r->Y.Add(&r->Z, &r->Y);
	r->Z.Sub(&t0, &r->T);
	r->T.Add(&t0, &r->T);
}

static void GeAdd(GroupP1P1 *r, const GroupP3 *p, const GroupCached *q)
{
	FieldElement t0;
	r->X.Add(&p->Y, &p->X);
	r->Y.Sub(&p->Y, &p->X);
	r->Z.Mul(&r->X, &q->YplusX);
	r->Y.Mul(&r->Y, &q->YminusX);
	r->T.Mul(&q->T2d, &p->T);
	t0.Mul(&p->Z, &q->Z);
	t0.Add(&t0, &t0);
	r->X.Sub(&r->Z, &r->Y);
	r->Y.Add(&r->Z, &r->Y);
	r->Z.Add(&t0, &r->T);
	r->T.Sub(&t0, &r->T);
}

static void GeSub(GroupP1P1 *r, const GroupP3 *p, const GroupCached *q)
{
	FieldElement t0;
	r->X.Add(&p->Y, &p->X);
	r->Y.Sub(&p->Y, &p->X);
	r->Z.Mul(&r->X, &q->YminusX);
	r->Y.Mul(&r->Y, &q->YplusX);
	r->T.Mul(&q->T2d, &p->T);
	t0.Mul(&p->Z, &q->Z);
	t0.Add(&t0, &t0);
	r->X.Sub(&r->Z, &r->Y);
	r->Y.Add(&r->Z, &r->Y);
	r->Z.Sub(&t0, &r->T);
	r->T.Add(&t0, &r->T);
}

/* Decompress an Edwards point from 32 bytes, negate x.
 * Returns 0 on success, -1 on failure. */
static int GeFromBytesNegateVarTime(GroupP3 *h, const unsigned char *s)
{
	FieldElement u, v, v3, vxx, check;

	h->Y.FromBytes(s);
	h->Z.One();
	u.Square(&h->Y);
	v.Mul(&u, &Ed25519D);
	u.Sub(&u, &h->Z); /* u = y^2 - 1 */
	v.Add(&v, &h->Z); /* v = d*y^2 + 1 */

	v3.Square(&v);
	v3.Mul(&v3, &v); /* v3 = v^3 */
	h->X.Square(&v3);
	h->X.Mul(&h->X, &v);
	h->X.Mul(&h->X, &u); /* x = uv^7 */

	h->X.Pow2523(&h->X); /* x = (uv^7)^((q-5)/8) */
	h->X.Mul(&h->X, &v3);
	h->X.Mul(&h->X, &u); /* x = uv^3(uv^7)^((q-5)/8) */

	vxx.Square(&h->X);
	vxx.Mul(&vxx, &v);
	check.Sub(&vxx, &u); /* vx^2 - u */
	if( check.IsNonzero() )
	{
		check.Add(&vxx, &u); /* vx^2 + u */
		if( check.IsNonzero() )
			return -1;
		h->X.Mul(&h->X, &Ed25519SqrtM1);
	}

	if( h->X.IsNegative() == (s[31] >> 7) )
		h->X.Neg(&h->X);

	h->T.Mul(&h->X, &h->Y);
	return 0;
}

static void GeToBytes(unsigned char *s, const GroupP2 *h)
{
	FieldElement recip, x, y;

	recip.Invert(&h->Z);
	x.Mul(&h->X, &recip);
	y.Mul(&h->Y, &recip);
	y.ToBytes(s);
	s[31] ^= x.IsNegative() << 7;
}

static void SlideScalar(signed char *r, const unsigned char *a)
{
	for( int i = 0; i < 256; i++ )
		r[i] = 1 & (a[i >> 3] >> (i & 7));

	for( int i = 0; i < 256; i++ )
	{
		if( r[i] )
		{
			for( int b = 1; b <= 6 && i + b < 256; b++ )
			{
				if( r[i + b] )
				{
					if( r[i] + (r[i + b] * (1 << b)) <= 15 )
					{
						r[i] += r[i + b] * (1 << b);
						r[i + b] = 0;
					}
					else if( r[i] - (r[i + b] * (1 << b)) >= -15 )
					{
						r[i] -= r[i + b] * (1 << b);
						for( int k = i + b; k < 256; k++ )
						{
							if( !r[k] )
							{
								r[k] = 1;
								break;
							}
							r[k] = 0;
						}
					}
					else
						break;
				}
			}
		}
	}
}

/* Odd multiples depend only on the host public key, not on the scalar.
 * Reuse them for the subgroup check and the signature equation. */
static void GePrecomputeOddMultiples(GroupCached *oddMultiples, const GroupP3 *point)
{
	GroupP1P1 t;
	GroupP3 u, a2;
	GroupP2 ap2;

	GeP3ToCached(&oddMultiples[0], point);
	GeP3ToP2(&ap2, point);
	GeP2Double(&t, &ap2);
	GeP1P1ToP3(&a2, &t);
	for( int i = 1; i < 8; i++ )
	{
		GeAdd(&t, &a2, &oddMultiples[i - 1]);
		GeP1P1ToP3(&u, &t);
		GeP3ToCached(&oddMultiples[i], &u);
	}
}

/* Combine variable-base and fixed-base scalar multiples for Ed25519 verification. */
static void GeDoubleScalarMultVarTime(GroupP2 *r, const unsigned char *a,
	const GroupCached *oddMultiples, const unsigned char *b)
{
	signed char aslide[256], bslide[256];
	SlideScalar(aslide, a);
	SlideScalar(bslide, b);

	GeP2Zero(r);

	int i = 255;
	for( ; i >= 0; i-- )
		if( aslide[i] || bslide[i] )
			break;

	GroupP1P1 t;
	GroupP3 u;
	for( ; i >= 0; i-- )
	{
		GeP2Double(&t, r);

		if( aslide[i] > 0 )
		{
			GeP1P1ToP3(&u, &t);
			GeAdd(&t, &u, &oddMultiples[aslide[i] / 2]);
		}
		else if( aslide[i] < 0 )
		{
			GeP1P1ToP3(&u, &t);
			GeSub(&t, &u, &oddMultiples[(-aslide[i]) / 2]);
		}

		if( bslide[i] > 0 )
		{
			GeP1P1ToP3(&u, &t);
			GeMixedAdd(&t, &u, &Bi[bslide[i] / 2]);
		}
		else if( bslide[i] < 0 )
		{
			GeP1P1ToP3(&u, &t);
			GeMixedSub(&t, &u, &Bi[(-bslide[i]) / 2]);
		}

		GeP1P1ToP2(r, &t);
	}
}

/*
 * ScReduce: reduce a 64-byte value modulo L
 * L = 2^252 + 27742317777372353535851937790883648493
 */
static void ScReduce(unsigned char *s)
{
	__int64 s0 = 2097151 & Load3(s);
	__int64 s1 = 2097151 & (Load4(s + 2) >> 5);
	__int64 s2 = 2097151 & (Load3(s + 5) >> 2);
	__int64 s3 = 2097151 & (Load4(s + 7) >> 7);
	__int64 s4 = 2097151 & (Load4(s + 10) >> 4);
	__int64 s5 = 2097151 & (Load3(s + 13) >> 1);
	__int64 s6 = 2097151 & (Load4(s + 15) >> 6);
	__int64 s7 = 2097151 & (Load3(s + 18) >> 3);
	__int64 s8 = 2097151 & Load3(s + 21);
	__int64 s9 = 2097151 & (Load4(s + 23) >> 5);
	__int64 s10 = 2097151 & (Load3(s + 26) >> 2);
	__int64 s11 = 2097151 & (Load4(s + 28) >> 7);
	__int64 s12 = 2097151 & (Load4(s + 31) >> 4);
	__int64 s13 = 2097151 & (Load3(s + 34) >> 1);
	__int64 s14 = 2097151 & (Load4(s + 36) >> 6);
	__int64 s15 = 2097151 & (Load3(s + 39) >> 3);
	__int64 s16 = 2097151 & Load3(s + 42);
	__int64 s17 = 2097151 & (Load4(s + 44) >> 5);
	__int64 s18 = 2097151 & (Load3(s + 47) >> 2);
	__int64 s19 = 2097151 & (Load4(s + 49) >> 7);
	__int64 s20 = 2097151 & (Load4(s + 52) >> 4);
	__int64 s21 = 2097151 & (Load3(s + 55) >> 1);
	__int64 s22 = 2097151 & (Load4(s + 57) >> 6);
	__int64 s23 = Load4(s + 60) >> 3;

	s11 += s23 * 666643;
	s12 += s23 * 470296;
	s13 += s23 * 654183;
	s14 -= s23 * 997805;
	s15 += s23 * 136657;
	s16 -= s23 * 683901;
	s23 = 0;

	s10 += s22 * 666643;
	s11 += s22 * 470296;
	s12 += s22 * 654183;
	s13 -= s22 * 997805;
	s14 += s22 * 136657;
	s15 -= s22 * 683901;
	s22 = 0;

	s9 += s21 * 666643;
	s10 += s21 * 470296;
	s11 += s21 * 654183;
	s12 -= s21 * 997805;
	s13 += s21 * 136657;
	s14 -= s21 * 683901;
	s21 = 0;

	s8 += s20 * 666643;
	s9 += s20 * 470296;
	s10 += s20 * 654183;
	s11 -= s20 * 997805;
	s12 += s20 * 136657;
	s13 -= s20 * 683901;
	s20 = 0;

	s7 += s19 * 666643;
	s8 += s19 * 470296;
	s9 += s19 * 654183;
	s10 -= s19 * 997805;
	s11 += s19 * 136657;
	s12 -= s19 * 683901;
	s19 = 0;

	s6 += s18 * 666643;
	s7 += s18 * 470296;
	s8 += s18 * 654183;
	s9 -= s18 * 997805;
	s10 += s18 * 136657;
	s11 -= s18 * 683901;
	s18 = 0;

	__int64 carry6 = Sar64(s6 + (1L << 20), 21);
	s7 += carry6;
	s6 -= Shl64(carry6, 21);
	__int64 carry8 = Sar64(s8 + (1L << 20), 21);
	s9 += carry8;
	s8 -= Shl64(carry8, 21);
	__int64 carry10 = Sar64(s10 + (1L << 20), 21);
	s11 += carry10;
	s10 -= Shl64(carry10, 21);
	__int64 carry12 = Sar64(s12 + (1L << 20), 21);
	s13 += carry12;
	s12 -= Shl64(carry12, 21);
	__int64 carry14 = Sar64(s14 + (1L << 20), 21);
	s15 += carry14;
	s14 -= Shl64(carry14, 21);
	__int64 carry16 = Sar64(s16 + (1L << 20), 21);
	s17 += carry16;
	s16 -= Shl64(carry16, 21);

	__int64 carry7 = Sar64(s7 + (1L << 20), 21);
	s8 += carry7;
	s7 -= Shl64(carry7, 21);
	__int64 carry9 = Sar64(s9 + (1L << 20), 21);
	s10 += carry9;
	s9 -= Shl64(carry9, 21);
	__int64 carry11 = Sar64(s11 + (1L << 20), 21);
	s12 += carry11;
	s11 -= Shl64(carry11, 21);
	__int64 carry13 = Sar64(s13 + (1L << 20), 21);
	s14 += carry13;
	s13 -= Shl64(carry13, 21);
	__int64 carry15 = Sar64(s15 + (1L << 20), 21);
	s16 += carry15;
	s15 -= Shl64(carry15, 21);

	s5 += s17 * 666643;
	s6 += s17 * 470296;
	s7 += s17 * 654183;
	s8 -= s17 * 997805;
	s9 += s17 * 136657;
	s10 -= s17 * 683901;
	s17 = 0;

	s4 += s16 * 666643;
	s5 += s16 * 470296;
	s6 += s16 * 654183;
	s7 -= s16 * 997805;
	s8 += s16 * 136657;
	s9 -= s16 * 683901;
	s16 = 0;

	s3 += s15 * 666643;
	s4 += s15 * 470296;
	s5 += s15 * 654183;
	s6 -= s15 * 997805;
	s7 += s15 * 136657;
	s8 -= s15 * 683901;
	s15 = 0;

	s2 += s14 * 666643;
	s3 += s14 * 470296;
	s4 += s14 * 654183;
	s5 -= s14 * 997805;
	s6 += s14 * 136657;
	s7 -= s14 * 683901;
	s14 = 0;

	s1 += s13 * 666643;
	s2 += s13 * 470296;
	s3 += s13 * 654183;
	s4 -= s13 * 997805;
	s5 += s13 * 136657;
	s6 -= s13 * 683901;
	s13 = 0;

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;

	__int64 carry0 = Sar64(s0 + (1L << 20), 21);
	s1 += carry0;
	s0 -= Shl64(carry0, 21);
	__int64 carry2 = Sar64(s2 + (1L << 20), 21);
	s3 += carry2;
	s2 -= Shl64(carry2, 21);
	__int64 carry4 = Sar64(s4 + (1L << 20), 21);
	s5 += carry4;
	s4 -= Shl64(carry4, 21);
	carry6 = Sar64(s6 + (1L << 20), 21);
	s7 += carry6;
	s6 -= Shl64(carry6, 21);
	carry8 = Sar64(s8 + (1L << 20), 21);
	s9 += carry8;
	s8 -= Shl64(carry8, 21);
	carry10 = Sar64(s10 + (1L << 20), 21);
	s11 += carry10;
	s10 -= Shl64(carry10, 21);

	__int64 carry1 = Sar64(s1 + (1L << 20), 21);
	s2 += carry1;
	s1 -= Shl64(carry1, 21);
	__int64 carry3 = Sar64(s3 + (1L << 20), 21);
	s4 += carry3;
	s3 -= Shl64(carry3, 21);
	__int64 carry5 = Sar64(s5 + (1L << 20), 21);
	s6 += carry5;
	s5 -= Shl64(carry5, 21);
	carry7 = Sar64(s7 + (1L << 20), 21);
	s8 += carry7;
	s7 -= Shl64(carry7, 21);
	carry9 = Sar64(s9 + (1L << 20), 21);
	s10 += carry9;
	s9 -= Shl64(carry9, 21);
	carry11 = Sar64(s11 + (1L << 20), 21);
	s12 += carry11;
	s11 -= Shl64(carry11, 21);

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;

	carry0 = Sar64(s0, 21);
	s1 += carry0;
	s0 -= Shl64(carry0, 21);
	carry1 = Sar64(s1, 21);
	s2 += carry1;
	s1 -= Shl64(carry1, 21);
	carry2 = Sar64(s2, 21);
	s3 += carry2;
	s2 -= Shl64(carry2, 21);
	carry3 = Sar64(s3, 21);
	s4 += carry3;
	s3 -= Shl64(carry3, 21);
	carry4 = Sar64(s4, 21);
	s5 += carry4;
	s4 -= Shl64(carry4, 21);
	carry5 = Sar64(s5, 21);
	s6 += carry5;
	s5 -= Shl64(carry5, 21);
	carry6 = Sar64(s6, 21);
	s7 += carry6;
	s6 -= Shl64(carry6, 21);
	carry7 = Sar64(s7, 21);
	s8 += carry7;
	s7 -= Shl64(carry7, 21);
	carry8 = Sar64(s8, 21);
	s9 += carry8;
	s8 -= Shl64(carry8, 21);
	carry9 = Sar64(s9, 21);
	s10 += carry9;
	s9 -= Shl64(carry9, 21);
	carry10 = Sar64(s10, 21);
	s11 += carry10;
	s10 -= Shl64(carry10, 21);
	carry11 = Sar64(s11, 21);
	s12 += carry11;
	s11 -= Shl64(carry11, 21);

	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;

	carry0 = Sar64(s0, 21);
	s1 += carry0;
	s0 -= Shl64(carry0, 21);
	carry1 = Sar64(s1, 21);
	s2 += carry1;
	s1 -= Shl64(carry1, 21);
	carry2 = Sar64(s2, 21);
	s3 += carry2;
	s2 -= Shl64(carry2, 21);
	carry3 = Sar64(s3, 21);
	s4 += carry3;
	s3 -= Shl64(carry3, 21);
	carry4 = Sar64(s4, 21);
	s5 += carry4;
	s4 -= Shl64(carry4, 21);
	carry5 = Sar64(s5, 21);
	s6 += carry5;
	s5 -= Shl64(carry5, 21);
	carry6 = Sar64(s6, 21);
	s7 += carry6;
	s6 -= Shl64(carry6, 21);
	carry7 = Sar64(s7, 21);
	s8 += carry7;
	s7 -= Shl64(carry7, 21);
	carry8 = Sar64(s8, 21);
	s9 += carry8;
	s8 -= Shl64(carry8, 21);
	carry9 = Sar64(s9, 21);
	s10 += carry9;
	s9 -= Shl64(carry9, 21);
	carry10 = Sar64(s10, 21);
	s11 += carry10;
	s10 -= Shl64(carry10, 21);

	s[0] = (unsigned char)(s0 >> 0);
	s[1] = (unsigned char)(s0 >> 8);
	s[2] = (unsigned char)((s0 >> 16) | (((unsigned long)s1 << 5)));
	s[3] = (unsigned char)(s1 >> 3);
	s[4] = (unsigned char)(s1 >> 11);
	s[5] = (unsigned char)((s1 >> 19) | (((unsigned long)s2 << 2)));
	s[6] = (unsigned char)(s2 >> 6);
	s[7] = (unsigned char)((s2 >> 14) | (((unsigned long)s3 << 7)));
	s[8] = (unsigned char)(s3 >> 1);
	s[9] = (unsigned char)(s3 >> 9);
	s[10] = (unsigned char)((s3 >> 17) | (((unsigned long)s4 << 4)));
	s[11] = (unsigned char)(s4 >> 4);
	s[12] = (unsigned char)(s4 >> 12);
	s[13] = (unsigned char)((s4 >> 20) | (((unsigned long)s5 << 1)));
	s[14] = (unsigned char)(s5 >> 7);
	s[15] = (unsigned char)((s5 >> 15) | (((unsigned long)s6 << 6)));
	s[16] = (unsigned char)(s6 >> 2);
	s[17] = (unsigned char)(s6 >> 10);
	s[18] = (unsigned char)((s6 >> 18) | (((unsigned long)s7 << 3)));
	s[19] = (unsigned char)(s7 >> 5);
	s[20] = (unsigned char)(s7 >> 13);
	s[21] = (unsigned char)(s8 >> 0);
	s[22] = (unsigned char)(s8 >> 8);
	s[23] = (unsigned char)((s8 >> 16) | (((unsigned long)s9 << 5)));
	s[24] = (unsigned char)(s9 >> 3);
	s[25] = (unsigned char)(s9 >> 11);
	s[26] = (unsigned char)((s9 >> 19) | (((unsigned long)s10 << 2)));
	s[27] = (unsigned char)(s10 >> 6);
	s[28] = (unsigned char)((s10 >> 14) | (((unsigned long)s11 << 7)));
	s[29] = (unsigned char)(s11 >> 1);
	s[30] = (unsigned char)(s11 >> 9);
	s[31] = (unsigned char)(s11 >> 17);
}

/*
 * X25519 / Curve25519 scalar multiplication (RFC 7748)
 * Uses the Montgomery ladder on the u-coordinate.
 * Reuses the field arithmetic methods defined above.
 */

/* Constant-time conditional swap */
void FieldElement::ConditionalSwap(FieldElement *g, int b)
{
	long mask = -(long)b;
	for( int i = 0; i < 10; i++ )
	{
		long x = mask & (v[i] ^ g->v[i]);
		v[i] ^= x;
		g->v[i] ^= x;
	}
}

/* X25519 ladder constant multiplication. Its input limbs are bounded by
 * two reduced field elements: <= 2^26 for even limbs, <= 2^25 for odd.
 * Split each signed limb into 13-bit pieces: all products and the carry
 * calculation fit in a signed 32-bit long on the 386. In particular, no
 * Watcom 64-bit multiply/shift helpers are needed in these 255 rounds. */
void FieldElement::Mul121666Limb(long &remainder, long &carry, long value, long extra, int bits)
{
	const long factor = 121666L;
	const int high_bits = bits - 13;
	const long radix = 1L << bits;

	long high_product = (value >> 13) * factor;
	long low_product = (value & 8191L) * factor;
	long low_sum = ((high_product & ((1L << high_bits) - 1L)) << 13) + low_product + extra;
	long low_carry = (low_sum + (radix >> 1)) >> bits;

	carry = (high_product >> high_bits) + low_carry;
	remainder = low_sum - low_carry * radix;
}

void FieldElement::Mul121666(const FieldElement *f)
{
	long last_remainder, last_carry;
	Mul121666Limb(last_remainder, last_carry, f->v[9], 0, 25);

	/* The carry out of limb 9 wraps into limb 0 with coefficient 19. */
	long carry = last_carry * 19;
	for( int i = 0; i < 9; i++ )
	{
		long next_carry;
		Mul121666Limb(v[i], next_carry, f->v[i], carry, 26 - (i & 1));
		carry = next_carry;
	}
	v[9] = last_remainder + carry;
}

void SshCurve::ScalarMult(unsigned char *q, const unsigned char *n, const unsigned char *p)
{
	unsigned char e[32];
	memcpy(e, n, 32);
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;

	FieldElement x1, x2, z2, x3, z3;
	x1.FromBytes(p);
	x2.One();
	z2.Zero();
	x3.Copy(&x1);
	z3.One();

	FieldElement tmp0, tmp1;
	int swap = 0;
	for( int pos = 254; pos >= 0; pos-- )
	{
		int b = (e[pos / 8] >> (pos & 7)) & 1;
		swap ^= b;
		x2.ConditionalSwap(&x3, swap);
		z2.ConditionalSwap(&z3, swap);
		swap = b;

		tmp0.Sub(&x3, &z3);
		tmp1.Sub(&x2, &z2);
		x2.Add(&x2, &z2);
		z2.Add(&x3, &z3);
		z3.Mul(&tmp0, &x2);
		z2.Mul(&z2, &tmp1);
		tmp0.Square(&tmp1);
		tmp1.Square(&x2);
		x3.Add(&z3, &z2);
		z2.Sub(&z3, &z2);
		x2.Mul(&tmp1, &tmp0);
		tmp1.Sub(&tmp1, &tmp0);
		z2.Square(&z2);
		z3.Mul121666(&tmp1);
		x3.Square(&x3);
		tmp0.Add(&tmp0, &z3);
		z3.Mul(&x1, &z2);
		z2.Mul(&tmp1, &tmp0);
	}
	x2.ConditionalSwap(&x3, swap);
	z2.ConditionalSwap(&z3, swap);

	z2.Invert(&z2);
	x2.Mul(&x2, &z2);
	x2.ToBytes(q);
}

/* Canonical compressed point encoding: y must be strictly < p=2^255-19.
 * The high bit encodes the sign of x and is deliberately masked. */
static bool EdCanonical(const unsigned char *p)
{
	static const unsigned char prime[32] = {0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
											0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
											0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};
	for( int i = 31; i >= 0; i-- )
	{
		unsigned char n = p[i];
		if( i == 31 )
			n &= 0x7F;
		if( n < prime[i] )
			return true;
		if( n > prime[i] )
			return false;
	}
	return false;
}

bool SshCurve::VerifyEd25519(const unsigned char *publicKey, const unsigned char *signature,
					const unsigned char *message, size_t messageLen)
{
	/* Reject noncanonical S: RFC8032 requires 0 <= S < L. */
	static const unsigned char order[32] = {0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7,
											0xA2, 0xDE, 0xF9, 0xDE, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};
	static const unsigned char zero[32] = {0};
	static const unsigned char identity[32] = {1};
	int cmp = 0;
	for( int i = 31; i >= 0; i-- )
	{
		if( signature[32 + i] != order[i] )
		{
			cmp = (signature[32 + i] < order[i]) ? -1 : 1;
			break;
		}
	}
	if( cmp != -1 || !EdCanonical(publicKey) || !EdCanonical(signature) )
		return false;

	/* An identity key is the only point in the prime-order subgroup for
	 * which [8]A is identity, since gcd(8, L) = 1. Its canonical
	 * encoding can be rejected directly, avoiding a third scalar multiply. */
	if( memcmp(publicKey, identity, 32) == 0 )
		return false;

	GroupP3 a;
	if( GeFromBytesNegateVarTime(&a, publicKey) != 0 || ((publicKey[31] & 0x80) && !a.X.IsNonzero()) )
		return false;

	GroupCached odd_multiples[8];
	GePrecomputeOddMultiples(odd_multiples, &a);

	/* Enforce [L]A = identity: this keeps the original strict
	 * prime-order host-key policy (including mixed-torsion rejection).
	 * In projective coordinates identity is X=0, Y=Z; converting to
	 * affine coordinates here would waste a full field inversion. */
	GroupP2 r;
	GeDoubleScalarMultVarTime(&r, order, odd_multiples, zero);
	FieldElement y_minus_z;
	y_minus_z.Sub(&r.Y, &r.Z);
	if( r.X.IsNonzero() || y_minus_z.IsNonzero() )
		return false;

	/* h = SHA-512(R || A || message) mod L */
	Sha512State hash_state;
	hash_state.Init();
	hash_state.Bytes(signature, 32); /* R */
	hash_state.Bytes(publicKey, 32); /* A */
	hash_state.Bytes(message, messageLen);

	unsigned char h[64];
	hash_state.Final(h);
	ScReduce(h);

	/* Copy S (second half of signature) */
	unsigned char scopy[32];
	memcpy(scopy, signature + 32, 32);

	/* Compute [S]B - [h]A = R (since A was negated, this is [S]B + [h](-A)) */
	GeDoubleScalarMultVarTime(&r, h, odd_multiples, scopy);
	
	unsigned char rcheck[32];
	GeToBytes(rcheck, &r);

	/* Compare with R (first half of signature) */
	int bad = 0;
	for( int i = 0; i < 32; i++ )
		bad |= rcheck[i] ^ signature[i];

	return bad == 0;
}

/* FIPS 197 AES-128 key expansion and forward rounds. Counter mode applies
 * the forward cipher for both directions (RFC 4344). */
static const unsigned char SshSbox[256] = {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

void SshCrypt::Zero(void *p, size_t size)
{
	volatile unsigned char *q = (volatile unsigned char *)p;
	while( size-- )
		*q++ = 0;
}

bool SshCrypt::Equal(const unsigned char *a, const unsigned char *b, size_t size)
{
	if( a == NULL || b == NULL )
		return false;

	unsigned char difference = 0;
	for( size_t i = 0; i < size; i++ )
		difference |= a[i] ^ b[i];
	return difference == 0;
}

//static unsigned char SshXtime(unsigned char x)
//{
//	return (unsigned char)((x << 1) ^ ((x >> 7) * 0x1B));
//}

static unsigned char SshXtime(unsigned char x);
#pragma aux SshXtime = \
	"add al, al" \
	"sbb ah, ah" \
	"and ah, 1Bh" \
	"xor al, ah" \
	parm [al] value [al] modify exact [ax] nomemory;

static void SshAesExpand(unsigned char w[176], const unsigned char key[16])
{
	memcpy(w, key, 16);

	static const unsigned char rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
	for( int i = 16; i < 176; i += 4 )
	{
		unsigned char tmp[4];
		memcpy(tmp, w + i - 4, 4);
		if( (i % 16) == 0 )
		{
			unsigned char t = tmp[0];
			tmp[0] = SshSbox[tmp[1]] ^ rcon[i / 16 - 1];
			tmp[1] = SshSbox[tmp[2]];
			tmp[2] = SshSbox[tmp[3]];
			tmp[3] = SshSbox[t];
		}
		for( int j = 0; j < 4; j++ )
			w[i + j] = w[i + j - 16] ^ tmp[j];
	}
}

void SSHCRYPT_AES::EncryptBlock(unsigned char b[16]) const
{
	for( int i = 0; i < 16; i++ )
		b[i] ^= round[i];
	
	for( int r = 1; r <= 10; r++ )
	{
		unsigned char t[16];
		for( int i = 0; i < 16; i++ )
			t[i] = SshSbox[b[i]];
		/* State stored column-major: ShiftRows. */
		b[0] = t[0];
		b[4] = t[4];
		b[8] = t[8];
		b[12] = t[12];
		b[1] = t[5];
		b[5] = t[9];
		b[9] = t[13];
		b[13] = t[1];
		b[2] = t[10];
		b[6] = t[14];
		b[10] = t[2];
		b[14] = t[6];
		b[3] = t[15];
		b[7] = t[3];
		b[11] = t[7];
		b[15] = t[11];
		if( r != 10 )
		{
			for( int i = 0; i < 16; i += 4 )
			{
				unsigned char a = b[i];
				unsigned char c = b[i + 1];
				unsigned char d = b[i + 2];
				unsigned char e = b[i + 3];
				unsigned char x = a ^ c ^ d ^ e;
				b[i] ^= x ^ SshXtime((unsigned char)(a ^ c));
				b[i + 1] ^= x ^ SshXtime((unsigned char)(c ^ d));
				b[i + 2] ^= x ^ SshXtime((unsigned char)(d ^ e));
				b[i + 3] ^= x ^ SshXtime((unsigned char)(e ^ a));
			}
		}
		for( int i = 0; i < 16; i++ )
			b[i] ^= round[16*r + i];
	}
}

void SSHCRYPT_AES::Init(const unsigned char key[16], const unsigned char iv[16])
{
	SshAesExpand(round, key);
	memcpy(counter, iv, 16);
	memset(block, 0, 16);
	used = 16;
}

void SSHCRYPT_AES::Xor(unsigned char *p, size_t length)
{
	while( length )
	{
		if( used == 16 )
		{
			memcpy(block, counter, 16);
			EncryptBlock(block);
			for( int j = 16; j > 0; j-- )
			{
				counter[j - 1]++;
				if( counter[j - 1] )
					break;
			}
			used = 0;
		}
		size_t count = 16 - used;
		if( count > length )
			count = length;
		for( size_t i = 0; i < count; i++ )
			p[i] ^= block[used + i];
		used += count;
		p += count;
		length -= count;
	}
}

/* HMAC-DRBG SHA-256; SSHENT.CPP prepares and mixes the seed material. */
void SSHCRYPT_RNG::Update(const unsigned char *seed, size_t length)
{
	unsigned char msg[97];
	memcpy(msg, value, 32);
	msg[32] = 0;
	if( length )
		memcpy(msg + 33, seed, length);

	unsigned char next[32];
	Sha256HMAC(key, 32, msg, 33 + length, next);
	memcpy(key, next, 32);
	Sha256HMAC(key, 32, value, 32, next);
	memcpy(value, next, 32);
	if( length )
	{
		msg[32] = 1;
		memcpy(msg, value, 32);
		Sha256HMAC(key, 32, msg, 33 + length, next);
		memcpy(key, next, 32);
		Sha256HMAC(key, 32, value, 32, next);
		memcpy(value, next, 32);
	}
	SshCrypt::Zero(msg, sizeof(msg));
	SshCrypt::Zero(next, sizeof(next));
}

void SSHCRYPT_RNG::Init(const unsigned char seed[64])
{
	memset(this, 0, sizeof(*this));
	memset(value, 1, 32);
	Update(seed, 64);
	paddingUsed = sizeof(padding);
	initialized = true;
}

bool SSHCRYPT_RNG::Generate(unsigned char *p, size_t len)
{
	if( !initialized || len == 0 )
		return false;

	unsigned char next[32];
	while( len )
	{
		Sha256HMAC(key, 32, value, 32, next);
		memcpy(value, next, 32);
		size_t size = len < 32 ? len : 32;
		memcpy(p, next, size);
		p += size;
		len -= size;
	}
	Update(NULL, 0);
	SshCrypt::Zero(next, sizeof(next));
	return true;
}

void SSHCRYPT_RNG::GeneratePadding(unsigned char *p, size_t len)
{
	if( len == 0 )
		return;

		if( paddingUsed + len > sizeof(padding) )
	{
		Generate(padding, sizeof(padding));
		paddingUsed = 0;
	}
	memcpy(p, padding + paddingUsed, len);
	paddingUsed += len;
}

void SSHCRYPT_RNG::Clear()
{
	SshCrypt::Zero(this, sizeof(*this));
}
