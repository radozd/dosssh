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

#include <errno.h>
#include <dos.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "CONFIG.H"
#include "GLOBALS.H"
#include "SSHCRYPT.H"
#include "SSHSCAN.H"
#include "UTIL.H"

/* DOSSSH.DAT is ASCII text with explicit CRLF endings:
 * 128 HEX characters (64-byte seed), CRLF, CRLF,
 * then: normalized-host SP ssh-ed25519 SP base64(51-byte SSH key blob) CRLF.
 * The key lines use OpenSSH known_hosts syntax. */

static const int SSHDATA_MAX_HOSTS = 128;
static const size_t SSHDATA_SEED_HEX = 128;
static const size_t SSHDATA_KEY_BASE64 = 68;
static char s_dataPath[] = "C:\\DOSSSH.DAT";
static char s_tempPath[] = "C:\\DOSSSH.TMP";
static char s_backPath[] = "C:\\DOSSSH.BAK";
static const char s_base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char s_keyType[] = " ssh-ed25519 ";

// DOS 21h/36h reports FFFFh in AX if the specified drive is invalid.
// This is a one-based drive number: 1=A, 2=B, 3=C.
static bool SshDataDrive(int drive)
{
	union REGS regs;
	memset(&regs, 0, sizeof(regs));
	regs.h.ah = 0x36;
	regs.h.dl = (unsigned char)drive;
	intdos(&regs, &regs);
	return regs.x.ax != 0xFFFFu;
}

bool SshData::Select(unsigned char launchedDrive)
{
	unsigned char drive = 2;
	if( !SshDataDrive(3) )
	{
		if( launchedDrive > 1u || !SshDataDrive((int)launchedDrive + 1) )
			return false;
		drive = launchedDrive;
	}

	s_dataPath[0] = (char)('A' + drive);
	s_tempPath[0] = (char)('A' + drive);
	s_backPath[0] = (char)('A' + drive);
	return true;
}

unsigned char SshData::Drive()
{
	return (unsigned char)(s_dataPath[0] - 'A');
}

static int SshDataReadLine(FILE *file, char *line, size_t capacity)
{
	if( capacity < 3 || capacity > (size_t)INT_MAX )
		return 0;
	if( !fgets(line, (int)capacity, file) )
		return feof(file) && !ferror(file) ? -1 : 0;

	size_t length = strlen(line);
	if( length < 2 || line[length - 2] != '\r' || line[length - 1] != '\n' )
		return 0;

	for( size_t i = 0; i < length - 2; i++ )
	{
		unsigned char ch = (unsigned char)line[i];
		if( ch < 32 || ch > 126 )
			return 0;
	}
	line[length - 2] = '\0';
	return 1;
}

static int SshDataHexDigit(char ch)
{
	if( ch >= '0' && ch <= '9' )
		return ch - '0';
	if( ch >= 'A' && ch <= 'F' )
		return ch - 'A' + 10;
	if( ch >= 'a' && ch <= 'f' )
		return ch - 'a' + 10;
	return -1;
}

static bool SshDataReadSeed(const char *line, unsigned char seed[64])
{
	if( strlen(line) != SSHDATA_SEED_HEX )
		return false;

	for( size_t i = 0; i < 64; i++ )
	{
		int high = SshDataHexDigit(line[2*i]);
		int low = SshDataHexDigit(line[2*i + 1]);
		if( high < 0 || low < 0 )
			return false;
		seed[i] = (unsigned char)((high << 4) | low);
	}
	return true;
}

static bool SshDataWriteSeed(FILE *file, const unsigned char seed[64])
{
	static const char digits[] = "0123456789ABCDEF";
	char line[129];
	for( size_t i = 0; i < 64; i++ )
	{
		line[2*i] = digits[seed[i] >> 4];
		line[2*i + 1] = digits[seed[i] & 15u];
	}
	line[SSHDATA_SEED_HEX] = '\0';
	bool ok = fprintf(file, "%s\r\n\r\n", line) >= 0;
	SshCrypt::Zero(line, sizeof(line));
	return ok;
}

static int SshDataBase64Digit(char ch)
{
	if( !ch )
		return -1;
	const char *p = strchr(s_base64, ch);
	return p ? (int)(p - s_base64) : -1;
}

static bool SshDataKeyValid(const unsigned char *key)
{
	return memcmp(key, "\0\0\0\013ssh-ed25519\0\0\0\040", 19) == 0;
}

static bool SshDataReadKey(const char *text, unsigned char key[51])
{
	if( strlen(text) != SSHDATA_KEY_BASE64 )
		return false;

	for( size_t i = 0; i < 17; i++ )
	{
		int a = SshDataBase64Digit(text[4*i]);
		int b = SshDataBase64Digit(text[4*i + 1]);
		int c = SshDataBase64Digit(text[4*i + 2]);
		int d = SshDataBase64Digit(text[4*i + 3]);
		if( a < 0 || b < 0 || c < 0 || d < 0 )
			return false;

		key[3*i] = (unsigned char)((a << 2) | (b >> 4));
		key[3*i + 1] = (unsigned char)((b << 4) | (c >> 2));
		key[3*i + 2] = (unsigned char)((c << 6) | d);
	}
	return SshDataKeyValid(key);
}

static void SshDataWriteBase64(const unsigned char key[51], char text[69])
{
	for( size_t i = 0, j = 0; i < 51; i += 3, j += 4 )
	{
		unsigned int a = key[i];
		unsigned int b = key[i + 1];
		unsigned int c = key[i + 2];
		text[j] = s_base64[a >> 2];
		text[j + 1] = s_base64[((a & 3u) << 4) | (b >> 4)];
		text[j + 2] = s_base64[((b & 15u) << 2) | (c >> 6)];
		text[j + 3] = s_base64[c & 63u];
	}
	text[SSHDATA_KEY_BASE64] = '\0';
}

static bool SshDataHostName(char output[144], const char *host, unsigned int port)
{
	if( !host || !host[0] || port == 0 )
		return false;

	int n = 0;
	if( port != SSH_DEFAULT_PORT )
		output[n++] = '[';

	for( int i = 0; host[i]; i++ )
	{
		unsigned char ch = (unsigned char)host[i];

		if( i >= 127 || !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_' || ch == ':') )
			return false;
		output[n++] = (ch >= 'A' && ch <= 'Z') ? (char)(ch - 'A' + 'a') : (char)ch;
	}

	if( port != SSH_DEFAULT_PORT )
	{
		output[n++] = ']';
		output[n++] = ':';
		char number[8];
		SprintfTrunc(number, sizeof(number), "%u", port);
		for( int i = 0; number[i]; i++ )
			output[n++] = number[i];
	}

	output[n] = '\0';
	return true;
}

static bool SshDataStoredName(const char *name, size_t length)
{
	if( length == 0 || length >= 144 )
		return false;

	size_t start = 0;
	size_t host_end = length;
	if( name[0] == '[' )
	{
		start = 1;
		host_end = start;
		while( host_end < length && name[host_end] != ']' )
			host_end++;
		if( host_end == length || host_end == start || host_end >= length-2 || name[host_end + 1] != ':' || name[host_end + 2] == '0' )
			return false;

		unsigned int port = 0;
		for( size_t i = host_end + 2; i < length; i++ )
		{
			unsigned char digit = (unsigned char)name[i];
			if( digit < '0' || digit > '9' )
				return false;
			unsigned int value = (unsigned int)(digit - '0');
			if( port > (65535u - value) / 10u )
				return false;
			port = port * 10u + value;
		}
		if( port == SSH_DEFAULT_PORT )
			return false;
	}
	if( host_end - start > 127 )
		return false;

	for( size_t i = start; i < host_end; i++ )
	{
		unsigned char ch = (unsigned char)name[i];
		if( !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_' || ch == ':') )
			return false;
	}
	return true;
}

static bool SshDataReadHost(char *line, unsigned char key[51])
{
	char host[144];
	char text[69];
	if( sscanf(line, "%143s ssh-ed25519 %68s", host, text) != 2 )
		return false;

	size_t host_length = strlen(host);
	if( !SshDataStoredName(host, host_length) ||
		strlen(line) != host_length + sizeof(s_keyType) - 1 + SSHDATA_KEY_BASE64 ||
		strncmp(line + host_length, s_keyType, sizeof(s_keyType) - 1) != 0 ||
		!SshDataReadKey(text, key) )
	{
		return false;
	}

	strcpy(line, host);
	return true;
}

static bool SshDataWriteHost(FILE *file, const char *host, const unsigned char key[51])
{
	char text[69];
	SshDataWriteBase64(key, text);
	return fprintf(file, "%s ssh-ed25519 %s\r\n", host, text) >= 0;
}

// 1 = identical key, -1 = changed key, 0 = unknown host.
static bool SshDataVerify(const char *path, unsigned char seed[64],
	const char *lookup, const unsigned char *expectedKey, int *match, int *count)
{
	FILE *file = fopen(path, "rb");
	if( !file )
		return false;

	char line[256];
	unsigned char key[51];
	bool valid = SshDataReadLine(file, line, sizeof(line)) == 1 && SshDataReadSeed(line, seed) && SshDataReadLine(file, line, sizeof(line)) == 1 && line[0] == '\0';
	int total = 0;
	if( match )
		*match = 0;

	while( valid )
	{
		int status = SshDataReadLine(file, line, sizeof(line));
		if( status == -1 )
			break;

		if( status != 1 || total == SSHDATA_MAX_HOSTS || !SshDataReadHost(line, key) )
		{
			valid = false;
			break;
		}

		total++;
		if( lookup && strcmp(line, lookup) == 0 )
		{
			if( *match == -1 || memcmp(key, expectedKey, sizeof(key)) != 0 )
				*match = -1;
			else
				*match = 1;
		}
	}
	if( fclose(file) != 0 )
		valid = false;

	if( valid && count )
		*count = total;

	if( !valid )
		SshCrypt::Zero(seed, 64);

	SshCrypt::Zero(line, sizeof(line));
	SshCrypt::Zero(key, sizeof(key));
	return valid;
}

static bool SshDataRecover()
{
	FILE *file = fopen(s_dataPath, "rb");
	if( file )
	{
		fclose(file);
		return true;
	}
	if( errno != ENOENT )
		return false;

	file = fopen(s_backPath, "rb");
	if( file )
	{
		fclose(file);

		unsigned char seed[64];
		bool valid = SshDataVerify(s_backPath, seed, NULL, NULL, NULL, NULL);
		SshCrypt::Zero(seed, sizeof(seed));
		if( !valid )
			return false;

		return rename(s_backPath, s_dataPath) == 0;
	}
	return errno == ENOENT;
}

bool SshData::LoadSeed(unsigned char seed[64], bool &present)
{
	present = false;
	SshCrypt::Zero(seed, 64);
	if( !SshDataRecover() )
		return false;

	FILE *file = fopen(s_dataPath, "rb");
	if( file )
	{
		fclose(file);
		present = true;
		return SshDataVerify(s_dataPath, seed, NULL, NULL, NULL, NULL);
	}
	return errno == ENOENT;
}

static bool SshDataCommit(const unsigned char newSeed[64], const char *newHost, const unsigned char *newKey)
{
	unsigned char old_seed[64];
	bool had_file = false;
	if( !SshData::LoadSeed(old_seed, had_file) )
	{
		SshCrypt::Zero(old_seed, sizeof(old_seed));
		return false;
	}

	int old_count = 0;
	bool valid = !had_file || SshDataVerify(s_dataPath, old_seed, NULL, NULL, NULL, &old_count);
	SshCrypt::Zero(old_seed, sizeof(old_seed));
	if( !valid || (newHost && (old_count == SSHDATA_MAX_HOSTS || !newKey || !SshDataKeyValid(newKey))) )
		return false;

	FILE *old = NULL;
	char line[256];
	if( had_file )
	{
		old = fopen(s_dataPath, "rb");
		if( !old )
			return false;

		bool header = SshDataReadLine(old, line, sizeof(line)) == 1 && SshDataReadLine(old, line, sizeof(line)) == 1 && line[0] == '\0';
		SshCrypt::Zero(line, sizeof(line));
		if( !header )
		{
			fclose(old);
			return false;
		}
	}

	// An abandoned TMP has not been committed; the validated DAT wins.
	remove(s_tempPath);
	FILE *out = fopen(s_tempPath, "wb");
	if( !out )
	{
		if( old )
			fclose(old);
		return false;
	}

	bool ok = SshDataWriteSeed(out, newSeed);
	if( old )
	{
		int status = 0;
		while( ok && (status = SshDataReadLine(old, line, sizeof(line))) == 1 )
			ok = fprintf(out, "%s\r\n", line) >= 0;
		if( ok && status != -1 )
			ok = false;
		if( fclose(old) != 0 )
			ok = false;
	}

	SshCrypt::Zero(line, sizeof(line));
	if( ok && newHost )
		ok = SshDataWriteHost(out, newHost, newKey);
	if( fflush(out) != 0 )
		ok = false;
	if( fclose(out) != 0 )
		ok = false;

	if( ok )
	{
		unsigned char verified[64];
		int match = 0;
		int count = 0;
		ok = SshDataVerify(s_tempPath, verified, newHost, newKey, newHost ? &match : NULL, &count) &&
			SshCrypt::Equal(verified, newSeed, sizeof(verified)) &&
			count == old_count + (newHost ? 1 : 0) && (!newHost || match == 1);
		SshCrypt::Zero(verified, sizeof(verified));
	}
	if( !ok )
	{
		remove(s_tempPath);
		return false;
	}

	if( had_file && remove(s_backPath) != 0 && errno != ENOENT )
	{
		remove(s_tempPath);
		return false;
	}
	if( had_file && rename(s_dataPath, s_backPath) != 0 )
	{
		remove(s_tempPath);
		return false;
	}
	if( rename(s_tempPath, s_dataPath) != 0 )
	{
		if( had_file )
			rename(s_backPath, s_dataPath);
		return false;
	}
	if( had_file )
		remove(s_backPath);
	return true;
}

bool SshData::RotateSeed(const unsigned char seed[64])
{
	return SshDataCommit(seed, NULL, NULL);
}

bool SshData::KnownHost(const char *host, unsigned int port, const unsigned char *key,
	size_t keySize, const unsigned char digest[32])
{
	char lookup[144];
	if( keySize != 51 || !SshDataKeyValid(key) || !SshDataHostName(lookup, host, port) )
		return false;

	unsigned char seed[64];
	int match;
	if( !SshDataVerify(s_dataPath, seed, lookup, key, &match, NULL) )
	{
		SshCrypt::Zero(seed, sizeof(seed));
		return false;
	}
	if( match == 1 )
	{
		SshCrypt::Zero(seed, sizeof(seed));
		return true;
	}
	if( match == -1 )
	{
		printf("WARNING: SSH HOST KEY CHANGED for %s!\n", lookup);
		printf("Refusing connection. Check the host independently.\n");
		SshCrypt::Zero(seed, sizeof(seed));
		return false;
	}

	char fingerprint[52];
	SshScanFingerprint(digest, fingerprint);
	if( !DosConfirmHost(lookup, fingerprint) )
	{
		SshCrypt::Zero(seed, sizeof(seed));
		return false;
	}

	int current;
	if( !SshDataVerify(s_dataPath, seed, lookup, key, &current, NULL) || current != 0 )
	{
		SshCrypt::Zero(seed, sizeof(seed));
		return false;
	}
	bool saved = SshDataCommit(seed, lookup, key);
	SshCrypt::Zero(seed, sizeof(seed));
	return saved;
}
