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

#ifndef DOSSSH_UTIL_H
#define DOSSSH_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

enum
{
	VT_UNDERLINE = 1,
	VT_REVERSE = 2,
	VT_BOLD = 4
};

void CopyDataTrunc(char *dst, size_t dstSize, const char *src, size_t srcLen);
void CopyTrunc(char *dst, size_t dstSize, const char *src);

void SprintfTruncV(char *dst, size_t dstSize, const char *fmt, va_list ap);
void SprintfTrunc(char *dst, size_t dstSize, const char *fmt, ...);

void FormatSize(char *dst, size_t dstSize, __int64 bytes);
void ProbeFreeMem(char *buf, size_t bufSize);

#endif
