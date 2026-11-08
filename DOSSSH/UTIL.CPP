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

#include <malloc.h>
#include <mem.h>
#include <stdio.h>

#include "inlines.h"

#include "UTIL.H"

// Strings

void CopyDataTrunc(char *dst, size_t dstSize, const char *src, size_t srcLen)
{
	if( dst == NULL || dstSize == 0 )
		return;

	dst[0] = '\0';
	if( src == NULL )
		return;

	size_t copy_len = srcLen;
	if( copy_len > dstSize - 1 )
		copy_len = dstSize - 1;

	if( copy_len > 0 )
		memcpy(dst, src, copy_len);

	dst[copy_len] = '\0';
}

void CopyTrunc(char *dst, size_t dstSize, const char *src)
{
	CopyDataTrunc(dst, dstSize, src, src ? strlen(src) : 0);
}

void SprintfTruncV(char *dst, size_t dstSize, const char *fmt, va_list ap)
{
	if( dst == NULL || dstSize == 0 )
		return;

	vsnprintf(dst, dstSize, fmt, ap);
	dst[dstSize - 1] = '\0';
}

void SprintfTrunc(char *dst, size_t dstSize, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	SprintfTruncV(dst, dstSize, fmt, ap);
	va_end(ap);
}

// Mem

void FormatSize(char *dst, size_t dstSize, __int64 bytes)
{
	const __int64 KB = 1024ul;
	const __int64 MB = 1024ul * 1024ul;
	const __int64 GB = 1024ul * 1024ul * 1024ul;

	if( dst == NULL || dstSize == 0 )
		return;

	if( bytes < 10240ul )
		SprintfTrunc(dst, dstSize, "%lu B", (unsigned long)bytes);
	else if( bytes < MB )
		SprintfTrunc(dst, dstSize, "%lu KB", (unsigned long)(bytes / KB));
	else if( bytes < GB )
	{
		unsigned long whole = (unsigned long)(bytes / MB);
		__int64 rem = bytes % MB;
		unsigned long frac = (unsigned long)((rem * 100 + (MB / 2)) / MB);

		if( frac >= 100 )
		{
			whole++;
			frac = 0;
		}
		SprintfTrunc(dst, dstSize, "%lu.%02lu MB", whole, frac);
	}
	else
	{
		unsigned long whole = (unsigned long)(bytes / GB);
		__int64 rem = bytes % GB;
		unsigned long frac = (unsigned long)((rem * 1000 + (GB / 2)) / GB);

		if( frac >= 1000 )
		{
			whole++;
			frac = 0;
		}
		SprintfTrunc(dst, dstSize, "%lu.%03lu GB", whole, frac);
	}
}

void ProbeFreeMem(char *buf, size_t bufSize)
{
	buf[0] = '\0';

	void **ptr = (void **)malloc(1024 * sizeof(void *));
	if( ptr == NULL )
		return;

	int num;
	for( num = 0; num < 1024; num++ )
	{
		ptr[num] = malloc(1024);
		if( ptr[num] == NULL )
			break;
	}

	long count = num;

	while( --num >= 0 )
		free(ptr[num]);

	free(ptr);

	long bytes = count * 1024L + 1024L * sizeof(void *);
	size_t stack = stackavail();

	char sizebuf[32];
	FormatSize(sizebuf, sizeof(sizebuf), bytes);

	SprintfTrunc(buf, bufSize, "Heap=%s, Stack=%d B", sizebuf, stack);
}
