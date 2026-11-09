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

/* SSH key trace is enabled by -debug ONLY; contains live session secrets.
 * Never log password, keyboard-interactive reply or PTY data buffers.
 */

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include "DEBUG.H"
#include "GLOBALS.H"
#include "UTIL.H"

static FILE *s_debugStream = NULL;

void InitDebug()
{
	if( !s_debugArg )
		return;

	s_debugStream = fopen("DOSSSH.LOG", "wt");
	if( s_debugStream == NULL )
	{
		Log('E', "Cannot open DOSSSH.LOG; continuing without -debug trace.");
		return;
	}

	printf("WARNING: DOSSSH.LOG contains secret session keys.\n");
	printf("Do not publish this file.\n");
	fflush(stdout);
}

bool DebugEnabled()
{
	return s_debugStream != NULL;
}

void StopDebug()
{
	if( DebugEnabled() )
	{
		fclose(s_debugStream);
		s_debugStream = NULL;
	}
}

// INT 1Ch is chained by mTCP. Keep its screen writer independent of the
// network and of stack-allocated LongOp objects. No DOS/BIOS/CRT calls in ISR.
static LongOp *s_currentOp = NULL;
static bool s_statusVisible = false;

static volatile unsigned long s_timerTicks = 0;
static volatile unsigned long s_timerOpStart = 0;
static volatile unsigned long s_timerShownSecond = 0;

static volatile unsigned char s_timerDrawEnabled = 0;
static unsigned int s_timerVideoSegment = 0;
static unsigned int s_timerFieldOffset = 0;
static bool s_timerHooked = false;
static void (__interrupt __far *s_oldTimer1c)() = NULL;

static void __interrupt __far LongOpTimer1c()
{
	s_timerTicks++;
	if( s_timerDrawEnabled && !g_screen.IsCaptured() )
	{
		unsigned long seconds = (s_timerTicks - s_timerOpStart) / TIMER_TICKS_PER_SEC;
		if( seconds > 9999ul )
			seconds = 9999ul;
		if( seconds != 0 && seconds != s_timerShownSecond )
		{
			s_timerShownSecond = seconds;

			volatile unsigned char far *field = (volatile unsigned char far *)MK_FP(s_timerVideoSegment, s_timerFieldOffset);
			unsigned char reversed[4];
			int count = 0;
			do
			{
				reversed[count++] = (unsigned char)('0' + seconds % 10ul);
				seconds /= 10ul;
			} while( seconds != 0 );
			field[0] = ' ';
			for( int i = 0; i < count; i++ )
				field[2 + 2*i] = reversed[count - 1 - i];
			field[2 + 2*count] = 's';
		}
	}
	_chain_intr(s_oldTimer1c);
}

// A 32-bit value must be read atomically on a 16-bit processor.
static unsigned long LongOpTicks()
{
	disable_ints();
	unsigned long ticks = s_timerTicks;
	enable_ints();
	return ticks;
}

void LongOp::StartTimer()
{
	if( s_timerHooked )
		return;

	disable_ints();
	s_oldTimer1c = getvect(0x1C);
	setvect(0x1C, LongOpTimer1c);
	s_timerHooked = true;
	enable_ints();
}

void LongOp::StopTimer()
{
	s_timerDrawEnabled = 0;
	if( !s_timerHooked )
		return;

	disable_ints();
	setvect(0x1C, s_oldTimer1c);
	s_timerHooked = false;
	enable_ints();
}

static void LogEndStatus()
{
	s_timerDrawEnabled = 0;
	if( s_statusVisible )
	{
		s_statusVisible = false;
		if( !g_screen.IsCaptured() )
		{
			putchar('\n');
			fflush(stdout);
		}
	}
}

LongOp::LongOp(const char *name)
{
	LogEndStatus();
	_name = name;
	_previous = s_currentOp;
	_started = LongOpTicks();
	s_currentOp = this;
	Show();
}

LongOp::~LongOp()
{
	unsigned long ticks = LongOpTicks() - _started;

	LogEndStatus();
	s_currentOp = _previous;
	Log('S', "%s %lu.%lus", _name, ticks / TIMER_TICKS_PER_SEC, (ticks % TIMER_TICKS_PER_SEC) * 10ul / TIMER_TICKS_PER_SEC);
	if( s_currentOp != NULL )
		Show();
}

void LongOp::Show()
{
	if( g_screen.IsCaptured() )
		return;

	printf("%.48s", s_currentOp->_name);
	fflush(stdout);
	s_statusVisible = true;

	volatile unsigned char far *bios = (volatile unsigned char far *)MK_FP(0x40, 0);
	unsigned int cols = (unsigned int)bios[0x4A] | ((unsigned int)bios[0x4B] << 8);
	unsigned int col = bios[0x50];
	unsigned int row = bios[0x51];
	unsigned int mode = bios[0x49];
	if( s_timerHooked && bios[0x62] == 0 &&
		(mode == 2 || mode == 3 || mode == 7) &&
		cols >= 80 && cols <= 132 && row < 50 &&
		col + 6u <= cols )
	{
		s_timerVideoSegment = mode == 7 ? 0xB000 : 0xB800;
		s_timerFieldOffset = 2u*(cols*row + col);
		s_timerOpStart = s_currentOp->_started;
		s_timerShownSecond = 0;
		s_timerDrawEnabled = 1;
	}
}

static void LogWriteFile(char type, const char *line)
{
	if( !DebugEnabled() || line[0] == '\0' )
		return;

	time_t now = time(NULL);
	struct tm *local_time = localtime(&now);
	if( local_time != NULL )
	{
		fprintf(s_debugStream, "%04d-%02d-%02d %02d:%02d:%02d %c %s\n",
			local_time->tm_year + 1900, local_time->tm_mon + 1,
			local_time->tm_mday, local_time->tm_hour, local_time->tm_min,
			local_time->tm_sec, type, line);
	}
	else
		fprintf(s_debugStream, "??? %c %s\n", type, line);

	fflush(s_debugStream);
}

void Log(char type, const char *format, ...)
{
	if( !DebugEnabled() && (type != 'E' || g_screen.IsCaptured()) )
		return;

	char line[224];
	va_list ap;
	va_start(ap, format);
	SprintfTruncV(line, sizeof(line), format, ap);
	va_end(ap);
	if( line[0] == '\0' )
		return;

	LogWriteFile(type, line);
	if( type == 'E' && !g_screen.IsCaptured() )
	{
		LogEndStatus();
		printf("%s\n", line);
	}
}

void DebugHex(const char *name, const unsigned char *bytes, size_t length)
{
	if( !DebugEnabled() )
		return;

	static const char digits[] = "0123456789abcdef";
	char hex[129];
	for( size_t i = 0; i < length; i++ )
	{
		hex[2*i] = digits[bytes[i] >> 4];
		hex[2*i + 1] = digits[bytes[i] & 15];
	}
	hex[2*length] = '\0';
	Log('K', "key %s=%s", name, hex);
}

void DebugPacket(const char *direction, int type, size_t length, unsigned long sequence)
{
	if( !DebugEnabled() )
		return;

	if( type == 94 || type == 95 ) // Never trace interactive traffic
		return;

	if( type == 50 || type == 61 )
		Log('P', "%s type=%d seq=%lu (redacted)", direction, type, sequence);
	else
		Log('P', "%s type=%d len=%lu seq=%lu", direction, type, (unsigned long)length, sequence);
}
