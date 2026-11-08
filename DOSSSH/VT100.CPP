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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "VT100.H"
#include "ENCODING.H"
#include "UTIL.H"
#include "INPUT.H"

static const char g_ansiToEga[8] = { 0, 4, 2, 6, 1, 5, 3, 7 };

uint16_t VtCell::ScreenChar(bool bw) const
{
	if( bw )
	{
		uint16_t attr = 0x07;
		if( flags & VT_REVERSE )
			attr = 0x70;
		else if( flags & VT_UNDERLINE )
			attr = 0x01;
		else if( (fg & 8) || (flags & VT_BOLD) )
			attr = 0x0F;
		return (attr << 8) | ch;
	}

	unsigned char fg2 = fg & 15;
	unsigned char bg2 = bg & 7;
	uint16_t val = flags & VT_REVERSE ? ((fg2 & 7) << 4) | bg2 : (bg2 << 4) | fg2;
	return (val << 8) | ch;
}

Vt100::Vt100()
{
	_cells = NULL;
	_normalCells = NULL;
	_cols = 0;
	_rows = 0;
	ResetState();
}

Vt100::~Vt100()
{
	free(_cells);
	free(_normalCells);
}

bool Vt100::Init(int cols, int rows)
{
	if( cols < 80 || cols > 132 || rows < 25 || rows > 50 )
		return false;

	size_t bytes = (size_t)cols * rows * sizeof(VtCell);
	VtCell *buffer = (VtCell *)malloc(bytes);
	if( buffer == NULL )
		return false;

	free(_cells);
	free(_normalCells);
	_normalCells = NULL;
	_cells = buffer;
	_cols = cols;
	_rows = rows;
	memset(_dirtyFirst, 255, sizeof(_dirtyFirst));
	memset(_dirtyLast, 0, sizeof(_dirtyLast));

	Reset();
	return true;
}

void Vt100::ResetState()
{
	memset(&_screenState, 0, sizeof(_screenState));
	_screenState.scrollBottom = _rows ? _rows - 1 : 0;
	_screenState.fg = 7;
	_screenState.savedFg = 7;
	_screenState.cursorVisible = true;
	_screenState.wrap = true;
	_screenFailed = false;
	_state = 0;
	_private = 0;
	_paramIndex = 0;
	_utf8.Reset();
	_replyLength = 0;
	_mouseMode = 0;
	_mouseSgr = false;
}

void Vt100::Reset()
{
	if( _normalCells != NULL )
	{
		free(_cells);
		_cells = _normalCells;
		_normalCells = NULL;
	}

	ResetState();
	if( _cells == NULL )
		return;

	for( int y = 0; y < _rows; y++ )
		ClearRow(y, 0, _cols - 1);
	MarkAllDirty();
}

const VtCell *Vt100::Row(int y) const
{
	if( _cells == NULL || y < 0 || y >= _rows )
		return NULL;
	return &_cells[_cols*y];
}

bool Vt100::TakeDirtyRow(int y, int &first, int &last)
{
	if( y < 0 || y >= _rows || _dirtyFirst[y] == 255 )
		return false;

	first = _dirtyFirst[y];
	last = _dirtyLast[y];
	_dirtyFirst[y] = 255;
	_dirtyLast[y] = 0;

	return true;
}

void Vt100::MarkDirty(int y, int first, int last)
{
	if( first < _dirtyFirst[y] )
		_dirtyFirst[y] = (unsigned char)first;
	if( last > _dirtyLast[y] )
		_dirtyLast[y] = (unsigned char)last;
}

void Vt100::MarkAllDirty()
{
	for( int y = 0; y < _rows; y++ )
	{
		_dirtyFirst[y] = 0;
		_dirtyLast[y] = (unsigned char)(_cols - 1);
	}
}

void Vt100::SetCell(int x, int y, unsigned char ch)
{
	VtCell *cell = &_cells[_cols*y + x];
	cell->ch = ch;
	cell->fg = _screenState.fg;
	cell->bg = _screenState.bg;
	cell->flags = _screenState.flags;
	MarkDirty(y, x, x);
}

void Vt100::ClearRow(int y, int first, int last)
{
	VtCell *cell = &_cells[_cols*y + first];
	for( int x = first; x <= last; x++, cell++ )
	{
		cell->ch = ' ';
		cell->fg = _screenState.fg;
		cell->bg = _screenState.bg;
		cell->flags = _screenState.flags;
	}
	MarkDirty(y, first, last);
}

void Vt100::ScrollUp(int first, int last, int lines)
{
	if( lines > last - first + 1 )
		lines = last - first + 1;

	int y = first;
	for( ; y + lines <= last; y++ )
	{
		memmove(_cells + _cols*y, _cells + _cols*(y + lines), _cols * sizeof(VtCell));
		MarkDirty(y, 0, _cols - 1);
	}
	for( ; y <= last; y++ )
		ClearRow(y, 0, _cols - 1);
}

void Vt100::ScrollDown(int first, int last, int lines)
{
	if( lines > last - first + 1 )
		lines = last - first + 1;

	for( int y = last; y >= first + lines; y-- )
	{
		memmove(_cells + _cols*y, _cells + _cols*(y - lines), _cols * sizeof(VtCell));
		MarkDirty(y, 0, _cols - 1);
	}
	for( int y = first; y < first + lines; y++ )
		ClearRow(y, 0, _cols - 1);
}

void Vt100::LineFeed()
{
	_screenState.pendingWrap = false;
	if( _screenState.y == _screenState.scrollBottom )
		ScrollUp(_screenState.scrollTop, _screenState.scrollBottom, 1);
	else if( _screenState.y < _rows - 1 )
		_screenState.y++;
}

void Vt100::ReverseIndex()
{
	_screenState.pendingWrap = false;
	if( _screenState.y == _screenState.scrollTop )
		ScrollDown(_screenState.scrollTop, _screenState.scrollBottom, 1);
	else if( _screenState.y > 0 )
		_screenState.y--;
}

unsigned char Vt100::GraphicsChar(unsigned char ch)
{
	switch( ch )
	{
	case 'q': return 196;
	case 'x': return 179;
	case 'l': return 218;
	case 'k': return 191;
	case 'm': return 192;
	case 'j': return 217;
	case 't': return 195;
	case 'u': return 180;
	case 'v': return 193;
	case 'w': return 194;
	case 'n': return 197;
	case 'a': return 177;
	default:  return ch;
	}
}

void Vt100::QueueReply(const char *reply)
{
	size_t size = strlen(reply);
	if( size > sizeof(_replies) - _replyLength )
		return;

	memcpy(_replies + _replyLength, reply, size);
	_replyLength += size;
}

size_t Vt100::ReadReply(unsigned char *out, size_t capacity)
{
	size_t count = _replyLength;
	if( count > capacity )
		count = capacity;

	if( count )
	{
		memcpy(out, _replies, count);
		_replyLength -= count;
		memmove(_replies, _replies + count, _replyLength);
	}
	return count;
}

void Vt100::AlternateScreen(bool enabled)
{
	if( enabled )
	{
		if( _normalCells != NULL )
			return;

		VtCell *buffer = (VtCell *)malloc((size_t)_cols * _rows * sizeof(VtCell));
		if( buffer == NULL )
		{
			_screenFailed = true;
			return;
		}

		_normalState = _screenState;
		_normalCells = _cells;
		_cells = buffer;
		memset(&_screenState, 0, sizeof(_screenState));
		_screenState.cursorApplication = _normalState.cursorApplication;
		_screenState.scrollBottom = _rows - 1;
		_screenState.fg = 7;
		_screenState.savedFg = 7;
		_screenState.wrap = true;
		for( int y = 0; y < _rows; y++ )
			ClearRow(y, 0, _cols - 1);
		MarkAllDirty();
	}
	else if( _normalCells != NULL )
	{
		free(_cells);
		_cells = _normalCells;
		_normalCells = NULL;
		_screenState = _normalState;
		MarkAllDirty();
	}
}

void Vt100::Put(unsigned char ch)
{
	if( _screenState.pendingWrap )
	{
		_screenState.pendingWrap = false;
		if( _screenState.wrap )
		{
			_screenState.x = 0;
			LineFeed();
		}
	}
	SetCell(_screenState.x, _screenState.y, _screenState.charset ? GraphicsChar(ch) : ch);
	if( _screenState.x >= _cols - 1 )
		_screenState.pendingWrap = _screenState.wrap;
	else
		_screenState.x++;
}

void Vt100::SaveCursor()
{
	_screenState.savedX = _screenState.x;
	_screenState.savedY = _screenState.y;
	_screenState.savedFg = _screenState.fg;
	_screenState.savedBg = _screenState.bg;
	_screenState.savedFlags = _screenState.flags;
	_screenState.savedCharset = _screenState.charset;
	_screenState.savedUseG1 = _screenState.useG1;
}

void Vt100::RestoreCursor()
{
	_screenState.x = _screenState.savedX;
	_screenState.y = _screenState.savedY;
	_screenState.fg = _screenState.savedFg;
	_screenState.bg = _screenState.savedBg;
	_screenState.flags = _screenState.savedFlags;
	_screenState.charset = _screenState.savedCharset;
	_screenState.useG1 = _screenState.savedUseG1;
	_screenState.pendingWrap = false;
}

int Vt100::Param(int idx, int fallback) const
{
	if( idx > _paramIndex || _params[idx] == 0 )
		return fallback;
	return _params[idx];
}

void Vt100::Sgr()
{
	for( int i = 0; i < ParamCount(); i++ )
	{
		int p = _params[i];
		if( p == 38 || p == 48 || p == 58 )
		{
			// Ignore unsupported extended colors
			if( i < ParamCount()-1 )
			{
				if( _params[i + 1] == 5 )
					i += 2;
				else if( _params[i + 1] == 2 )
					i += 4;
			}
			continue;
		}
		if( p == 0 )
		{
			_screenState.fg = 7;
			_screenState.bg = 0;
			_screenState.flags = 0;
		}
		else if( p == 1 )
		{
			_screenState.flags |= VT_BOLD;
			_screenState.fg |= 8;
		}
		else if( p == 4 )
			_screenState.flags |= VT_UNDERLINE;
		else if( p == 7 )
			_screenState.flags |= VT_REVERSE;
		else if( p == 22 )
		{
			_screenState.flags &= (unsigned char)~VT_BOLD;
			_screenState.fg &= 7;
		}
		else if( p == 24 )
			_screenState.flags &= (unsigned char)~VT_UNDERLINE;
		else if( p == 27 )
			_screenState.flags &= (unsigned char)~VT_REVERSE;
		else if( p >= 30 && p <= 37 )
			_screenState.fg = g_ansiToEga[p - 30] | ((_screenState.flags & VT_BOLD) ? 8 : 0);
		else if( p == 39 )
			_screenState.fg = (_screenState.flags & VT_BOLD) ? 15 : 7;
		else if( p >= 40 && p <= 47 )
			_screenState.bg = g_ansiToEga[p - 40];
		else if( p == 49 )
			_screenState.bg = 0;
		else if( p >= 90 && p <= 97 )
			_screenState.fg = g_ansiToEga[p - 90] + 8;
		else if( p >= 100 && p <= 107 )
			_screenState.bg = g_ansiToEga[p - 100]; // 8 EGA background colours, not bright
	}
}

void Vt100::Csi(char finalByte)
{
	if( _private )
	{
		if( _private == 2 )
		{
			if( finalByte == 'c' )
				QueueReply("\033[>0;0;0c");
			return;
		}
		if( finalByte == 'n' && _params[0] == 6u )
		{
			char response[24];
			SprintfTrunc(response, sizeof(response), "\033[?%d;%dR", _screenState.y + 1, _screenState.x + 1);
			QueueReply(response);
		}
		if( finalByte == 'h' || finalByte == 'l' )
		{
			bool enabled = (finalByte == 'h');
			for( int i = 0; i < ParamCount(); i++ )
			{
				if( _params[i] == 1 )
					_screenState.cursorApplication = enabled;
				if( _params[i] == 9 || _params[i] == 1000 || _params[i] == 1002 || _params[i] == 1003 )
				{
					if( enabled )
						_mouseMode = _params[i];
					else if( _mouseMode == (unsigned int)_params[i] )
						_mouseMode = 0;
				}
				if( _params[i] == 1006 )
					_mouseSgr = enabled;
				if( _params[i] == 47 || _params[i] == 1047 || _params[i] == 1049 )
					AlternateScreen(enabled);
				if( _params[i] == 1048 )
				{
					if( enabled )
						SaveCursor();
					else
						RestoreCursor();
				}
				if( _params[i] == 25 )
					_screenState.cursorVisible = enabled;
				if( _params[i] == 7 )
					_screenState.wrap = enabled;
				if( _params[i] == 6 )
				{
					_screenState.origin = enabled;
					_screenState.x = 0;
					_screenState.y = _screenState.origin ? _screenState.scrollTop : 0;
				}
			}
		}
		_screenState.pendingWrap = false;
		return;
	}

	int n = Param(0, 1);
	switch( finalByte )
	{
	case 'c': // Primary device attributes, VT100 with AVO.
		QueueReply("\033[?1;2c");
		break;
	case 'n': // Device status and cursor position queries.
		if( _params[0] == 5u )
			QueueReply("\033[0n");
		if( _params[0] == 6u )
		{
			char response[24];
			SprintfTrunc(response, sizeof(response), "\033[%d;%dR", _screenState.y + 1, _screenState.x + 1);
			QueueReply(response);
		}
		break;
	case 'A':
	{
		int top = _screenState.origin ? _screenState.scrollTop : 0;
		_screenState.y = n > _screenState.y - top ? top : _screenState.y - n;
		break;
	}
	case 'B':
	{
		int bottom = _screenState.origin ? _screenState.scrollBottom : _rows - 1;
		_screenState.y = n >= bottom - _screenState.y ? bottom : _screenState.y + n;
		break;
	}
	case 'C':
		_screenState.x = n >= _cols - _screenState.x ? _cols - 1 : _screenState.x + n;
		break;
	case 'D':
		_screenState.x = n > _screenState.x ? 0 : _screenState.x - n;
		break;
	case 'E':
		_screenState.y = n >= (_screenState.origin ? _screenState.scrollBottom : _rows - 1) - _screenState.y ?
			(_screenState.origin ? _screenState.scrollBottom : _rows - 1) : _screenState.y + n;
		_screenState.x = 0;
		break;
	case 'F':
		_screenState.y = n > _screenState.y - (_screenState.origin ? _screenState.scrollTop : 0) ? (_screenState.origin ? _screenState.scrollTop : 0) : _screenState.y - n;
		_screenState.x = 0;
		break;
	case 'G':
	case '`':
	{
		int x = n - 1;
		_screenState.x = x < _cols ? x : _cols - 1;
		break;
	}
	case 'd':
	{
		int y = n - 1;
		if( _screenState.origin )
			y += _screenState.scrollTop;
		_screenState.y = y <= (_screenState.origin ? _screenState.scrollBottom : _rows - 1) ? y : (_screenState.origin ? _screenState.scrollBottom : _rows - 1);
		break;
	}
	case 'f':
	case 'H':
	{
		int y = n - 1;
		if( _screenState.origin )
			y += _screenState.scrollTop;
		int x = Param(1, 1) - 1;
		_screenState.y = y <= (_screenState.origin ? _screenState.scrollBottom : _rows - 1) ? y : (_screenState.origin ? _screenState.scrollBottom : _rows - 1);
		_screenState.x = x < _cols ? x : _cols - 1;
		break;
	}
	case 'J':
		if( _params[0] == 2 )
		{
			for( int y = 0; y < _rows; y++ )
				ClearRow(y, 0, _cols - 1);
		}
		else if( _params[0] == 0 )
		{
			ClearRow(_screenState.y, _screenState.x, _cols - 1);
			for( int y = _screenState.y + 1; y < _rows; y++ )
				ClearRow(y, 0, _cols - 1);
		}
		else if( _params[0] == 1 )
		{
			for( int y = 0; y < _screenState.y; y++ )
				ClearRow(y, 0, _cols - 1);
			ClearRow(_screenState.y, 0, _screenState.x);
		}
		break;
	case 'K':
		if( _params[0] == 0 )
			ClearRow(_screenState.y, _screenState.x, _cols - 1);
		if( _params[0] == 1 )
			ClearRow(_screenState.y, 0, _screenState.x);
		if( _params[0] == 2 )
			ClearRow(_screenState.y, 0, _cols - 1);
		break;
	case 'X':
	{
		int x = _screenState.x + n - 1;
		ClearRow(_screenState.y, _screenState.x, x < _cols ? x : _cols - 1);
		break;
	}
	case '@':
		if( n > _cols - _screenState.x )
			n = _cols - _screenState.x;
		for( int x = _cols - 1; x >= (_screenState.x + n); x-- )
			_cells[_cols*_screenState.y + x] = _cells[_cols*_screenState.y + x - n];
		for( int x = _screenState.x; x < (_screenState.x + n); x++ )
			SetCell(x, _screenState.y, ' ');
		MarkDirty(_screenState.y, _screenState.x, _cols - 1);
		break;
	case 'P':
		if( n > _cols - _screenState.x )
			n = _cols - _screenState.x;
		for( int x = _screenState.x; x + n < _cols; x++ )
			_cells[_cols*_screenState.y + x] = _cells[_cols*_screenState.y + x + n];
		ClearRow(_screenState.y, _cols - n, _cols - 1);
		MarkDirty(_screenState.y, _screenState.x, _cols - 1);
		break;
	case 'L':
		if( _screenState.y >= _screenState.scrollTop && _screenState.y <= _screenState.scrollBottom )
			ScrollDown(_screenState.y, _screenState.scrollBottom, n);
		break;
	case 'M':
		if( _screenState.y >= _screenState.scrollTop && _screenState.y <= _screenState.scrollBottom )
			ScrollUp(_screenState.y, _screenState.scrollBottom, n);
		break;
	case 'S':
		ScrollUp(_screenState.scrollTop, _screenState.scrollBottom, n);
		break;
	case 'T':
		ScrollDown(_screenState.scrollTop, _screenState.scrollBottom, n);
		break;
	case 'r':
	{
		int x = Param(0, 1);
		int y = Param(1, _rows);
		if( x < y && y <= _rows )
		{
			_screenState.scrollTop = x - 1;
			_screenState.scrollBottom = y - 1;
			_screenState.x = 0;
			_screenState.y = _screenState.origin ? _screenState.scrollTop : 0;
		}
		break;
	}
	case 's':
		SaveCursor();
		break;
	case 'u':
		RestoreCursor();
		break;
	case 'm':
		Sgr();
		break;
	}
	_screenState.pendingWrap = false;
}

void Vt100::Feed(const unsigned char *bytes, size_t size)
{
	if( bytes == NULL || _cells == NULL )
		return;

	for( size_t i = 0; i < size; i++ )
	{
		unsigned char ch = bytes[i];
		if( _state == 0 && _utf8.Pending() )
		{
			long unicode = _utf8.Continue(ch);
			if( unicode >= 0 )
			{
				if( unicode >= 0x300 && unicode <= 0x36F )
				{
					// Combining marks have no separate DOS cell.
				}
				else
					Put(DosUnicodeOem((unsigned long)unicode));
			}
			else if( unicode == DosUtf8Decoder::Invalid || unicode == DosUtf8Decoder::Interrupted )
				Put('?');
			if( unicode != DosUtf8Decoder::Interrupted )
				continue;
		}
		if( _state == 4 ) // OSC payload is ignored.
		{
			if( ch == 7 )
				_state = 0;
			else if( ch == 27 )
				_state = 5;
			continue;
		}
		if( _state == 5 )
		{
			_state = ch == '\\' ? 0 : 4;
			continue;
		}
		if( ch == 27 )
		{
			_state = 1;
			continue;
		}
		if( _state == 3 || _state == 7 )
		{
			if( _state == 3 )
				_screenState.g0 = ch == '0' ? 1 : 0;
			else
				_screenState.g1 = ch == '0' ? 1 : 0;
			_screenState.charset = _screenState.useG1 ? _screenState.g1 : _screenState.g0;
			_state = 0;
			continue;
		}
		if( _state == 1 )
		{
			_state = 0;
			if( ch == '[' )
			{
				_state = 2;
				_paramIndex = 0;
				_private = 0;
				memset(_params, 0, sizeof(_params));
			}
			else if( ch == '(' )
				_state = 3;
			else if( ch == ')' )
				_state = 7;
			else if( ch == ']' )
				_state = 4;
			else if( ch == 'Z' )
				QueueReply("\033[?1;2c");
			else if( ch == '7' )
				SaveCursor();
			else if( ch == '8' )
				RestoreCursor();
			else if( ch == 'D' )
				LineFeed();
			else if( ch == 'M' )
				ReverseIndex();
			else if( ch == 'E' )
			{
				_screenState.x = 0;
				LineFeed();
			}
			else if( ch == 'c' )
				Reset();
			continue;
		}
		if( _state == 2 )
		{
			if( (ch == '?' || ch == '>') && _paramIndex == 0 && !_params[0] )
				_private = ch == '?' ? 1 : 2;
			else if( ch >= '0' && ch <= '9' )
			{
				if( _params[_paramIndex] <= 999 )
					_params[_paramIndex] = _params[_paramIndex] * 10 + (ch - '0');
			}
			else if( ch == ';' )
			{
				if( _paramIndex < (int)(sizeof(_params) / sizeof(_params[0])) - 1 )
					_paramIndex++;
				else
					_state = 6; // Too many CSI parameters: discard until final byte.
			}
			else if( ch == ':' )
				_state = 6; // Unsupported colon-delimited CSI parameters.
			else if( ch >= 0x40 && ch <= 0x7E )
			{
				Csi(ch);
				_state = 0;
			}
			else if( ch < 0x20 )
				_state = 0;
			continue;
		}
		if( _state == 6 )
		{
			if( ch >= 0x40 && ch <= 0x7E )
				_state = 0;
			continue;
		}
		if( ch == '\r' )
		{
			_screenState.x = 0;
			_screenState.pendingWrap = false;
		}
		else if( ch == '\n' || ch == '\v' || ch == '\f' )
			LineFeed();
		else if( ch == '\b' )
		{
			if( _screenState.x > 0 )
				_screenState.x--;
			_screenState.pendingWrap = false;
		}
		else if( ch == 14 ) // SO: select G1 graphics charset.
		{
			_screenState.useG1 = true;
			_screenState.charset = _screenState.g1;
		}
		else if( ch == 15 ) // SI: return to G0 charset.
		{
			_screenState.useG1 = false;
			_screenState.charset = _screenState.g0;
		}
		else if( ch == '\t' )
		{
			int next = (_screenState.x + 8) & ~7;
			_screenState.x = next >= _cols ? _cols - 1 : next;
			_screenState.pendingWrap = false;
		}
		else if( ch >= 0x80 )
		{
			if( !_utf8.Start(ch) )
				Put('?');
		}
		else if( ch >= 32 && ch != 127 )
			Put(ch);
	}
}

static size_t CopyKeySequence(const char *sequence, unsigned char *out, size_t capacity)
{
	size_t length = strlen(sequence);
	if( length > capacity )
		return 0;
	memcpy(out, sequence, length);
	return length;
}

size_t Vt100::MouseToVt(const DosMouseEvent &event, unsigned int modifiers, unsigned char *out, size_t capacity) const
{
	if( !_mouseMode || event.x >= (unsigned int)_cols || event.y >= (unsigned int)_rows )
		return 0;

	unsigned int button_code = event.type == DOS_MOUSE_MOVE ? 35u : event.button;
	bool released = event.type == DOS_MOUSE_RELEASE;
	if( event.type == DOS_MOUSE_MOVE )
	{
		if( _mouseMode != 1003u && (_mouseMode != 1002u || !event.buttons) )
			return 0;
		if( event.buttons & 1u )
			button_code = 32u;
		else if( event.buttons & 4u )
			button_code = 33u;
		else if( event.buttons & 2u )
			button_code = 34u;
	}
	if( _mouseMode == 9 && released )
		return 0;

	unsigned int modifiers_code = ((modifiers & VT_KEY_SHIFT) ? 4u : 0u) +
		((modifiers & VT_KEY_ALT) ? 8u : 0u) + ((modifiers & VT_KEY_CTRL) ? 16u : 0u);
	unsigned int code = button_code + modifiers_code;
	if( _mouseSgr )
	{
		char sequence[32];
		SprintfTrunc(sequence, sizeof(sequence), "\033[<%u;%u;%u%c", code, event.x + 1u, event.y + 1u, released ? 'm' : 'M');
		return CopyKeySequence(sequence, out, capacity);
	}
	if( capacity < 6 )
		return 0;

	out[0] = 27;
	out[1] = '[';
	out[2] = 'M';
	out[3] = (unsigned char)(32u + (released ? 3u : button_code) + modifiers_code);
	out[4] = (unsigned char)(33u + event.x);
	out[5] = (unsigned char)(33u + event.y);
	return 6;
}

static unsigned int KeyModifierParameter(unsigned int modifiers)
{
	return 1u + ((modifiers & VT_KEY_SHIFT) ? 1u : 0u) +
		((modifiers & VT_KEY_ALT) ? 2u : 0u) +
		((modifiers & VT_KEY_CTRL) ? 4u : 0u);
}

static int FunctionKeyNumber(int scan, unsigned int &modifiers)
{
	// F1-F10: unmodified, Shift, Ctrl and Alt use consecutive blocks.
	if( scan >= 0x3B && scan <= 0x44 )
		return scan - 0x3B + 1;
	if( scan >= 0x54 && scan <= 0x5D )
	{
		modifiers |= VT_KEY_SHIFT;
		return scan - 0x54 + 1;
	}
	if( scan >= 0x5E && scan <= 0x67 )
	{
		modifiers |= VT_KEY_CTRL;
		return scan - 0x5E + 1;
	}
	if( scan >= 0x68 && scan <= 0x71 )
	{
		modifiers |= VT_KEY_ALT;
		return scan - 0x68 + 1;
	}

	// F11/F12 use individual scan-code pairs on enhanced keyboards.
	if( scan >= 0x85 && scan <= 0x8C )
	{
		if( scan >= 0x87 && scan <= 0x88 )
			modifiers |= VT_KEY_SHIFT;
		if( scan >= 0x89 && scan <= 0x8A )
			modifiers |= VT_KEY_CTRL;
		if( scan >= 0x8B )
			modifiers |= VT_KEY_ALT;
		return 11 + ((scan - 0x85) & 1);
	}
	return 0;
}

static size_t FunctionKeySequence(int functionKey, unsigned int modifiers, unsigned char *out, size_t capacity)
{
	static const unsigned char tilde[12] = { 0, 0, 0, 0, 15, 17, 18, 19, 20, 21, 23, 24 };
	unsigned int parameter = KeyModifierParameter(modifiers);
	char sequence[24];

	if( functionKey <= 4 )
	{
		if( parameter == 1u )
			SprintfTrunc(sequence, sizeof(sequence), "\033O%c", 'P' + functionKey - 1);
		else
			SprintfTrunc(sequence, sizeof(sequence), "\033[1;%u%c", parameter, 'P' + functionKey - 1);
	}
	else if( parameter == 1u )
		SprintfTrunc(sequence, sizeof(sequence), "\033[%u~", (unsigned int)tilde[functionKey - 1]);
	else
		SprintfTrunc(sequence, sizeof(sequence), "\033[%u;%u~", (unsigned int)tilde[functionKey - 1], parameter);

	return CopyKeySequence(sequence, out, capacity);
}

static bool NavigationKey(int scan, char &cursor, int &tilde, unsigned int &modifiers)
{
	cursor = 0;
	tilde = 0;
	switch( scan )
	{
	case 0x48: cursor = 'A'; break; // Up
	case 0x50: cursor = 'B'; break; // Down
	case 0x4D: cursor = 'C'; break; // Right
	case 0x4B: cursor = 'D'; break; // Left
	case 0x47: cursor = 'H'; break; // Home
	case 0x4F: cursor = 'F'; break; // End
	case 0x52: tilde = 2; break; // Insert
	case 0x53: tilde = 3; break; // Delete
	case 0x49: tilde = 5; break; // PageUp
	case 0x51: tilde = 6; break; // PageDown

	case 0x8D: cursor = 'A'; modifiers |= VT_KEY_CTRL; break;
	case 0x91: cursor = 'B'; modifiers |= VT_KEY_CTRL; break;
	case 0x73: cursor = 'D'; modifiers |= VT_KEY_CTRL; break;
	case 0x74: cursor = 'C'; modifiers |= VT_KEY_CTRL; break;
	case 0x77: cursor = 'H'; modifiers |= VT_KEY_CTRL; break;
	case 0x75: cursor = 'F'; modifiers |= VT_KEY_CTRL; break;
	case 0x84: tilde = 5; modifiers |= VT_KEY_CTRL; break;
	case 0x76: tilde = 6; modifiers |= VT_KEY_CTRL; break;
	case 0x92: tilde = 2; modifiers |= VT_KEY_CTRL; break;
	case 0x93: tilde = 3; modifiers |= VT_KEY_CTRL; break;

	case 0x98: cursor = 'A'; modifiers |= VT_KEY_ALT; break;
	case 0xA0: cursor = 'B'; modifiers |= VT_KEY_ALT; break;
	case 0x9D: cursor = 'C'; modifiers |= VT_KEY_ALT; break;
	case 0x9B: cursor = 'D'; modifiers |= VT_KEY_ALT; break;
	case 0x97: cursor = 'H'; modifiers |= VT_KEY_ALT; break;
	case 0x9F: cursor = 'F'; modifiers |= VT_KEY_ALT; break;
	case 0x99: tilde = 5; modifiers |= VT_KEY_ALT; break;
	case 0xA1: tilde = 6; modifiers |= VT_KEY_ALT; break;
	case 0xA2: tilde = 2; modifiers |= VT_KEY_ALT; break;
	case 0xA3: tilde = 3; modifiers |= VT_KEY_ALT; break;
	}
	return cursor != 0 || tilde != 0;
}

static size_t NavigationKeySequence(char cursor, int tilde, unsigned int modifiers, bool applicationCursor, unsigned char *out, size_t capacity)
{
	unsigned int parameter = KeyModifierParameter(modifiers);
	char sequence[24];

	if( cursor )
	{
		if( parameter > 1u )
			SprintfTrunc(sequence, sizeof(sequence), "\033[1;%u%c", parameter, cursor);
		else
			SprintfTrunc(sequence, sizeof(sequence), "\033%c%c", applicationCursor ? 'O' : '[', cursor);
	}
	else if( parameter > 1u )
		SprintfTrunc(sequence, sizeof(sequence), "\033[%d;%u~", tilde, parameter);
	else
		SprintfTrunc(sequence, sizeof(sequence), "\033[%d~", tilde);
	return CopyKeySequence(sequence, out, capacity);
}

static char AltScanAscii(int scan)
{
	// Alt+key codes identify US-PC physical key positions, not a DOS layout.
	if( scan >= 0x10 && scan <= 0x19 )
		return "qwertyuiop"[scan - 0x10];
	if( scan >= 0x1E && scan <= 0x26 )
		return "asdfghjkl"[scan - 0x1E];
	if( scan >= 0x2C && scan <= 0x32 )
		return "zxcvbnm"[scan - 0x2C];
	if( scan >= 0x78 && scan <= 0x81 )
		return "1234567890"[scan - 0x78];

	switch( scan )
	{
	case 0x01: return 27;  // Alt+Esc
	case 0x0E: return 127; // Alt+Backspace (Meta-Backspace)
	case 0x1A: return '[';
	case 0x1B: return ']';
	case 0x27: return ';';
	case 0x28: return '\'';
	case 0x29: return '`';
	case 0x2B: return '\\';
	case 0x33: return ',';
	case 0x34: return '.';
	case 0x35: return '/';
	case 0x82: return '-';
	case 0x83: return '=';
	}
	return 0;
}

size_t Vt100::KeyToVt(unsigned int biosKey, unsigned int modifiers, unsigned char *out, size_t capacity)
{
	int scan = (biosKey >> 8) & 255;
	int ascii = biosKey & 255;
	if( ascii == 0 || ascii == 0xE0 )
	{
		unsigned int key_mod = modifiers & (VT_KEY_SHIFT | VT_KEY_ALT | VT_KEY_CTRL);
		int key_func = FunctionKeyNumber(scan, key_mod);
		if( key_func )
			return FunctionKeySequence(key_func, key_mod, out, capacity);

		char cursor;
		int tilde;
		if( NavigationKey(scan, cursor, tilde, key_mod) )
			return NavigationKeySequence(cursor, tilde, key_mod, _screenState.cursorApplication, out, capacity);

		if( scan == 0x0F ) // Shift+Tab
			return CopyKeySequence("\033[Z", out, capacity);

		// Do not infer Alt from printable ASCII: AltGr and Alt+numpad must
		// remain ordinary characters. BIOS Alt scans have zero ASCII.
		char meta = ascii == 0 ? AltScanAscii(scan) : 0;
		if( meta )
		{
			if( (key_mod & VT_KEY_SHIFT) && meta >= 'a' && meta <= 'z' )
				meta = (char)(meta - 'a' + 'A');
			if( capacity < 2 )
				return 0;
			out[0] = 27;
			out[1] = (unsigned char)meta;
			return 2;
		}

		// Unknown extended keys must not leak as OEM characters.
		return 0;
	}

	if( capacity == 0 )
		return 0;

	if( ascii == 8 )
		ascii = 127; // VT100-compatible Backspace

	out[0] = (unsigned char)ascii;

	return 1;
}
