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

class UiScreen
{
public:
	UiScreen();
	~UiScreen();

	bool Init();
	void Capture();
	void Restore();

	bool IsCaptured() const { return _valid; }
	uint16_t Rows() const { return _screenRows; }
	uint16_t Cols() const { return _screenCols; }

	void Draw();

private:
	uint8_t far *_screen;
	uint16_t _screenRows;
	uint16_t _screenCols;
	bool _bw;

	size_t _savedScreenBytes;
	size_t _savedScreenCapacity;
	uint8_t _savedCursorStart;
	uint8_t _savedCursorEnd;
	uint8_t _savedCursorX;
	uint8_t _savedCursorY;
	uint8_t *_savedScreen;
	bool _valid;

	uint8_t _lastCursorX;
	uint8_t _lastCursorY;
	bool _cursorKnown;
	bool _lastCursorVisible;
};

UiScreen::UiScreen()
{
	_screen = NULL;
	_screenRows = 25;
	_screenCols = 80;
	_bw = false;

	_savedScreenBytes = 0;
	_savedScreenCapacity = 0;
	_savedCursorStart = 6;
	_savedCursorEnd = 7;
	_savedCursorX = 0;
	_savedCursorY = 0;
	_savedScreen = NULL;
	_valid = false;
	_lastCursorX = 0;
	_lastCursorY = 0;
	_cursorKnown = false;
	_lastCursorVisible = false;
}

UiScreen::~UiScreen()
{
	if( _savedScreen != NULL )
	{
		free(_savedScreen);
		_savedScreen = NULL;
	}
	_savedScreenBytes = 0;
	_savedScreenCapacity = 0;
	_valid = false;
}

bool UiScreen::Init()
{
	uint8_t mode = *((uint8_t far *)MK_FP(0x40, 0x49));
	uint8_t page = *((uint8_t far *)MK_FP(0x40, 0x62));
	if( (mode != 2 && mode != 3 && mode != 7) || page != 0 )
	{
		Log('E', "DOSSSH requires text mode 2, 3 or 7 on video page 0");
		return false;
	}

	_bw = mode == 7;
	if( _bw )
		_screen = (uint8_t far *)MK_FP(0xB000, 0);
	else
		_screen = (uint8_t far *)MK_FP(0xB800, 0);

	if( _bw || getEgaMemSize() == 0x10 )
	{
		_screenCols = 80;
		_screenRows = 25;
	}
	else
	{
		_screenCols = *((uint16_t far *)MK_FP(0x40, 0x4A));
		_screenRows = *((uint8_t far *)MK_FP(0x40, 0x84)) + 1;
	}

	if( _screenCols < 80 || _screenCols > 132 || _screenRows < 25 || _screenRows > 50 )
	{
		Log('E', "Unsupported text mode: %ux%u. Please use 80x25 to 132x50.", _screenCols, _screenRows);
		_screen = NULL;
		return false;
	}
	return true;
}

void UiScreen::Capture()
{
	if( !_screen )
		return;

	union REGS r;
	r.h.ah = 0x03;
	r.h.bh = 0x00;
	int86(0x10, &r, &r);

	_savedCursorStart = r.h.ch;
	_savedCursorEnd = r.h.cl;
	_savedCursorX = r.h.dl;
	_savedCursorY = r.h.dh;

	size_t bytes = (size_t)_screenRows * _screenCols * 2u;
	if( bytes > _savedScreenCapacity )
	{
		uint8_t *buf = (uint8_t *)realloc(_savedScreen, bytes);
		if( buf == NULL )
		{
			_valid = false;
			_savedScreenBytes = 0;
			return;
		}

		_savedScreen = buf;
		_savedScreenCapacity = bytes;
	}

	_savedScreenBytes = bytes;
	for( size_t i = 0; i < _savedScreenBytes; i++ )
		_savedScreen[i] = _screen[i];

	_valid = true;
	_cursorKnown = false;
}

void UiScreen::Restore()
{
	if( !_valid || !_screen || _savedScreen == NULL )
		return;

	for( size_t i = 0; i < _savedScreenBytes; i++ )
		_screen[i] = _savedScreen[i];

	union REGS r;
	r.h.ah = 0x01;
	r.h.ch = _savedCursorStart;
	r.h.cl = _savedCursorEnd;
	int86(0x10, &r, &r);

	r.h.ah = 0x02;
	r.h.bh = 0x00;
	r.h.dh = _savedCursorY;
	r.h.dl = _savedCursorX;
	int86(0x10, &r, &r);

	_valid = false;
	_cursorKnown = false;
}

void UiScreen::Draw()
{
	if( !_screen || !_valid || !g_terminal.Ok() || g_terminal.Cols() != _screenCols || g_terminal.Rows() != _screenRows )
		return;

	uint16_t far *video = (uint16_t far *)_screen;
	for( unsigned int y = 0; y < _screenRows; y++ )
	{
		int first;
		int last;
		if( !g_terminal.TakeDirtyRow(y, first, last) )
			continue;

		const VtCell *line = g_terminal.Row(y);
		int offset = _screenCols*y + first;
		for( int x = first; x <= last; x++, offset++ )
		{
			uint16_t sc = line[x].ScreenChar(_bw);
			if( video[offset] != sc )
				video[offset] = sc;
		}
	}

	bool visible = g_terminal.CursorVisible();
	uint8_t cx = g_terminal.CursorX();
	uint8_t cy = g_terminal.CursorY();

	if( !_cursorKnown || _lastCursorVisible != visible )
	{
		union REGS r;
		memset(&r, 0, sizeof(r));
		r.h.ah = 0x01;
		r.h.ch = visible ? _savedCursorStart : 0x20;
		r.h.cl = _savedCursorEnd;
		int86(0x10, &r, &r);
	}
	if( !_cursorKnown || _lastCursorX != cx || _lastCursorY != cy )
	{
		union REGS r;
		r.h.ah = 0x02;
		r.h.bh = 0;
		r.h.dh = cy;
		r.h.dl = cx;
		int86(0x10, &r, &r);
	}
	_cursorKnown = true;
	_lastCursorVisible = visible;
	_lastCursorX = cx;
	_lastCursorY = cy;
}
