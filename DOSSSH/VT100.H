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

#ifndef DOSSSH_VT100_H
#define DOSSSH_VT100_H

#include <stddef.h>
#include <stdint.h>

#include "ENCODING.H"

struct DosMouseEvent;

struct VtCell
{
	unsigned char ch;
	char fg;
	char bg;
	char flags;

	uint16_t ScreenChar(bool bw) const;
};

class Vt100
{
public:
	Vt100();
	~Vt100();

	bool Init(int cols, int rows);
	void Reset();
	void Feed(const unsigned char *bytes, size_t size);
	size_t ReadReply(unsigned char *out, size_t capacity);
	size_t KeyToVt(unsigned int biosKey, unsigned int modifiers, unsigned char *out, size_t capacity);
	size_t MouseToVt(const DosMouseEvent &event, unsigned int modifiers, unsigned char *out, size_t capacity) const;
	unsigned int MouseMode() const { return _mouseMode; }

	// Dirty ranges are inclusive; consumed by the DOS video driver.
	const VtCell *Row(int y) const;
	bool TakeDirtyRow(int y, int &first, int &last);

	int Cols() const { return _cols; }
	int Rows() const { return _rows; }
	int CursorX() const { return _screenState.x; }
	int CursorY() const { return _screenState.y; }
	bool CursorVisible() const { return _screenState.cursorVisible; }
	bool Ok() const { return _cells != NULL && !_screenFailed; }

private:
	struct ScreenState
	{
		int x;
		int y;
		char fg;
		char bg;
		char flags;
		char charset;
		bool useG1;

		int scrollTop;
		int scrollBottom;
		char g0;
		char g1;
		bool cursorVisible;
		bool wrap;
		bool pendingWrap;
		bool origin;
		bool cursorApplication;

		int savedX;
		int savedY;
		char savedFg;
		char savedBg;
		char savedFlags;
		char savedCharset;
		bool savedUseG1;
	};
	VtCell *_cells;
	VtCell *_normalCells;
	ScreenState _screenState;
	ScreenState _normalState;
	unsigned char _replies[64];
	size_t _replyLength;
	int _cols;
	int _rows;
	unsigned char _dirtyFirst[50];
	unsigned char _dirtyLast[50];
	int _params[12];
	int _paramIndex;
	char _state;
	char _private;
	DosUtf8Decoder _utf8;
	bool _screenFailed;
	unsigned int _mouseMode;
	bool _mouseSgr;

	void ResetState();
	void Put(unsigned char ch);
	void SetCell(int x, int y, unsigned char ch);
	void MarkDirty(int y, int first, int last);
	void MarkAllDirty();
	void ClearRow(int y, int first, int last);
	void ScrollUp(int first, int last, int lines);
	void ScrollDown(int first, int last, int lines);
	void LineFeed();
	void ReverseIndex();
	void Csi(char finalByte);
	void Sgr();
	void AlternateScreen(bool enabled);
	void QueueReply(const char *reply);
	void SaveCursor();
	void RestoreCursor();
	int Param(int idx, int fallback) const;
	int ParamCount() const { return _paramIndex + 1; }
	static unsigned char GraphicsChar(unsigned char ch);
};
#endif
