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
#include "ENCODING.H"

struct VtCell
{
	unsigned char ch;
	char fg;
	char bg;
	char flags;
};

#define VT_UNDERLINE (1u)
#define VT_REVERSE (2u)
#define VT_BOLD (4u)

unsigned char DosColor(const VtCell &cell, bool bw);
size_t KeyToVt(unsigned int biosKey, unsigned char *out, size_t capacity, bool applicationCursor = false);

class Vt100
{
public:
	Vt100();
	~Vt100();

	bool Init(int cols, int rows);
	void Reset();
	void SetCodePage(int codepage);
	void Feed(const unsigned char *bytes, size_t size);
	size_t ReadReply(unsigned char *out, size_t capacity);

	bool CursorApplication() const { return _screenState.cursorApplication; }

	/ Dirty ranges are inclusive; consumed by the DOS video driver.
	/ The virtual screen never exceeds 132 x 50 cells.
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
		int savedX;
		int savedY;
		int scrollTop;
		int scrollBottom;
		char fg;
		char bg;
		char flags;
		char savedFg;
		char savedBg;
		char savedFlags;
		char charset;
		char savedCharset;
		char g0;
		char g1;
		bool useG1;
		bool savedUseG1;
		bool cursorVisible;
		bool wrap;
		bool pendingWrap;
		bool origin;
		bool cursorApplication;
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
	int _codePage;
	DosUtf8Decoder _utf8;
	bool _screenFailed;

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
