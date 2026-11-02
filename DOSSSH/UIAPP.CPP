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

/* One session owns SSH cipher state and the active username. The screen and terminal
 * objects remain global as in FTP2P. Cleanup is safe after early returns. */
class UiApp
{
public:
	UiApp()
	{
		_cleaned = false;
	}

	~UiApp()
	{
		Cleanup();
	}

	void Cleanup()
	{
		if( _cleaned )
			return;

		_cleaned = true;
		RestoreVideo();
		if( g_transport.Aborted() )
			Log('E', "Interrupted");
		g_transport.Stop();
		_session.Clear();
		_rng.Clear();
		SshCrypt::Zero(_username, sizeof(_username));
	}

	int Run(const char *programPath)
	{
		/* The mTCP timer starts only after entropy initialization.  Use
		 * the BIOS tick counter until the mTCP interrupt hook is active. */
		volatile unsigned long far *ticks = (volatile unsigned long far *)MK_FP(0x40, 0x6C);
		unsigned long start = *ticks;
		if( !SshEntropy::Initialize(_rng, programPath) )
		{
			Log('E', "No usable cryptographic seed; SSH connection cancelled.");
			return 1;
		}

		unsigned long end = *ticks;
		unsigned long entropy_ticks = end >= start ? end - start : TIMER_TICKS_PER_DAY - start + end;
		if( !g_transport.Start() )
		{
			Log('E', "mTCP setup failed. Check MTCPCFG and packet driver.");
			return 1;
		}

		Log('I', "Entropy %lu ticks", entropy_ticks);
		{
			char connect_name[80];
			SprintfTrunc(connect_name, sizeof(connect_name), "Connecting %s", g_hostArg);
			LongOp connect_op(connect_name);
			if( !g_transport.ConnectHost(g_hostArg, g_portArg) )
				return 1;
		}

		char server_ident[SSHSCAN_ID_SIZE];
		if( !SshScanSendIdent(TIMER_SECS_TO_TICKS(5)) )
		{
			Log('E', "Cannot send SSH client identification");
			return 1;
		}
		if( !SshScanIdent(server_ident, sizeof(server_ident), TIMER_SECS_TO_TICKS(15)) )
		{
			Log('E', "Invalid SSH server identification");
			return 1;
		}

		Log('I', "Peer %s", server_ident);
		const char *reason = "SSH connection failed";
		if( !SshScanExchangeTofu(server_ident, _rng, _session, DosTrustHost, NULL, &reason, TIMER_SECS_TO_TICKS(30)) )
		{
			Log('E', "SSH initial KEX failed: %s", reason);
			return 1;
		}

		// One-hour automatic rekey
		_session.rekeyPeriodTicks = TIMER_SECS_TO_TICKS(3600);
		if( g_userArg[0] )
		{
			if( !DosOemString(g_userArg, _username, sizeof(_username)) )
			{
				Log('E', "Invalid username or too long");
				return 1;
			}
		}
		else if( !DosUsername(_username, sizeof(_username)) )
		{
			Log('E', "Username entry cancelled");
			return 1;
		}

		Log('I', "Auth user=%s", _username);
		{
			SshAuthenticator authenticator(_session, _rng, _username,
				DosPassword, DosChallenge, _username, &reason, TIMER_SECS_TO_TICKS(30));
			if( !authenticator.Login() )
			{
				Log('E', "Authentication failed: %s", reason);
				return 1;
			}
		}

		if( !g_screen.Init() )
			return 1;
		if( !g_terminal.Init(g_screen.Cols(), g_screen.Rows()) )
		{
			Log('E', "Cannot initialize DOS text screen");
			return 1;
		}
		g_screen.Capture();
		if( !g_screen.IsCaptured() )
		{
			Log('E', "Cannot initialize DOS text screen");
			return 1;
		}
		g_terminal.SetCodePage(g_dosCodePage);
		g_terminal.Reset();
		g_screen.Draw();
		UiTerminal display;

		if( DebugIsOn() )
		{
			char memory_report[80];
			ProbeFreeMem(memory_report, sizeof(memory_report));
			Log('I', "Memory %s", memory_report);
		}

		DosFlushKeys();
		g_transport.SetInteractive(true);
		/* xterm defines F1-F12 in both video modes. Its basic 8 colours
		 * plus bright foreground fit the 16-colour CGA/EGA/VGA palette;
		 * UiScreen maps output to monochrome attributes for MDA. */
		bool opened = SshScanShell(_session, _rng, g_screen.Cols(), g_screen.Rows(),
			"xterm", UiTerminal::Input, UiTerminal::Output,
			&display, &reason, TIMER_SECS_TO_TICKS(30));

		RestoreVideo();
		Log('I', "Shell result=%d exit=%d code=%lu", opened, _session.exitStatusReceived, _session.exitStatus);
		if( !opened )
		{
			Log('E', "Shell failed: %s", reason);
			return 1;
		}

		return _session.exitStatusReceived ? (int)(_session.exitStatus & 255ul) : 0;
	}

private:
	bool _cleaned;
	SSHCRYPT_RNG _rng;
	SSHSCAN_Session _session;
	char _username[129];

	void RestoreVideo()
	{
		if( g_screen.IsCaptured() )
		{
			g_transport.SetInteractive(false);
			g_screen.Restore();
		}
	}
};
