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

#ifndef DOSSSH_SSHSCAN_H
#define DOSSSH_SSHSCAN_H

#include "SSHCRYPT.H"
#include "SSHPKT.H"

#define SSHSCAN_ID_SIZE 256
#define DOSSSH_VERSION "1.0"
#define SSHSCAN_CLIENT_ID "SSH-2.0-DOSSSH_" DOSSSH_VERSION "\r\n"

struct SSHSCAN_Session
{
	SSHPKT_Cipher encrypt;
	SSHPKT_Cipher decrypt;
	unsigned long outSequence;
	unsigned long inSequence;
	bool authenticated;
	bool exitStatusReceived;
	unsigned long exitStatus;
	// RFC 4253: the original session identifier and packet sequence numbers
	// survive every rekey; cipher states do not.
	unsigned char sessionId[32];
	unsigned char serverHostKey[51];
	size_t serverHostKeyLength;
	char serverIdent[SSHSCAN_ID_SIZE];
	unsigned long inEpochPackets;
	unsigned long outEpochPackets;
	unsigned long inEpochBytes;
	unsigned long outEpochBytes;
	unsigned long lastKexTicks;
	unsigned long rekeyPeriodTicks;
	bool rekeyRequested;

	void Clear();
	bool NeedsRekey(unsigned long now) const;
	void RecordSent(size_t length);
	void RecordReceived(size_t length);
};

typedef bool (*SSHSCAN_Password)(void *ctx, char *buffer, size_t capacity);
// Keyboard-interactive may ask for passwords and for displayed OTPs.
typedef bool (*SSHSCAN_Challenge)(void *ctx, const char *prompt, bool echo, char *response, size_t capacity);
typedef void (*SSHSCAN_Output)(void *ctx, const unsigned char *data, size_t length);
// capacity=0: poll only local commands (0, -1 detach, -2 fatal).
// capacity>0: returns 0 idle, -1 disconnect, -2 fatal or 1..capacity bytes.
typedef int (*SSHSCAN_Input)(void *ctx, unsigned char *data, size_t capacity);
typedef bool (*SSHSCAN_HostTrust)(void *ctx, const unsigned char *hostKey, size_t keySize, const unsigned char sha256[32]);

bool SshScanIdent(char *server, size_t capacity, unsigned long timeoutTicks);
bool SshScanSendIdent(unsigned long timeoutTicks);

bool SshScanExchangeTofu(const char *serverIdent, SSHCRYPT_RNG &rng,
	SSHSCAN_Session &session, SSHSCAN_HostTrust checkHost, void *trustCtx,
	const char **reason, unsigned long timeoutTicks);

void SshScanFingerprint(const unsigned char digest[32], char result[52]);
bool SshScanUtf8Valid(const unsigned char *text, size_t length);

class SshAuthenticator
{
public:
	SshAuthenticator(SSHSCAN_Session &session, SSHCRYPT_RNG &rng,
		const char *username, SSHSCAN_Password password, SSHSCAN_Challenge challenge,
		void *promptCtx, const char **reason, unsigned long timeout);
	~SshAuthenticator();
	bool Login();

private:
	SSHSCAN_Session &_session;
	SSHCRYPT_RNG &_rng;
	const char *_username;
	SSHSCAN_Password _password;
	SSHSCAN_Challenge _challenge;
	void *_promptCtx;
	const char **_reason;
	unsigned long _timeout;
	unsigned int _methods;
	bool _partial;
	char _secret[97];

	void SetReason(const char *message);
	bool Complete();
	bool SendRequest(const char *method);
	bool ValidResponse(const char *answer);
	int WaitResult(bool interactive);
	int SendPassword();
	int SendInteractive();
	bool AnswerChallenge(const unsigned char *packet, size_t length);
};

bool SshScanShell(SSHSCAN_Session &session, SSHCRYPT_RNG &rng,
	int cols, int rows, const char *terminalType,
	SSHSCAN_Input keyboard, SSHSCAN_Output display, void *terminalCtx,
	const char **reason, unsigned long timeoutTicks);

#endif
