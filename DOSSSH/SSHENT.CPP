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

#include <stdio.h>
#include <string.h>
#include <conio.h>
#include <dos.h>
#include <time.h>

#include "inlines.h"

#include "SSHENT.H"
#include "CONFIG.H"
#include "INPUT.H"

SshEntropy::SshEntropy()
{
	_samples = 0;

	_hash.Init();

	static const unsigned char domain[] = "DOSSSH entropy collector v2";
	_hash.Bytes(domain, sizeof(domain) - 1);
}

void SshEntropy::AddState(const unsigned char *bytes, size_t length)
{
	static const unsigned char tag = 'S';
	_hash.Bytes(&tag, 1);
	_hash.Bytes(bytes, length);
}

static void Store32(unsigned char *bytes, unsigned long value)
{
	memcpy(bytes, &value, 4);
}

void SshEntropy::AddVolume(unsigned char drive, unsigned long serial, unsigned long totalSectors)
{
	unsigned char metadata[10];

	metadata[0] = 'V';
	metadata[1] = drive;
	Store32(metadata + 2, serial);
	Store32(metadata + 6, totalSectors);
	_hash.Bytes(metadata, sizeof(metadata));
}

void SshEntropy::AddSector(const unsigned char sector[512], unsigned long sectorNumber,
	unsigned long beforeTick, unsigned long afterTick)
{
	unsigned char metadata[13];
	unsigned long duration = afterTick - beforeTick;

	metadata[0] = 'D';
	Store32(metadata + 1, sectorNumber);
	Store32(metadata + 5, beforeTick);
	Store32(metadata + 9, duration);
	_hash.Bytes(metadata, sizeof(metadata));
	_hash.Bytes(sector, 512);

	_samples++;
}

void SshEntropy::Final(unsigned char seed[64])
{
	static const unsigned char domain[] = "DOSSSH entropy expansion v2";

	_hash.Final(seed);

	/* Domain-separated expansion of a 256-bit digest to the 64-byte
	   input required by the existing HMAC-DRBG. This cannot add entropy. */
	Sha256State hash;
	hash.Init();
	hash.Bytes(domain, sizeof(domain) - 1);
	hash.Bytes(seed, 32);
	hash.Final(seed + 32);
	SshCrypt::Zero(&hash, sizeof(hash));
}

unsigned long SshEntropy::NextSelector(unsigned long previous, unsigned long readDuration,
	unsigned long sampleStamp, unsigned long lastSector)
{
	/* Explicit 32-bit arithmetic on both 16-bit DOS and 64-bit test hosts. */
	unsigned long value = (previous ^ readDuration) & 0xFFFFFFFFul;
	value ^= (value << 13) & 0xFFFFFFFFul;
	value ^= value >> 17;
	value ^= (value << 5) & 0xFFFFFFFFul;
	value += sampleStamp + lastSector + 0x9E3779B9ul;
	return value & 0xFFFFFFFFul;
}

unsigned long SshEntropy::PickSector(unsigned long firstSector, unsigned long sectorCount, unsigned long selector)
{
	if( sectorCount == 0 )
		return firstSector;

	return firstSector + selector % sectorCount;
}

/* DOS 3.31+ INT 25h, CX=FFFFh, DS:BX -> 10-byte transfer packet.
   The interrupt leaves a FLAGS word on the stack; POPF removes it.
   Save DS explicitly for the 16-bit large-data model. */
unsigned int SshEntReadAbsolute(unsigned int drive, const void far *packet);
#pragma aux SshEntReadAbsolute = \
	"push bp" \
	"push ds" \
	"mov ds, dx" \
	"mov cx, 0FFFFh" \
	"int 25h" \
	"sbb ax, ax" \
	"popf" \
	"pop ds" \
	"pop bp" \
	parm [ax] [dx bx] \
	value [ax] \
	modify [bx cx dx si di];

static unsigned char s_sector[512];
static unsigned char s_packet[10];

static unsigned int Load16(const unsigned char *bytes)
{
	return (unsigned int)bytes[0] | ((unsigned int)bytes[1] << 8);
}

static unsigned long Load32(const unsigned char *bytes)
{
	return (unsigned long)Load16(bytes) | ((unsigned long)Load16(bytes + 2) << 16);
}

static void Store16(unsigned char *bytes, unsigned int value)
{
	bytes[0] = (unsigned char)value;
	bytes[1] = (unsigned char)(value >> 8);
}

/* PIT channel 0 counts down at ~1.193 MHz. Combine its latched value
   with the BIOS tick counter so reads longer than 55 ms are measurable.
   This is a time stamp, NOT a cryptographic source on its own. */
static unsigned long PitStamp()
{
	volatile unsigned long far *bios_ticks = (volatile unsigned long far *)MK_FP(0x40, 0x6C);
	unsigned long before_ticks;
	unsigned long after_ticks;
	unsigned int low;
	unsigned int high;

	do
	{
		before_ticks = *bios_ticks;
		outp(0x43, 0);
		low = (unsigned int)inp(0x40);
		high = (unsigned int)inp(0x40);
		after_ticks = *bios_ticks;
	} while( before_ticks != after_ticks );

	return (before_ticks << 16) + 65535ul - (low | (high << 8));
}

static void ShowEntropyProgress(unsigned int percent, unsigned int &shown, bool haveMouse)
{
	unsigned int value = percent == 100u ? 100u : (percent / 5u) * 5u;
	if( value == shown )
		return;

	if( haveMouse )
		DosMouseCursor(false);

	printf("\rEntropy input: %3u%%", value);
	fflush(stdout);
	if( haveMouse )
		DosMouseCursor(true);
	shown = value;
}

static bool ReadSector(unsigned char drive, unsigned long sectorNumber)
{
	Store32(s_packet, sectorNumber);
	Store16(s_packet + 4, 1);
	Store16(s_packet + 6, FP_OFF(s_sector));
	Store16(s_packet + 8, FP_SEG(s_sector));

	return SshEntReadAbsolute(drive, s_packet) == 0;
}

static unsigned char ProgramDrive(const char *programPath)
{
	if( programPath && programPath[0] && programPath[1] == ':' )
	{
		unsigned char letter = (unsigned char)programPath[0];
		if( letter >= 'a' && letter <= 'z' )
			letter = (unsigned char)(letter - 'a' + 'A');
		if( letter >= 'A' && letter <= 'Z' )
			return (unsigned char)(letter - 'A');
	}

	union REGS r;
	memset(&r, 0, sizeof(r));
	r.h.ah = 0x19;
	intdos(&r, &r);
	return r.h.al < 26u ? r.h.al : 2u;
}

static void AddDosVolumeSerial(SshEntropy &collector, unsigned char drive)
{
	/* DOS 4+ AX=6900h: disk information starts with two reserved bytes,
	   followed by a four-byte FAT volume serial number. Ignore failures. */
	unsigned char disk_info[25];
	union REGS regs;
	struct SREGS segregs;

	memset(disk_info, 0, sizeof(disk_info));
	memset(&regs, 0, sizeof(regs));
	memset(&segregs, 0, sizeof(segregs));
	regs.x.ax = 0x6900;
	regs.x.bx = (unsigned int)drive + 1u;
	regs.x.dx = FP_OFF(disk_info);
	segregs.ds = FP_SEG(disk_info);
	intdosx(&regs, &regs, &segregs);

	if( !regs.x.cflag )
		collector.AddState(disk_info, sizeof(disk_info));
}

static unsigned int CollectDisk(SshEntropy &collector, unsigned char drive, int maxSamples)
{
	/* INT 25h is not necessarily implemented for SUBST, network drives,
	   or DOSBox directory mounts. Never attempt INT 26h (write). */
	if( !ReadSector(drive, 0) )
		return 0;

	unsigned int bytes_per_sector = Load16(s_sector + 11);
	unsigned int reserved = Load16(s_sector + 14);
	int fats = s_sector[16];
	unsigned int root_entries = Load16(s_sector + 17);
	unsigned int sectors_per_fat = Load16(s_sector + 22);
	unsigned long total_sectors = Load16(s_sector + 19);
	if( total_sectors == 0 )
		total_sectors = Load32(s_sector + 32);

	/* FAT12/16, 512 bytes/sector. Reject other layouts rather than
	   interpreting filesystem data as a BPB. */
	if( s_sector[510] != 0x55 || s_sector[511] != 0xAA ||
		bytes_per_sector != 512 || reserved == 0 || fats == 0 ||
		root_entries == 0 || sectors_per_fat == 0 )
	{
		return 0;
	}

	unsigned long data_start = (unsigned long)reserved + (unsigned long)fats * sectors_per_fat;
	data_start += ((unsigned long)root_entries * 32ul + 511ul) / 512ul;
	if( data_start >= total_sectors || total_sectors - data_start < 256ul )
		return 0;

	unsigned long serial = 0;
	if( s_sector[38] == 0x28 || s_sector[38] == 0x29 )
		serial = Load32(s_sector + 39);
	collector.AddVolume(drive, serial, total_sectors);
	AddDosVolumeSerial(collector, drive);

	/* Avoid boot sectors, FAT, directory tables, and early DOS system
	   files. Sector contents are supplementary; seeks supply timing data. */
	unsigned long first_sector = data_start + (total_sectors - data_start) / 4ul;
	unsigned long sector_count = total_sectors - first_sector;
	unsigned long selector = PitStamp() ^ (unsigned long)clock();
	selector ^= (unsigned long)time(NULL);
	int consecutive_failures = 0;
	unsigned long previous_duration = 0;
	unsigned long previous_sector = 0;

	for( int i = 0; i < maxSamples; i++ )
	{
		/* Deliberately change seek position across the volume. Each next
		   position is affected by the previous read's measured duration. */
		selector = SshEntropy::NextSelector(selector, previous_duration, PitStamp(), previous_sector);
		unsigned long sector_number = SshEntropy::PickSector(first_sector, sector_count, selector);

		unsigned long before_tick = PitStamp();
		bool read_ok = ReadSector(drive, sector_number);
		unsigned long after_tick = PitStamp();
		previous_duration = after_tick - before_tick;
		previous_sector = sector_number;

		if( read_ok )
		{
			collector.AddSector(s_sector, sector_number, before_tick, after_tick);
			consecutive_failures = 0;
		}
		else if( ++consecutive_failures >= 6 )
			break;
	}

	SshCrypt::Zero(s_sector, sizeof(s_sector));
	return collector.SampleCount();
}

/* BIOS, ROM and video memory are supplementary inputs. Their contents
   may be identical across cloned systems and receive no entropy credit. */
static void CollectMachineState(SshEntropy &collector)
{
	unsigned char bytes[128];
	const unsigned char far *bios_data = (const unsigned char far *)MK_FP(0x0040, 0x0000);
	const unsigned char far *rom = (const unsigned char far *)MK_FP(0xF000, 0xE000);
	unsigned char mode = *(const unsigned char far *)MK_FP(0x0040, 0x0049);
	const unsigned char far *screen = (const unsigned char far *)MK_FP(mode == 7 ? 0xB000 : 0xB800, 0);
	
	static const unsigned char tag[] = "DOS/BIOS/VIDEO passive state v1";
	collector.AddState(tag, sizeof(tag) - 1u);

	for( int region = 0; region < 3; region++ )
	{
		const unsigned char far *source = region == 0 ? bios_data : (region == 1 ? rom : screen);
		int length = region == 0 ? 256 : (region == 1 ? 512 : 2048);
		for( int offset = 0; offset < length; offset += (int)sizeof(bytes) )
		{
			for( int i = 0; i < (int)sizeof(bytes); i++ )
				bytes[i] = source[offset + i];
			collector.AddState(bytes, sizeof(bytes));
		}
	}

	unsigned char clocks[16];
	Store32(clocks, PitStamp());
	Store32(clocks + 4, (unsigned long)clock());
	Store32(clocks + 8, (unsigned long)time(NULL));
	Store32(clocks + 12, PitStamp());
	collector.AddState(clocks, sizeof(clocks));
	SshCrypt::Zero(bytes, sizeof(bytes));
	SshCrypt::Zero(clocks, sizeof(clocks));
}

static bool CollectInput(SshEntropy &collector)
{
	bool have_mouse = DosMouseInit();

	printf("Press keys and/or move the mouse until progress reaches 100%%. Esc cancels.\n");

	const unsigned int required_points = 32u;
	const unsigned long mouse_poll_interval = 12000ul;
	const unsigned long gesture_interval = 200000ul;
	unsigned int points = 0;
	unsigned int shown = 101u;
	unsigned int previous_key = 0;
	unsigned int travel = 0;
	int motion_dir = 0;
	int credited_dir = 0;
	unsigned long last_key = PitStamp();
	unsigned long last_motion = 0;
	unsigned long last_gesture = 0;
	unsigned long last_poll = last_key;

	ShowEntropyProgress(0u, shown, false);
	if( have_mouse )
		DosMouseCursor(true);

	for( ;; )
	{
		unsigned long now = PitStamp();
		unsigned int credit = 0;

		if( DosKeyReady() )
		{
			unsigned int key = DosKeyRead();
			if( (key & 255u) == 27u || (key & 255u) == 3u )
				break;

			unsigned char event[10];
			Store32(event, now);
			Store32(event + 4, now - last_key);
			Store16(event + 8, key);
			collector.AddState(event, sizeof(event));

			// Ignore auto-repeat
			if( key != previous_key )
				credit++;
			previous_key = key;
			last_key = now;
		}

		if( have_mouse && now - last_poll >= mouse_poll_interval )
		{
			last_poll = now;
			int dx;
			int dy;
			DosMouseMotion(dx, dy);
			if( dx || dy )
			{
				unsigned char event[12];
				Store32(event, now);
				Store16(event + 4, dx);
				Store16(event + 6, dy);
				Store32(event + 8, now - last_motion);
				collector.AddState(event, sizeof(event));
				last_motion = now;

				unsigned int x = dx < 0 ? (unsigned int)(-(long)dx) : (unsigned int)dx;
				unsigned int y = dy < 0 ? (unsigned int)(-(long)dy) : (unsigned int)dy;
				int dir = x >= y ? (dx > 0 ? 1 : -1) : (dy > 0 ? 2 : -2);
				if( dir != motion_dir )
				{
					motion_dir = dir;
					travel = 0;
				}
				unsigned long distance = (unsigned long)travel + x + y;
				travel = distance >= 12ul ? 12u : (unsigned int)distance;

				if( travel == 12u && (credited_dir == 0 || dir == -credited_dir) &&
					now - last_gesture >= gesture_interval )
				{
					credit += 2u;
					credited_dir = dir;
					last_gesture = now;
				}
			}
		}

		if( credit )
		{
			points += credit;
			if( points >= required_points )
				break;
			ShowEntropyProgress(points * 100u / required_points, shown, have_mouse);
		}
	}

	if( have_mouse )
		DosMouseCursor(false);
	if( points >= required_points )
		ShowEntropyProgress(100u, shown, false);
	printf("\n");
	return points >= required_points;
}

bool SshEntropy::Initialize(SSHCRYPT_RNG &rng, const char *programPath)
{
	unsigned char seed[64];
	bool have_seed = false;
	bool success = false;
	SshEntropy collector;

	if( !SshData::Select(ProgramDrive(programPath)) )
	{
		printf("No accessible C: or program drive for DOSSSH.DAT.\n");
		goto done;
	}
	if( !SshData::LoadSeed(seed, have_seed) )
	{
		printf("DOSSSH.DAT is corrupt or inaccessible; refusing to overwrite state.\n");
		goto done;
	}
	if( have_seed )
		collector.AddState(seed, sizeof(seed));

	CollectMachineState(collector);
	CollectDisk(collector, SshData::Drive(), have_seed ? 4 : 24);
	if( !have_seed )
	{
		/* Cloned disk images and passive machine state can be reproduced.
		 * Collect live mouse and keyboard input before first use. */
		if( !CollectInput(collector) )
			goto done;
	}
	collector.Final(seed);
	rng.Init(seed);
	rng.Generate(seed, sizeof(seed));
	if( !SshData::RotateSeed(seed) )
	{
		printf("DOSSSH.DAT update failed; refusing SSH connection.\n");
		goto done;
	}
	success = true;

done:
	SshCrypt::Zero(seed, sizeof(seed));
	if( !success )
		rng.Clear();
	return success;
}
