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
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <dos.h>
#include <time.h>
#include <bios.h>

#include "inlines.h"

#include "SSHENT.H"
#include "CONFIG.H"

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
	bytes[0] = (unsigned char)value;
	bytes[1] = (unsigned char)(value >> 8);
	bytes[2] = (unsigned char)(value >> 16);
	bytes[3] = (unsigned char)(value >> 24);
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

/* Static storage ensures both buffers have a stable far address and
   don't consume the 16-bit DOS stack. */
static unsigned char g_sector[512];
static unsigned char g_packet[10];

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

/* The BLASTER environment variable identifies a configured Sound Blaster.
 * Do not probe arbitrary ISA ports: only an explicitly configured card. */
static unsigned int SoundBlasterBase()
{
	const char *settings = getenv("BLASTER");
	if( settings == NULL )
		return 0;

	while( *settings )
	{
		while( *settings == ' ' || *settings == '\t' )
			settings++;

		if( *settings == 'A' || *settings == 'a' )
		{
			char *end_ptr;
			unsigned long address = strtoul(settings + 1, &end_ptr, 16);
			if( end_ptr > settings + 1 &&
				(*end_ptr == '\0' || *end_ptr == ' ' || *end_ptr == '\t') &&
				address >= 0x210ul && address <= 0x280ul && (address & 15ul) == 0ul )
			{
				return (unsigned int)address;
			}
		}
		while( *settings && *settings != ' ' && *settings != '\t' )
			settings++;
	}
	return 0;
}

/* DSP direct ADC (command 20h) needs neither DMA nor IRQ. Bounded polls
 * prevent a missing or nonresponding device from hanging DOSSSH. */
static bool SoundBlasterWrite(unsigned int base, unsigned char command)
{
	unsigned long start_stamp = PitStamp();
	while( (unsigned long)(PitStamp() - start_stamp) < 119318ul )
	{
		if( (inp(base + 0x0C) & 0x80) == 0 )
		{
			outp(base + 0x0C, command);
			return true;
		}
	}
	return false;
}

/* The ADC sample is 0..255; -1 means the DSP did not respond. */
static int SoundBlasterRead(unsigned int base)
{
	unsigned long start_stamp = PitStamp();
	while( (unsigned long)(PitStamp() - start_stamp) < 119318ul )
	{
		if( inp(base + 0x0E) & 0x80 )
			return inp(base + 0x0A) & 0xFF;
	}
	return -1;
}

static bool SoundBlasterReset(unsigned int base)
{
	outp(base + 0x06, 1);
	unsigned long start_stamp = PitStamp();
	while( (unsigned long)(PitStamp() - start_stamp) < 20ul )
		;
	outp(base + 0x06, 0);

	return SoundBlasterRead(base) == 0xAA;
}

/* Accept recorded sound only if a changing, non-silent signal was detected.
 * A PCM signal has no proven min-entropy bound; seed hashing never treats
 * silence or repeated, constant samples as sufficient on first startup. */
static bool CollectSoundBlaster(SshEntropy &collector)
{
	unsigned int base = SoundBlasterBase();
	if( !base || !SoundBlasterReset(base) )
		return false;

	printf("Sound Blaster: make some sound at the recording input for two seconds.\n");
	unsigned int active_samples = 0;
	unsigned int changed_samples = 0;
	unsigned int distinct_samples = 0;
	unsigned char seen_samples[32];
	memset(seen_samples, 0, sizeof(seen_samples));
	unsigned char low_sample = 255;
	unsigned char high_sample = 0;
	unsigned char previous_sample = 128;

	for( int i = 0; i < 384; i++ )
	{
		if( !SoundBlasterWrite(base, 0x20) )
			return false;
		int value = SoundBlasterRead(base);
		if( value < 0 )
			return false;
		unsigned char sample = (unsigned char)value;

		unsigned long stamp = PitStamp();
		unsigned char event[5];
		Store32(event, stamp);
		event[4] = sample;
		collector.AddState(event, sizeof(event));
		unsigned int sample_index = (unsigned int)sample >> 3;
		unsigned char sample_bit = (unsigned char)(1u << (sample & 7u));
		if( (seen_samples[sample_index] & sample_bit) == 0 )
		{
			seen_samples[sample_index] |= sample_bit;
			distinct_samples++;
		}
		if( sample < low_sample )
			low_sample = sample;
		if( sample > high_sample )
			high_sample = sample;
		if( sample < 120u || sample > 136u )
			active_samples++;
		if( i && ((int)sample - (int)previous_sample >= 4 ||
			(int)previous_sample - (int)sample >= 4) )
			changed_samples++;
		previous_sample = sample;

		/* Direct ADC is software-paced (~250 samples/s). */
		while( (unsigned long)(PitStamp() - stamp) < 4000ul )
			;
	}

	if( active_samples >= 48u && changed_samples >= 32u && distinct_samples >= 16u &&
		(unsigned int)(high_sample - low_sample) >= 20u )
	{
		printf("Sound Blaster input variation collected.\n");
		return true;
	}
	printf("Sound Blaster input silent or insufficient; trying the mouse.\n");
	return false;
}

static bool ReadSector(unsigned char drive, unsigned long sectorNumber)
{
	Store32(g_packet, sectorNumber);
	Store16(g_packet + 4, 1);
	Store16(g_packet + 6, FP_OFF(g_sector));
	Store16(g_packet + 8, FP_SEG(g_sector));

	return SshEntReadAbsolute(drive, g_packet) == 0;
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

	/* DOS 21h/19h: AL is the *zero-based* current drive (A=0).
	   Open Watcom 1.9 does not need getdisk() or direct.h for this. */
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

	unsigned int bytes_per_sector = Load16(g_sector + 11);
	unsigned int reserved = Load16(g_sector + 14);
	int fats = g_sector[16];
	unsigned int root_entries = Load16(g_sector + 17);
	unsigned int sectors_per_fat = Load16(g_sector + 22);
	unsigned long total_sectors = Load16(g_sector + 19);
	if( total_sectors == 0 )
		total_sectors = Load32(g_sector + 32);

	/* FAT12/16, 512 bytes/sector. Reject other layouts rather than
	   interpreting filesystem data as a BPB. */
	if( g_sector[510] != 0x55 || g_sector[511] != 0xAA ||
		bytes_per_sector != 512 || reserved == 0 || fats == 0 ||
		root_entries == 0 || sectors_per_fat == 0 )
		return 0;

	unsigned long data_start = (unsigned long)reserved + (unsigned long)fats * sectors_per_fat;
	data_start += ((unsigned long)root_entries * 32ul + 511ul) / 512ul;
	if( data_start >= total_sectors || total_sectors - data_start < 256ul )
		return 0;

	unsigned long serial = 0;
	if( g_sector[38] == 0x28 || g_sector[38] == 0x29 )
		serial = Load32(g_sector + 39);
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
			collector.AddSector(g_sector, sector_number, before_tick, after_tick);
			consecutive_failures = 0;
		}
		else if( ++consecutive_failures >= 6 )
			break;
	}

	SshCrypt::Zero(g_sector, sizeof(g_sector));
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

/* Check the INT 33h vector without resetting an existing mouse driver.
   Some DOS machines have no driver or only an IRET interrupt stub. */
static bool MousePresent()
{
	union REGS regs;
	struct SREGS segregs;
	memset(&regs, 0, sizeof(regs));
	memset(&segregs, 0, sizeof(segregs));
	regs.x.ax = 0x3533;
	intdosx(&regs, &regs, &segregs);
	if( (segregs.es == 0 && regs.x.bx == 0) || *(const unsigned char far *)MK_FP(segregs.es, regs.x.bx) == 0xCF )
		return false;
	return true;
}

/* Collect relative mouse motion (INT 33h/000Bh) and PIT intervals.
   Simple variation checks reject stationary/fixed input but do not
   establish a cryptographic lower bound on mouse entropy. */
static int CollectMouse(SshEntropy &collector, unsigned int &keyEvents, unsigned int &motions)
{
	if( !MousePresent() )
		return 0;

	/* A live interrupt vector alone does not initialise the mouse driver.
	 * INT 33h AX=0 resets its motion counters and confirms availability. */
	union REGS mouse_regs;
	memset(&mouse_regs, 0, sizeof(mouse_regs));
	int86(0x33, &mouse_regs, &mouse_regs);
	if( mouse_regs.x.ax != 0xFFFFu )
		return 0;

	printf("First start: move the mouse irregularly for a few seconds.\n");
	printf("Mouse not available? Keyboard fallback will follow. Esc cancels.\n");
	unsigned long begin = PitStamp();
	unsigned long last = begin;
	unsigned long last_motion = begin;
	unsigned int events = 0;
	unsigned int varied = 0;
	unsigned int time_bins = 0;
	unsigned int prev_x = 0;
	unsigned int prev_y = 0;

	for( unsigned long loop = 0; loop < 400000ul; loop++ )
	{
		unsigned long now = PitStamp();
		if( now - begin >= 5ul * 1193182ul || (events == 0 && now - begin >= 2ul * 1193182ul) )
			break;

		if( biosIsKeyReady() )
		{
			unsigned int key = biosKeyRead();
			if( (key & 255u) == 27u || (key & 255u) == 3u )
				return -1;
			unsigned char kb[10];
			Store32(kb, last);
			Store32(kb + 4, now);
			kb[8] = (unsigned char)key;
			kb[9] = (unsigned char)(key >> 8);
			collector.AddState(kb, sizeof(kb));
			keyEvents++;
		}
		if( now - last < 4000ul )
			continue; /* Limit mouse polling to approximately 250 Hz. */

		last = now;
		union REGS regs;
		memset(&regs, 0, sizeof(regs));
		regs.x.ax = 0x000B;
		int86(0x33, &regs, &regs);
		unsigned int dx = regs.x.cx;
		unsigned int dy = regs.x.dx;
		if( !dx && !dy )
			continue;

		unsigned char sample[12];
		Store32(sample, now);
		Store16(sample + 4, dx);
		Store16(sample + 6, dy);
		Store32(sample + 8, now - last_motion);
		collector.AddState(sample, sizeof(sample));
		last_motion = now;
		events++;
		motions = events;
		if( dx != prev_x || dy != prev_y )
			varied++;
		time_bins |= 1u << (now & 15u);
		prev_x = dx;
		prev_y = dy;

		if( events >= 32 && varied >= 12 && now - begin > 1193182ul )
		{
			int bins = 0;
			for( int bit = 0; bit < 16; bit++ )
				if( time_bins & (1u << bit) )
					bins++;
			if( bins >= 5 )
			{
				printf("Mouse movement collected (statistical heuristic; not certified RNG).\n");
				return 1;
			}
		}
	}
	printf("Mouse sample incomplete; finishing with keyboard timing.\n");
	return 0;
}

/* Keyboard timing is the last fallback for the first initialization.
   Fewer events are needed when mouse movement was also observed. */
static bool CollectKeys(SshEntropy &collector, int required)
{
	if( !required )
		return true;

	printf("Press %d irregularly timed keys (one-time setup). Esc cancels.\n", required);
	for( int i = 0; i < required; i++ )
	{
		unsigned long before_tick = PitStamp();
		while( !biosIsKeyReady() )
			;
		unsigned int key = biosKeyRead();
		if( (key & 255u) == 27u || (key & 255u) == 3u )
			return false;

		unsigned char event[10];
		Store32(event, before_tick);
		Store32(event + 4, PitStamp());
		event[8] = (unsigned char)key;
		event[9] = (unsigned char)(key >> 8);
		collector.AddState(event, sizeof(event));
		if( (i + 1) % 8 == 0 )
		{
			printf(".");
			fflush(stdout);
		}
	}
	printf("\n");
	return true;
}

bool SshEntropy::Initialize(SSHCRYPT_RNG &rng, const char *programPath)
{
	unsigned char saved_seed[64];
	unsigned char mixed_seed[64];
	unsigned char next_seed[64];
	bool have_seed = false;
	bool success = false;
	SshEntropy collector;

	if( !SshData::Select(ProgramDrive(programPath)) )
	{
		printf("No accessible C: or program drive for DOSSSH.DAT.\n");
		goto done;
	}
	if( !SshData::LoadSeed(saved_seed, have_seed) )
	{
		printf("DOSSSH.DAT is corrupt or inaccessible; refusing to overwrite state.\n");
		goto done;
	}
	if( have_seed )
		collector.AddState(saved_seed, sizeof(saved_seed));

	CollectMachineState(collector);
	CollectDisk(collector, SshData::Drive(), have_seed ? 4 : 24);
	if( !have_seed )
	{
		/* Cloned disk images and passive machine state can be reproduced.
		 * Try live audio, then an initialized mouse, then keyboard timing. */
		if( !CollectSoundBlaster(collector) )
		{
			unsigned int key_count = 0;
			unsigned int motions = 0;
			int mouse_result = CollectMouse(collector, key_count, motions);
			if( mouse_result < 0 )
				goto done;
			if( mouse_result == 0 )
			{
				int target = motions >= 32u ? 16 : (motions >= 16u ? 24 : 32);
				if( key_count < (unsigned int)target && !CollectKeys(collector, target - (int)key_count) )
					goto done;
			}
		}
	}
	collector.Final(mixed_seed);
	rng.Init(mixed_seed);
	rng.Generate(next_seed, sizeof(next_seed));
	if( !SshData::RotateSeed(next_seed) )
	{
		printf("DOSSSH.DAT update failed; refusing SSH connection.\n");
		goto done;
	}
	success = true;

done:
	SshCrypt::Zero(saved_seed, sizeof(saved_seed));
	SshCrypt::Zero(mixed_seed, sizeof(mixed_seed));
	SshCrypt::Zero(next_seed, sizeof(next_seed));
	if( !success )
		rng.Clear();
	return success;
}
