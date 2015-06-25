// Copyright 2010 fail0verflow <master@fail0verflow.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef GDB_H__
#define GDB_H__

#include <signal.h>
#include "types.h"

#ifdef _WIN32
#define SIGTRAP 5
#define	SIGTERM		15
#define MSG_WAITALL  8
#endif

#define	LS_SIZE	256 * 1024
#define	LSLR	(LS_SIZE - 1)

typedef enum
{
	GDB_BP_TYPE_NONE = 0,
	GDB_BP_TYPE_X,
	GDB_BP_TYPE_R,
	GDB_BP_TYPE_W,
	GDB_BP_TYPE_A
} gdb_bp_type;

bool gdb_init(u32 port);
void gdb_deinit(void);

typedef void event_callback(u32 signal, u32 address);

void gdb_handle_events(event_callback* callback);
int gdb_signal(u32 signal);

int gdb_bp_x(u32 addr);
int gdb_bp_r(u32 addr);
int gdb_bp_w(u32 addr);
int gdb_bp_a(u32 addr);

void gdb_handle_query();
void gdb_handle_set_thread();
void gdb_handle_signal(event_callback* callback);
void gdb_ack();
void gdb_read_registers(u32 reg[130][4]);
void gdb_write_registers(u32 reg[130][4]);
void gdb_read_register(u32 id, u32 reg[4]);
void gdb_write_register(u32 id, u32 reg[4]);
u32 gdb_read_mem(u32 addr, u8* buffer, u32 size);
u32 gdb_write_mem(u32 addr, u8* buffer, u32 size);
void gdb_continue();
void gdb_step();
void gdb_pause();
void gdb_remove_bp(u32 addr, gdb_bp_type type, u32 size);
void gdb_add_bp(u32 addr, gdb_bp_type type, u32 size);
void gdb_kill();

#endif
