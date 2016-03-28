// Copyright (C) 2014 oct0xor
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 2.0.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License 2.0 for more details.
// 
// A copy of the GPL 2.0 should have been included with the program.
// If not, see http ://www.gnu.org/licenses/

#define _WINSOCKAPI_

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <algorithm>
#include <vector>
#include <string>
#include <unordered_map>
#include <set>

#include <ida.hpp>
#include <area.hpp>
#include <ua.hpp>
#include <nalt.hpp>
#include <idd.hpp>
#include <segment.hpp>
#include <dbg.hpp>
#include <allins.hpp>

#include "debmod.h"
#include "include\ps3tmapi.h"

#include "gdb.h"

#ifdef _DEBUG
#define debug_printf ::msg
#else
#define debug_printf(...)
#endif

#define DEBUGGER_NAME "spu3"
#define DEBUGGER_ID_PLAYSTATION_3_SPU (0x8004)
#define PROCESSOR_NAME "spu"

static error_t idaapi idc_threadlst(idc_value_t *argv, idc_value_t *res);
void get_threads_info(void);
void clear_all_bp(uint32 tid);
uint32 read_pc_register(uint32 tid);
uint32 read_lr_register(uint32 tid);
uint32 read_ctr_register(uint32 tid);
int do_step(uint32 tid, uint32 dbg_notification);
bool addr_has_bp(uint32 ea);

static const char idc_threadlst_args[] = {0};

std::vector<SNPS3TargetInfo*> Targets;
std::string TargetName;
HTARGET TargetID;
uint32 ProcessID;
uint32 ThreadID;

bool LaunchTargetPicker = true;
bool AlwaysDC = false;
bool ForceDC = true;
bool WasOriginallyConnected = false;

static bool attaching = false; 
static bool singlestep = false;
static bool continue_from_bp = false;
static bool dabr_is_set = false;
uint32 dabr_addr;
uint8 dabr_type;

eventlist_t events;
SNPS3_DBG_EVENT_DATA target_event;

std::unordered_map<int, std::string> process_names;
std::unordered_map<int, std::string> modules;
std::unordered_map<int, int> main_bpts_map;

std::set<uint32> step_bpts;
std::set<uint32> main_bpts;

static const unsigned char bpt_code[] = {0x7f, 0xe0, 0x00, 0x08};

#define STEP_INTO 15
#define STEP_OVER 16

#define RC_GENERAL 1

struct regval
{
	uint64 lval;
	uint64 rval;
};
typedef struct regval regval;

//--------------------------------------------------------------------------
const char* register_classes[] =
{
    "General registers",
    NULL
};

//--------------------------------------------------------------------------
const char* register_formats[] =
{
    "spu_4_words",
    NULL
};

#define USE_CUSTOM_FORMAT 1
#if USE_CUSTOM_FORMAT
#define REGISTER_FLAGS REGISTER_CUSTFMT
#define REGISTER_DATA_TYPE dt_byte16
#define REGISTER_DATA_FORMAT register_formats

#define GPR_COUNT (128 + 2)

#define SPU_ID_INDEX (128 + 0)
#define PC_INDEX (128 + 1)
#else
#define REGISTER_FLAGS 0
#define REGISTER_DATA_TYPE dt_dword
#define REGISTER_DATA_FORMAT nullptr

#define GPR_COUNT (128 * 4 + 2)

#define SPU_ID_INDEX (128 * 4 + 0)
#define PC_INDEX (128 * 4 + 1)
#endif

char register_names[GPR_COUNT][16] = {0};

//--------------------------------------------------------------------------
register_info_t registers[GPR_COUNT] =
{
    { "r0",     REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r1",     REGISTER_FLAGS | REGISTER_ADDRESS | REGISTER_SP,       RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r2",     REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r3",     REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r4",     REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r5",     REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r6",     REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r7",     REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r8",     REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r9",     REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r10",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r11",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r12",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r13",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r14",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r15",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r16",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r17",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r18",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r19",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r20",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r21",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r22",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r23",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r24",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r25",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r26",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r27",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r28",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r29",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r30",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r31",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },

    { "r32",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r33",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r34",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r35",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r36",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r37",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r38",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r39",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r40",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r41",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r42",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r43",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r44",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r45",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r46",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r47",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r48",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r49",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r50",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r51",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r52",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r53",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r54",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r55",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r56",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r57",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r58",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r59",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r60",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r61",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r62",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r63",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },

    { "r64",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r65",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r66",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r67",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r68",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r69",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r70",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r71",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r72",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r73",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r74",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r75",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r76",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r77",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r78",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r79",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r80",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r81",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r82",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r83",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r84",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r85",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r86",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r87",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r88",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r89",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r90",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r91",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r92",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r93",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r94",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r95",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },

    { "r96",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r97",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r98",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r99",    REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r100",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r101",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r102",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r103",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r104",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r105",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r106",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r107",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r108",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r109",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r110",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r111",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r112",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r113",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r114",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r115",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r116",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r117",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r118",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r119",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r120",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r121",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r122",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r123",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r124",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r125",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r126",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },
    { "r127",   REGISTER_FLAGS | REGISTER_ADDRESS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 },

    { "SPU_ID", REGISTER_ADDRESS | REGISTER_READONLY, RC_GENERAL,  dt_dword,   NULL,   0 },
    { "PC",     REGISTER_ADDRESS | REGISTER_IP,       RC_GENERAL,  dt_dword,   NULL,   0 },
};

#define SPU_ID 0xdeadbabe

uint32 registers_id[] =
{
    SNPS3_spu_gpr_0,
    SNPS3_spu_gpr_1,
    SNPS3_spu_gpr_2,
    SNPS3_spu_gpr_3,
    SNPS3_spu_gpr_4,
    SNPS3_spu_gpr_5,
    SNPS3_spu_gpr_6,
    SNPS3_spu_gpr_7,
    SNPS3_spu_gpr_8,
    SNPS3_spu_gpr_9,
    SNPS3_spu_gpr_10,
    SNPS3_spu_gpr_11,
    SNPS3_spu_gpr_12,
    SNPS3_spu_gpr_13,
    SNPS3_spu_gpr_14,
    SNPS3_spu_gpr_15,
    SNPS3_spu_gpr_16,
    SNPS3_spu_gpr_17,
    SNPS3_spu_gpr_18,
    SNPS3_spu_gpr_19,
    SNPS3_spu_gpr_20,
    SNPS3_spu_gpr_21,
    SNPS3_spu_gpr_22,
    SNPS3_spu_gpr_23,
    SNPS3_spu_gpr_24,
    SNPS3_spu_gpr_25,
    SNPS3_spu_gpr_26,
    SNPS3_spu_gpr_27,
    SNPS3_spu_gpr_28,
    SNPS3_spu_gpr_29,
    SNPS3_spu_gpr_30,
    SNPS3_spu_gpr_31,
    
    SNPS3_spu_gpr_32,
    SNPS3_spu_gpr_33,
    SNPS3_spu_gpr_34,
    SNPS3_spu_gpr_35,
    SNPS3_spu_gpr_36,
    SNPS3_spu_gpr_37,
    SNPS3_spu_gpr_38,
    SNPS3_spu_gpr_39,
    SNPS3_spu_gpr_40,
    SNPS3_spu_gpr_41,
    SNPS3_spu_gpr_42,
    SNPS3_spu_gpr_43,
    SNPS3_spu_gpr_44,
    SNPS3_spu_gpr_45,
    SNPS3_spu_gpr_46,
    SNPS3_spu_gpr_47,
    SNPS3_spu_gpr_48,
    SNPS3_spu_gpr_49,
    SNPS3_spu_gpr_50,
    SNPS3_spu_gpr_51,
    SNPS3_spu_gpr_52,
    SNPS3_spu_gpr_53,
    SNPS3_spu_gpr_54,
    SNPS3_spu_gpr_55,
    SNPS3_spu_gpr_56,
    SNPS3_spu_gpr_57,
    SNPS3_spu_gpr_58,
    SNPS3_spu_gpr_59,
    SNPS3_spu_gpr_60,
    SNPS3_spu_gpr_61,
    SNPS3_spu_gpr_62,
    SNPS3_spu_gpr_63,
    
    SNPS3_spu_gpr_64,
    SNPS3_spu_gpr_65,
    SNPS3_spu_gpr_66,
    SNPS3_spu_gpr_67,
    SNPS3_spu_gpr_68,
    SNPS3_spu_gpr_69,
    SNPS3_spu_gpr_70,
    SNPS3_spu_gpr_71,
    SNPS3_spu_gpr_72,
    SNPS3_spu_gpr_73,
    SNPS3_spu_gpr_74,
    SNPS3_spu_gpr_75,
    SNPS3_spu_gpr_76,
    SNPS3_spu_gpr_77,
    SNPS3_spu_gpr_78,
    SNPS3_spu_gpr_79,
    SNPS3_spu_gpr_80,
    SNPS3_spu_gpr_81,
    SNPS3_spu_gpr_82,
    SNPS3_spu_gpr_83,
    SNPS3_spu_gpr_84,
    SNPS3_spu_gpr_85,
    SNPS3_spu_gpr_86,
    SNPS3_spu_gpr_87,
    SNPS3_spu_gpr_88,
    SNPS3_spu_gpr_89,
    SNPS3_spu_gpr_90,
    SNPS3_spu_gpr_91,
    SNPS3_spu_gpr_92,
    SNPS3_spu_gpr_93,
    SNPS3_spu_gpr_94,
    SNPS3_spu_gpr_95,
    
    SNPS3_spu_gpr_96,
    SNPS3_spu_gpr_97,
    SNPS3_spu_gpr_98,
    SNPS3_spu_gpr_99,
    SNPS3_spu_gpr_100,
    SNPS3_spu_gpr_101,
    SNPS3_spu_gpr_102,
    SNPS3_spu_gpr_103,
    SNPS3_spu_gpr_104,
    SNPS3_spu_gpr_105,
    SNPS3_spu_gpr_106,
    SNPS3_spu_gpr_107,
    SNPS3_spu_gpr_108,
    SNPS3_spu_gpr_109,
    SNPS3_spu_gpr_110,
    SNPS3_spu_gpr_111,
    SNPS3_spu_gpr_112,
    SNPS3_spu_gpr_113,
    SNPS3_spu_gpr_114,
    SNPS3_spu_gpr_115,
    SNPS3_spu_gpr_116,
    SNPS3_spu_gpr_117,
    SNPS3_spu_gpr_118,
    SNPS3_spu_gpr_119,
    SNPS3_spu_gpr_120,
    SNPS3_spu_gpr_121,
    SNPS3_spu_gpr_122,
    SNPS3_spu_gpr_123,
    SNPS3_spu_gpr_124,
    SNPS3_spu_gpr_125,
    SNPS3_spu_gpr_126,
    SNPS3_spu_gpr_127,

    SPU_ID,
	SNPS3_pc,
};

#if USE_CUSTOM_FORMAT
void setup_registers()
{
    static register_info_t default_register_info = { "",     REGISTER_FLAGS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 };
    static register_info_t spu_id_register_info = { "SPU_ID", REGISTER_ADDRESS | REGISTER_READONLY, RC_GENERAL,  dt_dword,   NULL,   0 };
    static register_info_t pc_register_info = { "PC",     REGISTER_ADDRESS | REGISTER_IP,       RC_GENERAL,  dt_dword,   NULL,   0 };

    for (int i = 0; i < 128; ++i)
    {
        // setup register names
        qsnprintf(register_names[i], 16, "r%d", i);
        // setup register info
        registers[i] = default_register_info; registers[i].name = register_names[i]; registers[i].flags |= (REGISTER_ADDRESS | REGISTER_NOLF | ((i == 1) ? REGISTER_SP : 0));
    }

    registers[SPU_ID_INDEX] = spu_id_register_info;
    registers[PC_INDEX] = pc_register_info;
}
#else
void setup_registers()
{
    static register_info_t default_register_info = { "",     REGISTER_FLAGS,                     RC_GENERAL,  REGISTER_DATA_TYPE,  REGISTER_DATA_FORMAT,   0 };
    static register_info_t spu_id_register_info = { "SPU_ID", REGISTER_ADDRESS | REGISTER_READONLY, RC_GENERAL,  dt_dword,   NULL,   0 };
    static register_info_t pc_register_info = { "PC",     REGISTER_ADDRESS | REGISTER_IP,       RC_GENERAL,  dt_dword,   NULL,   0 };

    for (int i = 0; i < 128; ++i)
    {
        // setup register names
        qsnprintf(register_names[i * 4 + 0], 16, "r%d", i);
        qsnprintf(register_names[i * 4 + 1], 16, "r%d_1", i);
        qsnprintf(register_names[i * 4 + 2], 16, "r%d_2", i);
        qsnprintf(register_names[i * 4 + 3], 16, "r%d_3", i);
        // setup register info
        registers[i * 4 + 0] = default_register_info; registers[i * 4 + 0].name = register_names[i * 4 + 0]; registers[i * 4 + 0].flags |= (REGISTER_ADDRESS | REGISTER_NOLF | ((i == 1) ? REGISTER_SP : 0));
        registers[i * 4 + 1] = default_register_info; registers[i * 4 + 1].name = register_names[i * 4 + 1]; registers[i * 4 + 1].flags |= (REGISTER_NOLF);
        registers[i * 4 + 2] = default_register_info; registers[i * 4 + 2].name = register_names[i * 4 + 2]; registers[i * 4 + 2].flags |= (REGISTER_NOLF);
        registers[i * 4 + 3] = default_register_info; registers[i * 4 + 3].name = register_names[i * 4 + 3];
    }

    registers[SPU_ID_INDEX] = spu_id_register_info;
    registers[PC_INDEX] = pc_register_info;
}
#endif
//-------------------------------------------------------------------------
static inline uint32 bswap32(uint32 x)
{
	return ( (x << 24) & 0xff000000 ) |
           ( (x <<  8) & 0x00ff0000 ) |
           ( (x >>  8) & 0x0000ff00 ) |
           ( (x >> 24) & 0x000000ff );
}

static inline uint64 bswap64(uint64 x)
{
	return ( (x << 56) & 0xff00000000000000ULL ) |
           ( (x << 40) & 0x00ff000000000000ULL ) |
           ( (x << 24) & 0x0000ff0000000000ULL ) |
           ( (x <<  8) & 0x000000ff00000000ULL ) |
           ( (x >>  8) & 0x00000000ff000000ULL ) |
           ( (x >> 24) & 0x0000000000ff0000ULL ) |
           ( (x >> 40) & 0x000000000000ff00ULL ) |
           ( (x >> 56) & 0x00000000000000ffULL );
}

bool GetHostnames(const char* input, std::string& ipOut, std::string& dnsNameOut)
{
	WSADATA wsaData;
	int iResult;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		return false;
	}

	sockaddr_in remotemachine;
	char hostname[NI_MAXHOST];

	remotemachine.sin_family = AF_INET;
	remotemachine.sin_addr.s_addr = inet_addr(input);

	// IP->Hostname
	DWORD dwRetVal = getnameinfo((SOCKADDR *)&remotemachine, 
		sizeof(sockaddr), 
		hostname, 
		NI_MAXHOST, 
		NULL, 
		0, 
		NI_NAMEREQD);

	if (dwRetVal == 0)
	{
		dnsNameOut = hostname;
		return true;
	}

	// Hostname -> IP
	struct hostent *remoteHost;
	remoteHost = gethostbyname(input);

	int i = 0;
	struct in_addr addr = { 0 };
	if (remoteHost && remoteHost->h_addrtype == AF_INET)
	{
		if (remoteHost->h_addr_list[0] != 0)
		{
			addr.s_addr = *(u_long *) remoteHost->h_addr_list[0];
			ipOut = inet_ntoa(addr);
			return true;
		}
	}

	WSACleanup();
	return false;
}

static void handle_events(u32 signal, u32 address)
{
    debug_printf("handle_events\n");

    debug_event_t ev;

    switch (signal)
    {
    case SIGABRT:
        {
            if (attaching)
            {
                debug_printf("SPU3_DBG_EVENT_PROCESS_START\n");

                attaching = false;

                ev.eid     = PROCESS_START;
                ev.pid     = ProcessID;
                ev.tid     = NO_THREAD;
                ev.ea      = BADADDR;
                ev.handled = true;

                qstrncpy(ev.modinfo.name, "SPU3", sizeof(ev.modinfo.name));
                ev.modinfo.base = 0;
                ev.modinfo.size = 0;
                ev.modinfo.rebase_to = BADADDR;

                events.enqueue(ev, IN_BACK);

                ev.eid     = PROCESS_SUSPEND;
                ev.pid     = ProcessID;

                events.enqueue(ev, IN_BACK);

                break;
            }
        }
        break;
    case SIGSEGV:
        {
            debug_printf("SPU3_DBG_EVENT_PROCESS_EXIT\n");

            ev.eid     = PROCESS_EXIT;
            ev.pid     = ProcessID;
            ev.tid     = NO_THREAD;
            ev.ea      = BADADDR;
            ev.handled = true;
            ev.exit_code = 0;

            events.enqueue(ev, IN_BACK);
        }
        break;
    case SIGTRAP:
        {
            debug_printf("SPU3_DBG_EVENT_TRAP\n");

            if (continue_from_bp == true)
            {
                debug_printf("\tContinuing from breakpoint...\n");
                continue_from_bp = false;
            }
            else if (singlestep == true)
            {
                debug_printf("\tSingle step...\n");

                ev.eid     = STEP;
                ev.pid     = ProcessID;
                ev.tid     = ThreadID;
                ev.ea      = address;
                ev.handled = true;
                ev.exc.code = 0;
                ev.exc.can_cont = true;
                ev.exc.ea = BADADDR;

                events.enqueue(ev, IN_BACK);

                continue_from_bp = false;
                singlestep = false;
            }
            else if (!addr_has_bp(address))
            {
                ev.eid     = PROCESS_SUSPEND;
                ev.pid     = ProcessID;
                ev.tid     = ThreadID;
                ev.ea      = address;
                ev.handled = true;

                events.enqueue(ev, IN_BACK);
            }
            else
            {
                debug_printf("\tBreakpoint...\n");

                ev.eid     = BREAKPOINT;
                ev.pid     = ProcessID;
                ev.tid     = ThreadID;
                ev.ea      = address;
                ev.handled = true;
                ev.bpt.hea = BADADDR;
                ev.bpt.kea = BADADDR;
                ev.exc.ea  = BADADDR;

                events.enqueue(ev, IN_BACK);
            }

            for (std::set<uint32>::const_iterator step_it = step_bpts.begin(); step_it != step_bpts.end(); ++step_it)
            {
                uint32 addr = *step_it;

                if (!addr_has_bp(addr))
                {
                    main_bpts_map.erase(addr);

                    gdb_remove_bp(addr, GDB_BP_TYPE_X, 4);
                    debug_printf("step bpt cleared: 0x%08X\n", (uint32)addr);
                }
            }
            step_bpts.clear();
        }
        break;
    default:
        debug_printf("Unknown event signal: 0x%08X\n");
        break;
    }
}

//--------------------------------------------------------------------------
// Initialize debugger
static bool idaapi init_debugger(const char *hostname, int port_num, const char *password)
{
    debug_printf("init_debugger\n");

    if (!gdb_init(port_num))
        return false;

	set_idc_func_ex("threadlst", idc_threadlst, idc_threadlst_args, 0);

	return true;
}

//--------------------------------------------------------------------------
// Terminate debugger
static bool idaapi term_debugger(void)
{
    debug_printf("term_debugger\n");

    gdb_deinit();

	set_idc_func_ex("threadlst", NULL, idc_threadlst_args, 0);

	return true;
}

//--------------------------------------------------------------------------
int idaapi process_get_info(int n, process_info_t *info)
{
    if (n > 0)
        return 0;

    info->pid = 0;
    qstrncpy(info->name, "SPU3", sizeof(info->name));

    return 1;
}

static const char *get_state_name(uint32 State)
{
	switch ( State )
	{
		case SNPS3_PPU_IDLE:			return "IDLE";
		case SNPS3_PPU_RUNNABLE:        return "RUNNABLE";
		case SNPS3_PPU_ONPROC:			return "ONPROC";
		case SNPS3_PPU_SLEEP:			return "SLEEP";
		case SNPS3_PPU_SUSPENDED:       return "SUSPENDED";
		case SNPS3_PPU_SLEEP_SUSPENDED: return "SLEEP_SUSPENDED";
		case SNPS3_PPU_STOP:			return "STOP";
		case SNPS3_PPU_ZOMBIE:			return "ZOMBIE";
		case SNPS3_PPU_DELETED:			return "DELETED";
		default:						return "???";
	}
}

static error_t idaapi idc_threadlst(idc_value_t *argv, idc_value_t *res)
{
	get_threads_info();
	return eOk;
}

void get_threads_info(void)
{
    debug_printf("get_threads_info\n");

    if (attaching == true) 
    {
        debug_event_t ev;

        attaching = false;

        ThreadID = 1;

        ev.eid     = THREAD_START;
        ev.pid     = ProcessID;
        ev.tid     = ThreadID;
        ev.ea      = read_pc_register(ThreadID);
        ev.handled = true;

        events.enqueue(ev, IN_BACK);

        clear_all_bp(0);

        // set break point on current instruction
        gdb_add_bp(ev.ea, GDB_BP_TYPE_X, 4);
        step_bpts.insert(ev.ea);
    }
}

int get_thread_state(uint32 tid)
{
	SNRESULT snr = SN_S_OK;
	uint32 ThreadInfoSize = 1024;
	SNPS3_PPU_THREAD_INFO *ThreadInfo;
	int state = 0;

	return state;
}

void get_modules_info(void)
{
}

void clear_all_bp(uint32 tid)
{
}

void bp_list(void)
{
}

bool addr_has_bp(uint32 ea)
{
    return (main_bpts.end() != main_bpts.find(ea));
}

uint32 debug_breakpoints[][32] =
{
    {0},
    {0x9FF8, 0xA020, 0xA054, 0xA080, 0},
    {0x97B8, 0x97E0, 0x9834, 0x9874, 0},
    {0},
    {0},
    {0xA3C8, 0xA3F0, 0xA424, 0xA450, 0},
    {0x9D60, 0x9D88, 0x9DBC, 0x9DE8, 0},
    {0xBCD8, 0xBD00, 0xBD34, 0xBD60, 0},
    {0xAD68, 0xAD90, 0xADE4, 0xAE24, 0},
    {0x94B8, 0x94E0, 0x94FC, 0x9534, 0},
    {0xB3A8, 0xB3D0, 0xB3F8, 0xB420, 0},
    {0xAA10, 0xAA38, 0xAA84, 0xAAC4, 0},
    {0xB104, 0xB130, 0xB158, 0xB180, 0},
    {0xA6AC, 0xA6D8, 0xA724, 0xA764, 0},
    {0xBA64, 0xBA90, 0xBAA4, 0xBAD0, 0},
    {0x915C, 0x9188, 0x91EC, 0x91F0, 0},
    {0x94B8, 0x94E0, 0x95CC, 0x9604, 0},
    {0xB850, 0xB878, 0xB88C, 0xB8B8, 0},
    {0x8E78, 0x8EA0, 0x8EDC, 0x8F1C, 0},
    {0xB638, 0xB660, 0xB674, 0xB6A0, 0},
    {0x8B98, 0x8BC0, 0x8BFC, 0x8C3C, 0},
    {0x3450, 0},
    {0x7158, 0},
};

//--------------------------------------------------------------------------
// Start an executable to debug
static int idaapi deci3_start_process(const char *path,
                              const char *args,
                              const char *startdir,
                              int dbg_proc_flags,
                              const char *input_path,
                              uint32 input_file_crc32)
{
	SNRESULT snr = SN_S_OK;
	//uint64 tid;

	debug_printf("start_process\n");
	debug_printf("path: %s\n", path);

    ProcessID = 0;

    attaching = true;

    debug_event_t ev;

    ev.eid     = PROCESS_START;
    ev.pid     = ProcessID;
    ev.tid     = NO_THREAD;
    ev.ea      = BADADDR;
    ev.handled = true;

    qstrncpy(ev.modinfo.name, "SPU3", sizeof(ev.modinfo.name));
    ev.modinfo.base = 0;
    ev.modinfo.size = 0;
    ev.modinfo.rebase_to = BADADDR;

    events.enqueue(ev, IN_BACK);

    get_threads_info();
    get_modules_info();
    clear_all_bp(-1);

#if 1
    int i = 0;
    uint32 breakpoint;
    while (breakpoint = debug_breakpoints[0x16][i++])
    {
        gdb_add_bp(breakpoint, GDB_BP_TYPE_X, 4);
        main_bpts.insert(breakpoint);
    }

    //gdb_add_bp(0x3F30, GDB_BP_TYPE_X, 4);
    //gdb_add_bp(0x4140, GDB_BP_TYPE_X, 4);
    //gdb_add_bp(0x44F8, GDB_BP_TYPE_X, 4);

    //gdb_add_bp(0x4500, GDB_BP_TYPE_X, 4);
    //gdb_add_bp(0x4710, GDB_BP_TYPE_X, 4);
    //gdb_add_bp(0x4AD0, GDB_BP_TYPE_X, 4);

    //gdb_add_bp(0x76C0, GDB_BP_TYPE_X, 4);
    //gdb_add_bp(0x89C8, GDB_BP_TYPE_X, 4);

    //gdb_add_bp(0xB3F8, GDB_BP_TYPE_X, 4);

    //main_bpts.insert(0x3F30);
    //main_bpts.insert(0x4140);
    //main_bpts.insert(0x44F8);

    //main_bpts.insert(0x4500);
    //main_bpts.insert(0x4710);
    //main_bpts.insert(0x4AD0);

    //main_bpts.insert(0x76C0);
    //main_bpts.insert(0x89C8);

    //main_bpts.insert(0xB3F8);
#endif

    gdb_continue();

/*
    ev.eid     = PROCESS_SUSPEND;
    ev.pid     = ProcessID;

    events.enqueue(ev, IN_BACK);

    gdb_handle_events(handle_events);
*/

	debug_printf("ProcessID: 0x%X\n", ProcessID);

	/*debug_event_t ev;
	ev.eid     = PROCESS_START;
	ev.pid     = ProcessID;
	ev.tid     = NO_THREAD;
	ev.ea      = BADADDR;
	ev.handled = true;

    qstrncpy(ev.modinfo.name, path, sizeof(ev.modinfo.name));
    ev.modinfo.base = 0x10200;
    ev.modinfo.size = 0;
    ev.modinfo.rebase_to = BADADDR;

	events.enqueue(ev, IN_BACK);*/

	return 1;
}

//--------------------------------------------------------------------------
// Attach to an existing running process
int idaapi deci3_attach_process(pid_t pid, int event_id)
{
    debug_printf("deci3_attach_process\n");

	//block the process until all generated events are processed
	attaching = true;

	ProcessID = pid;

	debug_event_t ev;
	ev.eid     = PROCESS_START;
	ev.pid     = ProcessID;
	ev.tid     = NO_THREAD;
	ev.ea      = BADADDR;
	ev.handled = true;

    qstrncpy(ev.modinfo.name, process_names[ProcessID].c_str(), sizeof(ev.modinfo.name));
    ev.modinfo.base = 0x10200;
    ev.modinfo.size = 0;
    ev.modinfo.rebase_to = BADADDR;

	events.enqueue(ev, IN_BACK);

	get_threads_info();
	get_modules_info();
	clear_all_bp(-1);

    ev.eid     = PROCESS_ATTACH;
    ev.pid     = ProcessID;
    ev.tid     = NO_THREAD;
    ev.ea      = BADADDR;
    ev.handled = true;

    qstrncpy(ev.modinfo.name, process_names[ProcessID].c_str(), sizeof(ev.modinfo.name));
    ev.modinfo.base = 0x10200;
    ev.modinfo.size = 0;
    ev.modinfo.rebase_to = BADADDR;

    events.enqueue(ev, IN_BACK);

	process_names.clear();

    return 1;
}

//--------------------------------------------------------------------------
int idaapi deci3_detach_process(void)
{
    debug_printf("deci3_detach_process\n");

    gdb_continue();

    gdb_deinit();

	debug_event_t ev;
    ev.eid     = PROCESS_DETACH;
    ev.pid     = ProcessID;

    events.enqueue(ev, IN_BACK);

    return 1;
}

//-------------------------------------------------------------------------
void idaapi rebase_if_required_to(ea_t new_base)
{
    debug_printf("rebase_if_required_to: 0x%llX\n", (uint64)new_base);
}

//--------------------------------------------------------------------------
int idaapi prepare_to_pause_process(void)
{
    debug_printf("prepare_to_pause_process\n");

    //gdb_pause();

	debug_event_t ev;
	ev.eid     = PROCESS_SUSPEND;
	ev.pid     = ProcessID;

    events.enqueue(ev, IN_BACK);

	return 1;
}

//--------------------------------------------------------------------------
int idaapi deci3_exit_process(void)
{
    debug_printf("deci3_exit_process\n");

    gdb_kill();

    debug_event_t ev;
    ev.eid     = PROCESS_EXIT;
    ev.pid     = ProcessID;
    ev.tid     = NO_THREAD;
    ev.ea      = BADADDR;
	ev.exit_code = 0;
    ev.handled = true;

    events.enqueue(ev, IN_BACK);

	return 1;
}

#ifdef _DEBUG

static const char *get_event_name(event_id_t id)
{
	switch ( id )
	{
		case NO_EVENT:        return "NO_EVENT";
		case THREAD_START:    return "THREAD_START";
		case THREAD_EXIT:     return "THREAD_EXIT";
		case PROCESS_ATTACH:  return "PROCESS_ATTACH";
		case PROCESS_DETACH:  return "PROCESS_DETACH";
		case PROCESS_START:   return "PROCESS_START";
		case PROCESS_SUSPEND: return "PROCESS_SUSPEND";
		case PROCESS_EXIT:    return "PROCESS_EXIT";
		case LIBRARY_LOAD:    return "LIBRARY_LOAD";
		case LIBRARY_UNLOAD:  return "LIBRARY_UNLOAD";
		case BREAKPOINT:      return "BREAKPOINT";
		case STEP:            return "STEP";
		case EXCEPTION:       return "EXCEPTION";
		case INFORMATION:     return "INFORMATION";
		case SYSCALL:         return "SYSCALL";
		case WINMESSAGE:      return "WINMESSAGE";
		default:              return "???";
	}
}

#endif

//--------------------------------------------------------------------------
// Get a pending debug event and suspend the process
gdecode_t idaapi get_debug_event(debug_event_t *event, int ida_is_idle)
{
	if ( event == NULL )
		return GDE_NO_EVENT;

	while ( true )
	{
        gdb_handle_events(handle_events);

		if ( events.retrieve(event) )
		{
#ifdef _DEBUG

			if (event->eid == BREAKPOINT && event->bpt.hea != BADADDR)
			{
				debug_printf("get_debug_event: BREAKPOINT (HW)\n");
			}
            else
            {
				debug_printf("get_debug_event: %s\n", get_event_name(event->eid));
			}

#endif

			if (event->eid == PROCESS_ATTACH)
			{
				attaching = false;
			}

			if (attaching == false) 
			{
			}

			return (events.empty()) ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
		}

		if (events.empty())
			break;
	}

	if (attaching == false)
	{
	}

	return GDE_NO_EVENT;
}

//--------------------------------------------------------------------------
// Continue after handling the event
int idaapi continue_after_event(const debug_event_t *event)
{
    if ( event == NULL )
        return false;

    if (!events.empty())
        return true;

#ifdef _DEBUG

    if (event->eid == BREAKPOINT && event->bpt.hea != BADADDR)
    {
        debug_printf("continue_after_event: BREAKPOINT (HW)\n");
    }
    else
    {
        debug_printf("continue_after_event: %s\n", get_event_name(event->eid));
    }

#endif

    if (event->eid == PROCESS_ATTACH || event->eid == PROCESS_SUSPEND || event->eid == STEP || event->eid == BREAKPOINT)
        gdb_continue();

    return true;
}

//--------------------------------------------------------------------------
// Continue after handling the event
int idaapi continue_after_event_old(const debug_event_t *event)
{
	if ( event == NULL )
		return false;

#ifdef _DEBUG

	if (event->eid == BREAKPOINT && event->bpt.hea != BADADDR)
	{
		debug_printf("continue_after_event: BREAKPOINT (HW)\n");
	}
    else
    {
		debug_printf("continue_after_event: %s\n", get_event_name(event->eid));
	}

#endif

    gdb_handle_events(handle_events);

	if (event->eid == PROCESS_ATTACH || event->eid == PROCESS_SUSPEND || event->eid == STEP || event->eid == BREAKPOINT)
    {
        bool user_bpt = addr_has_bp(event->ea);
		if ((event->eid == BREAKPOINT || event->eid == STEP) && user_bpt)
		{
            gdb_remove_bp(event->ea, GDB_BP_TYPE_X,  4);

            bool was_stepping = singlestep;

            if (!was_stepping)
            {
                do_step(event->tid, get_running_notification());

                continue_from_bp = true;

                //gdb_handle_events(handle_events);
            }

            gdb_continue();

            gdb_handle_events(handle_events);

            gdb_add_bp(event->ea, GDB_BP_TYPE_X,  4);

            if (!was_stepping)
            {
                gdb_continue();
            }
		}
        else
        {
            gdb_continue();
        }
	}

	return true;
}

//--------------------------------------------------------------------------
void idaapi stopped_at_debug_event(bool dlls_added)
{
}

//--------------------------------------------------------------------------
int idaapi thread_suspend(thid_t tid)
{
	debug_printf("thread_suspend: tid = 0x%llX\n", (uint64)tid);

    gdb_pause();

	return 1;
}

//--------------------------------------------------------------------------
int idaapi thread_continue(thid_t tid)
{
	debug_printf("thread_continue: tid = 0x%llX\n", (uint64)tid);

    gdb_continue();

	return 1;
}

#define G_STR_SIZE 256

enum spu_instructions
{
    SPU_a  =   58,
    SPU_absdb  =   150,
    SPU_addx  =   108,
    SPU_ah  =   76,
    SPU_ahi  =   9,
    SPU_ai  =   8,
    SPU_and  =   70,
    SPU_andbi  =   7,
    SPU_andc  =   59,
    SPU_andhi  =   6,
    SPU_andi  =   5,
    SPU_avgb  =   84,
    SPU_bg  =   41,
    SPU_bgx  =   97,
    SPU_bi  =   109,
    SPU_bihnz  =   93,
    SPU_bihz  =   92,
    SPU_binz  =   91,
    SPU_bisl  =   110,
    SPU_bisled  =   112,
    SPU_biz  =   90,
    SPU_br  =   171,
    SPU_bra  =   166,
    SPU_brasl  =   169,
    SPU_brhnz  =   163,
    SPU_brhz  =   161,
    SPU_brnz  =   159,
    SPU_brsl  =   172,
    SPU_brz  =   157,
    SPU_cbd  =   180,
    SPU_cbx  =   139,
    SPU_cdd  =   183,
    SPU_cdx  =   142,
    SPU_ceq  =   124,
    SPU_ceqb  =   138,
    SPU_ceqbi  =   27,
    SPU_ceqh  =   131,
    SPU_ceqhi  =   26,
    SPU_ceqi  =   25,
    SPU_cflts  =   195,
    SPU_cfltu  =   196,
    SPU_cg  =   60,
    SPU_cgt  =   39,
    SPU_cgtb  =   44,
    SPU_cgtbi  =   17,
    SPU_cgth  =   42,
    SPU_cgthi  =   16,
    SPU_cgti  =   15,
    SPU_cgx  =   96,
    SPU_chd  =   181,
    SPU_chx  =   140,
    SPU_clgt  =   69,
    SPU_clgtb  =   83,
    SPU_clgtbi  =   21,
    SPU_clgth  =   65,
    SPU_clgthi  =   20,
    SPU_clgti  =   19,
    SPU_clz  =   62,
    SPU_cntb  =   66,
    SPU_csflt  =   197,
    SPU_cuflt  =   198,
    SPU_cwd  =   182,
    SPU_cwx  =   141,
    SPU_dfa  =   80,
    SPU_dfceq  =   126,
    SPU_dfcgt  =   72,
    SPU_dfcmeq  =   133,
    SPU_dfcmgt  =   79,
    SPU_dfm  =   82,
    SPU_dfma  =   101,
    SPU_dfms  =   102,
    SPU_dfnma  =   104,
    SPU_dfnms  =   103,
    SPU_dfs  =   81,
    SPU_dftsv  =   178,
    SPU_dsync  =   32,
    SPU_eqv  =   43,
    SPU_fa  =   73,
    SPU_fceq  =   125,
    SPU_fcgt  =   71,
    SPU_fcmeq  =   132,
    SPU_fcmgt  =   78,
    SPU_fesd  =   45,
    SPU_fi  =   86,
    SPU_fm  =   75,
    SPU_fma  =   155,
    SPU_fms  =   156,
    SPU_fnms  =   154,
    SPU_frds  =   47,
    SPU_frest  =   121,
    SPU_frsqest  =   122,
    SPU_fs  =   74,
    SPU_fscrrd  =   107,
    SPU_fscrwr  =   123,
    SPU_fsm  =   117,
    SPU_fsmb  =   119,
    SPU_fsmbi  =   162,
    SPU_fsmh  =   118,
    SPU_gb  =   114,
    SPU_gbb  =   116,
    SPU_gbh  =   115,
    SPU_hbr  =   113,
    SPU_hbra  =   192,
    SPU_hbrr  =   194,
    SPU_heq  =   89,
    SPU_heqi  =   28,
    SPU_hgt  =   37,
    SPU_hgti  =   18,
    SPU_hlgt  =   85,
    SPU_hlgti  =   22,
    SPU_il  =   165,
    SPU_ila  =   193,
    SPU_ilh  =   160,
    SPU_ilhu  =   173,
    SPU_iohl  =   167,
    SPU_iret  =   111,
    SPU_lnop  =   30,
    SPU_lqa  =   170,
    SPU_lqd  =   11,
    SPU_lqr  =   168,
    SPU_lqx  =   127,
    SPU_lr  =   199,
    SPU_mfspr  =   34,
    SPU_mpy  =   61,
    SPU_mpya  =   153,
    SPU_mpyh  =   128,
    SPU_mpyhh  =   129,
    SPU_mpyhha  =   99,
    SPU_mpyhhau  =   100,
    SPU_mpyhhu  =   136,
    SPU_mpyi  =   23,
    SPU_mpys  =   130,
    SPU_mpyu  =   38,
    SPU_mpyui  =   24,
    SPU_mtspr  =   87,
    SPU_nand  =   68,
    SPU_nop  =   33,
    SPU_nor  =   120,
    SPU_or  =   40,
    SPU_orbi  =   2,
    SPU_orc  =   77,
    SPU_orhi  =   1,
    SPU_ori  =   0,
    SPU_orx  =   149,
    SPU_rchcnt  =   36,
    SPU_rdch  =   35,
    SPU_rot  =   48,
    SPU_roth  =   52,
    SPU_rothi  =   188,
    SPU_rothm  =   53,
    SPU_rothmi  =   189,
    SPU_roti  =   184,
    SPU_rotm  =   49,
    SPU_rotma  =   50,
    SPU_rotmah  =   54,
    SPU_rotmahi  =   190,
    SPU_rotmai  =   186,
    SPU_rotmi  =   185,
    SPU_rotqbi  =   143,
    SPU_rotqbii  =   179,
    SPU_rotqby  =   146,
    SPU_rotqbybi  =   134,
    SPU_rotqbyi  =   176,
    SPU_rotqmbi  =   144,
    SPU_rotqmbii  =   174,
    SPU_rotqmby  =   147,
    SPU_rotqmbybi  =   135,
    SPU_rotqmbyi  =   177,
    SPU_selb  =   151,
    SPU_sf  =   105,
    SPU_sfh  =   56,
    SPU_sfhi  =   4,
    SPU_sfi  =   3,
    SPU_sfx  =   95,
    SPU_shl  =   51,
    SPU_shlh  =   55,
    SPU_shlhi  =   57,
    SPU_shli  =   187,
    SPU_shlqbi  =   145,
    SPU_shlqbii  =   191,
    SPU_shlqby  =   148,
    SPU_shlqbybi  =   137,
    SPU_shlqbyi  =   175,
    SPU_shufb  =   152,
    SPU_stop  =   29,
    SPU_stopd  =   94,
    SPU_stqa  =   158,
    SPU_stqd  =   10,
    SPU_stqr  =   164,
    SPU_stqx  =   98,
    SPU_sumb  =   46,
    SPU_sync  =   31,
    SPU_wrch  =   88,
    SPU_xor  =   106,
    SPU_xorbi  =   14,
    SPU_xorhi  =   13,
    SPU_xori  =   12,
    SPU_xsbh  =   67,
    SPU_xshw  =   64,
    itype_xswd  =   63,
};

//-------------------------------------------------------------------------
int do_step(uint32 tid, uint32 dbg_notification)
{
    debug_printf("do_step\n");

    char mnem[G_STR_SIZE] = {0};

	ea_t ea = read_pc_register(tid);

    mnem[0] = 0;

    bool unconditional_noret = false;

	ea_t next_addr = ea + 4;
    ea_t resolved_addr = BADADDR;
    if (decode_insn(ea))
    {
        u32 reg[4];

        insn_t l_cmd = cmd;
        switch (l_cmd.itype)
        {
        case SPU_bi:
            {
                unconditional_noret = true;
                gdb_read_register(l_cmd.Op1.reg, reg);
                resolved_addr = reg[0] & ~3;
            }
            break;
        case SPU_bihnz:
        case SPU_bihz:
        case SPU_binz:
        case SPU_bisl:
        case SPU_bisled:
        case SPU_biz:
            {
                gdb_read_register(l_cmd.Op2.reg, reg);
                resolved_addr = reg[0] & ~3;
            }
            break;
        case SPU_br:
        case SPU_bra:
            {
                unconditional_noret = true;
                resolved_addr = l_cmd.Op1.addr & ~3;
            }
            break;
        case SPU_brasl:
        case SPU_brhnz:
        case SPU_brhz:
        case SPU_brnz:
        case SPU_brsl:
        case SPU_brz:
            {
                resolved_addr = l_cmd.Op2.addr & ~3;
            }
            break;
        default:
            {
            }
            break;
        }

        // get mnemonic
        ua_mnem(ea, mnem, sizeof(mnem));

        //debug_printf("do_step:\n");
        debug_printf("\tnext address: %08llX - resolved address: %08llX - decoded mnemonic: %s\n", (uint64)next_addr, (uint64)resolved_addr, mnem);
    }

    uint32 instruction;
    if (BADADDR != next_addr && (BADADDR == resolved_addr || !unconditional_noret))
    {
        gdb_add_bp(next_addr, GDB_BP_TYPE_X, 4);
        step_bpts.insert(next_addr);
    }

    if (BADADDR != resolved_addr && (unconditional_noret || STEP_OVER != dbg_notification))
    {
        gdb_add_bp(resolved_addr, GDB_BP_TYPE_X, 4);
        step_bpts.insert(resolved_addr);
    }

    return 1;
}

//--------------------------------------------------------------------------
// Run one instruction in the thread
int idaapi thread_set_step(thid_t tid)
{
    debug_printf("thread_set_step\n");

	int dbg_notification;
	int result = 0;

	dbg_notification = get_running_notification();

	if (dbg_notification == STEP_INTO || dbg_notification == STEP_OVER)
    {
		result = do_step(tid, dbg_notification);
		singlestep = true;
	}

	return result;
}

//-------------------------------------------------------------------------
uint32 read_pc_register(uint32 tid) 
{
    u32 reg[4];
    gdb_read_register(0x81, reg);

    return reg[0];
}

uint32 read_lr_register(uint32 tid) 
{
    u32 reg[4];
    gdb_read_register(0x00, reg);

    return reg[0];
}

uint32 read_ctr_register(uint32 tid) 
{
	SNRESULT snr = SN_S_OK;
	uint32 reg = SNPS3_ctr;
	byte result[SNPS3_REGLEN];

	return bswap32(*(uint32 *)(result + 4));
}

//--------------------------------------------------------------------------
// Read thread registers
int idaapi read_registers(thid_t tid, int clsmask, regval_t *values)
{
    if ( values == NULL ) 
    {
        debug_printf("NULL ptr detected !\n");
        return 0;
    }

    debug_printf("read_registers\n");

    u32 reg[130][4] = {0};
    gdb_read_registers(reg);

    for (u32 i = 0; i < 128; ++i)
    {
#if USE_CUSTOM_FORMAT
        values[i].set_bytes((u8*)reg[i], 16);
#else
        values[i * 4 + 0].set_int(reg[i][0]);
        values[i * 4 + 1].set_int(reg[i][1]);
        values[i * 4 + 2].set_int(reg[i][2]);
        values[i * 4 + 3].set_int(reg[i][3]);
#endif
    }

    // SPU_ID
    values[SPU_ID_INDEX].set_int(reg[0x80][0]);
    //PC
    values[PC_INDEX].set_int(reg[0x81][0]);

	return 1;
}

//--------------------------------------------------------------------------
// Write one thread register
int idaapi write_register(thid_t tid, int reg_idx, const regval_t *value)
{
    debug_printf("write_register\n");

    u32 reg[4] = {0};

    if (reg_idx < (GPR_COUNT - 2))
    {
        gdb_read_register(reg_idx / 4, reg);

#if USE_CUSTOM_FORMAT
        u32* in_reg = (u32*)value->get_data();
        reg[0] = in_reg[0];
        reg[1] = in_reg[1];
        reg[2] = in_reg[2];
        reg[3] = in_reg[3];
#else
        reg[reg_idx & 3] = value->ival & 0xFFFFFFFF;
        //reg[1] = (value->ival >> 32) & 0xFFFFFFFF;
        //reg[2] = 0;
        //reg[3] = 0;
#endif

        gdb_write_register(reg_idx / 4, reg);
    }
    else if (reg_idx < GPR_COUNT)
    {
        reg[0] = (u32)value->ival & 0xFFFFFFFF;

        gdb_write_register(reg_idx / 4 + reg_idx & 3, reg);
    }
    else
    {
        return 0;
    }

    return 1;
}

//--------------------------------------------------------------------------
// Get information on the memory areas
// The debugger module fills 'areas'. The returned vector MUST be sorted.
// Returns:
//   -3: use idb segmentation
//   -2: no changes
//   -1: the process does not exist anymore
//    0: failed
//    1: new memory layout is returned
int idaapi get_memory_info(meminfo_vec_t &areas)
{
    debug_printf("get_memory_info\n");

	memory_info_t info;

	info.startEA = 0;
	info.endEA = LS_SIZE; // 0xFFFF0000;
	info.name = NULL;
	info.sclass = NULL;
	info.sbase = 0;
	info.bitness = 1;
	info.perm = 0; // SEGPERM_EXEC / SEGPERM_WRITE / SEGPERM_READ
	
	areas.push_back(info);

	return 1;
}

//--------------------------------------------------------------------------
// Read process memory
ssize_t idaapi read_memory(ea_t ea, void *buffer, size_t size)
{
    debug_printf("read_memory\n");

    return gdb_read_mem(ea, (u8*)buffer, size);
}

//--------------------------------------------------------------------------
// Write process memory
ssize_t idaapi write_memory(ea_t ea, const void *buffer, size_t size)
{
    debug_printf("write_memory\n");

    return gdb_write_mem(ea, (u8*)buffer, size);
}

//--------------------------------------------------------------------------
int idaapi is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
    debug_printf("is_ok_bpt\n");

	switch(type)
	{
		case BPT_SOFT:
			{
				debug_printf("Software breakpoint\n");

                if (main_bpts.size() >= 10)
                    return BPT_TOO_MANY;

				return BPT_OK;
			}
			break;

		case BPT_EXEC:
			{
				debug_printf("Execute instruction\n");

                if (main_bpts.size() >= 10)
                    return BPT_TOO_MANY;

				return BPT_OK;
			}
			break;

		case BPT_WRITE:
			{
				debug_printf("Write access\n");

                return BPT_BAD_TYPE;

				/*if (len != 8)
				{
					msg("Hardware breakpoints must be 8 bytes long\n");
					return BPT_BAD_LEN;
				}*/
				
/*
				if (ea % 8 != 0)
				{
					msg("Hardware breakpoints must be 8 byte aligned\n");
					return BPT_BAD_ALIGN;
				}
				
				if (dabr_is_set == false)
				{
					//dabr_is_set is not set yet bug
					return BPT_OK;
				}
                else
                {
					msg("It's possible to set a single hardware breakpoint\n");
					return BPT_TOO_MANY;
				}
*/
			}
			break;

			// No read access?

		case BPT_RDWR:
			{
				debug_printf("Read/write access\n");

                return BPT_BAD_TYPE;

				/*if (len != 8)
				{
					msg("Hardware breakpoints must be 8 bytes long\n");
					return BPT_BAD_LEN;
				}*/

/*
				if (ea % 8 != 0)
				{
					msg("Hardware breakpoints must be 8 byte aligned\n");
					return BPT_BAD_ALIGN;
				}

				if (dabr_is_set == false)
				{
					//dabr_is_set is not set yet bug
					return BPT_OK;
				}
                else
                {
					msg("It's possible to set a single hardware breakpoint\n");
					return BPT_TOO_MANY;
				}
*/
			}
			break;

		default:
			debug_printf("Unsupported BP type !\n");
			return BPT_BAD_TYPE;
	}

}

//--------------------------------------------------------------------------
int idaapi update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
    debug_printf("update_bpts - add: %d - del: %d\n", (uint32)nadd, (uint32)ndel);

    int i;
    //std::vector<uint32>::iterator it;
    uint32 orig_inst = -1;
    uint32 BPCount;
    int cnt = 0;

    //debug_printf("BreakPoints sum: %d\n", BPCount);

    //bp_list();

    for (i = 0; i < ndel; i++)
    {
        debug_printf("del_bpt: type: %d, ea: 0x%llX, code: %d\n", (uint32)bpts[nadd + i].type, (uint64)bpts[nadd + i].ea, (uint32)bpts[nadd + i].code);

        bpts[nadd + i].code = BPT_OK;
        cnt++;

        switch(bpts[nadd + i].type)
        {
        case BPT_SOFT:
            {
                debug_printf("Software breakpoint\n");

                gdb_remove_bp(bpts[nadd + i].ea, GDB_BP_TYPE_X, bpts[nadd + i].size);

                main_bpts.erase(bpts[nadd + i].ea);

                main_bpts_map.erase(bpts[nadd + i].ea);
            }
            break;

        case BPT_EXEC:
            {
                debug_printf("Execute breakpoint\n");

                gdb_remove_bp(bpts[nadd + i].ea, GDB_BP_TYPE_X, bpts[nadd + i].size);

                main_bpts.erase(bpts[nadd + i].ea);

                main_bpts_map.erase(bpts[nadd + i].ea);
            }
            break;

        case BPT_WRITE:
            {
                debug_printf("Write access\n");

                gdb_remove_bp(bpts[nadd + i].ea, GDB_BP_TYPE_W, bpts[nadd + i].size);

                main_bpts.erase(bpts[nadd + i].ea);

                main_bpts_map.erase(bpts[nadd + i].ea);
            }
            break;

        case BPT_RDWR:
            {
                debug_printf("Read/write access\n");

                gdb_remove_bp(bpts[nadd + i].ea, GDB_BP_TYPE_A, bpts[nadd + i].size);

                main_bpts.erase(bpts[nadd + i].ea);

                main_bpts_map.erase(bpts[nadd + i].ea);
            }
            break;
        }
    }

    for (i = 0; i < nadd; i++)
    {
        if (bpts[i].code != BPT_OK)
            continue;

        debug_printf("add_bpt: type: %d, ea: 0x%llX, code: %d, size: %d\n", (uint32)bpts[i].type, (uint64)bpts[i].ea, (uint32)bpts[i].code, (uint32)bpts[i].size);

        //BPT_SKIP

        switch(bpts[i].type)
        {
        case BPT_SOFT:
            {
                debug_printf("Software breakpoint\n");

                gdb_add_bp(bpts[i].ea, GDB_BP_TYPE_X, bpts[i].size);

                bpts[i].code = BPT_OK;

                main_bpts.insert(bpts[i].ea);

                // NOTE: Software breakpoints require "original bytes" data
                gdb_read_mem(bpts[i].ea, (u8*)&orig_inst, sizeof(orig_inst));

                bpts[i].orgbytes.qclear();
                bpts[i].orgbytes.append(&orig_inst,  sizeof(orig_inst));

                cnt++;
            }
            break;

        case BPT_EXEC:
            {
                debug_printf("Execute instruction\n");

                gdb_add_bp(bpts[i].ea, GDB_BP_TYPE_X, bpts[i].size);

                bpts[i].code = BPT_OK;

                main_bpts.insert(bpts[i].ea);

                cnt++;
            }
            break;

        case BPT_WRITE:
            {
                debug_printf("Write access\n");

                gdb_add_bp(bpts[i].ea, GDB_BP_TYPE_W, bpts[i].size);

                bpts[i].code = BPT_OK;

                main_bpts.insert(bpts[i].ea);

                cnt++;
            }
            break;

            // No read access?

        case BPT_RDWR:
            {
                debug_printf("Read/write access\n");

                gdb_add_bp(bpts[i].ea, GDB_BP_TYPE_A, bpts[i].size);

                bpts[i].code = BPT_OK;

                main_bpts.insert(bpts[i].ea);

                cnt++;
            }
            break;

        default:
            debug_printf("Unsupported BP type !\n");
        }
    }

    //debug_printf("BreakPoints sum: %d\n", BPCount);

    //bp_list();

    return cnt;
}

//--------------------------------------------------------------------------
// Map process address
ea_t idaapi map_address(ea_t off, const regval_t *regs, int regnum)
{
    //debug_printf("map_address\n");

	if (regs == NULL) // jump prediction
	{
        if (off < LS_SIZE && off >= 0)
        {
            return off;
        }

		return BADADDR;
	}

    if (regnum >= 0)
    {
#if USE_CUSTOM_FORMAT
        if (regnum < (GPR_COUNT - 2))
        {
            if (regs[regnum].get_data_size() != 16)
            {
                debug_printf("Invalid register size.\n");
                return BADADDR;
            }

            uint32* reg = (uint32*)regs[regnum].get_data();

            if (reg[0] < LS_SIZE && reg[0] >= 0)
            {
                return reg[0];
            }
        }
        else
#endif
        if (regnum < GPR_COUNT)
        {
            const ea_t addr = (regs[regnum].ival & 0xFFFFFFFF);
            if (addr < LS_SIZE && addr >= 0)
            {
                return addr;
            }
        }
    }

	return BADADDR;
}

//-------------------------------------------------------------------------
int idaapi send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize)
{
	return 0;
}

//--------------------------------------------------------------------------
//
//      DEBUGGER DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
debugger_t debugger =
{
    IDD_INTERFACE_VERSION,
    DEBUGGER_NAME,				// Short debugger name
    DEBUGGER_ID_PLAYSTATION_3_SPU,	// Debugger API module id
    PROCESSOR_NAME,				// Required processor name
    DBG_FLAG_REMOTE | DBG_FLAG_NOHOST | DBG_FLAG_NEEDPORT | DBG_FLAG_CAN_CONT_BPT | DBG_FLAG_NOSTARTDIR | DBG_FLAG_NOPARAMETERS | DBG_FLAG_NOPASSWORD | DBG_FLAG_DEBTHREAD,

    register_classes,			// Array of register class names
    RC_GENERAL,					// Mask of default printed register classes
    registers,					// Array of registers
    qnumber(registers),			// Number of registers

    0x1000,						// Size of a memory page

    bpt_code,				    // Array of bytes for a breakpoint instruction
    qnumber(bpt_code),			// Size of this array
    0,							// for miniidbs: use this value for the file type after attaching
    0,							// reserved

    init_debugger,
    term_debugger,

    process_get_info,
    deci3_start_process,
    deci3_attach_process,
    deci3_detach_process,
    rebase_if_required_to,
    prepare_to_pause_process,
    deci3_exit_process,

    get_debug_event,
    continue_after_event,
    NULL, //set_exception_info,
    stopped_at_debug_event,

    thread_suspend,
    thread_continue,
    thread_set_step,
    read_registers,
    write_register,
    NULL, //thread_get_sreg_base

    get_memory_info,
    read_memory,
    write_memory,

    is_ok_bpt,
    update_bpts,
    NULL, //update_lowcnds
    NULL, //open_file
    NULL, //close_file
    NULL, //read_file
    map_address,
    NULL, //set_dbg_options
    NULL, //get_debmod_extensions
    NULL, //update_call_stack
    NULL, //appcall
    NULL, //cleanup_appcall
    NULL, //eval_lowcnd
    NULL, //write_file
    send_ioctl,
};
