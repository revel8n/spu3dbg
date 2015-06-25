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

#define WIN32_LEAN_AND_MEAN
#define VC_LEANMEAN
#include <windows.h>

#include <ida.hpp>
#include <area.hpp>
#include <idd.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include <idp.hpp>

#include "gdb.h"

extern debugger_t debugger;

static bool init_plugin(void);
static void term_plugin(void);

bool plugin_inited;

//--------------------------------------------------------------------------
// Initialize debugger plugin
static int idaapi init(void)
{
	if (init_plugin())
	{
		dbg = &debugger;
		plugin_inited = true;
		return PLUGIN_KEEP;
	}
	return PLUGIN_SKIP;
}

//--------------------------------------------------------------------------
// Terminate debugger plugin
static void idaapi term(void)
{
	if (plugin_inited)
	{
		term_plugin();
		plugin_inited = false;
	}
}

//--------------------------------------------------------------------------
// The plugin method - usually is not used for debugger plugins
static void idaapi run(int /*arg*/)
{

}

static bool idaapi spu_print_2_dwords(
    void *ud,                       // user-defined data
    qstring *out,                   // output buffer. may be NULL
    const void *value,              // value to print. may not be NULL
    asize_t size,                   // size of value in bytes
    ea_t current_ea,                // current address (BADADDR if unknown)
    int operand_num,                // current operand number
    int dtid)                       // custom data type id (0-standard built-in data type)
{
    if (0x10 != size)
        return false;

    qstring o;
    if (0 != out)
    {
        uint32* v = (uint32*)value;
        out->sprnt("%08X%08X %08X%08X", v[0], v[1], v[2], v[3]);
    }

    return true;
}

static bool idaapi spu_print_4_words(
    void *ud,                       // user-defined data
    qstring *out,                   // output buffer. may be NULL
    const void *value,              // value to print. may not be NULL
    asize_t size,                   // size of value in bytes
    ea_t current_ea,                // current address (BADADDR if unknown)
    int operand_num,                // current operand number
    int dtid)                       // custom data type id (0-standard built-in data type)
{
    if (0x10 != size)
        return false;

    qstring o;
    if (0 != out)
    {
        uint32* v = (uint32*)value;
        out->sprnt("%08X %08X %08X %08X", v[0], v[1], v[2], v[3]);
    }

    return true;
}

static bool idaapi spu_print_8_hwords(
    void *ud,                       // user-defined data
    qstring *out,                   // output buffer. may be NULL
    const void *value,              // value to print. may not be NULL
    asize_t size,                   // size of value in bytes
    ea_t current_ea,                // current address (BADADDR if unknown)
    int operand_num,                // current operand number
    int dtid)                       // custom data type id (0-standard built-in data type)
{
    if (0x10 != size)
        return false;

    qstring o;
    if (0 != out)
    {
        uint16* v = (uint16*)value;
        out->sprnt("%04X %04X %04X %04X %04X %04X %04X %04X",
            v[1], v[0], v[3], v[2], v[5], v[4], v[7], v[6]);
    }

    return true;
}

static bool idaapi spu_print_16_bytes(
    void *ud,                       // user-defined data
    qstring *out,                   // output buffer. may be NULL
    const void *value,              // value to print. may not be NULL
    asize_t size,                   // size of value in bytes
    ea_t current_ea,                // current address (BADADDR if unknown)
    int operand_num,                // current operand number
    int dtid)                       // custom data type id (0-standard built-in data type)
{
    if (0x10 != size)
        return false;

    qstring o;
    if (0 != out)
    {
        uint8* v = (uint8*)value;
        out->sprnt("%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
            v[3], v[2], v[1], v[0], v[7], v[6], v[5], v[4], v[11], v[10], v[9], v[8], v[15], v[14], v[13], v[12]);
    }

    return true;
}

static bool idaapi spu_print_2_doubles(
    void *ud,                       // user-defined data
    qstring *out,                   // output buffer. may be NULL
    const void *value,              // value to print. may not be NULL
    asize_t size,                   // size of value in bytes
    ea_t current_ea,                // current address (BADADDR if unknown)
    int operand_num,                // current operand number
    int dtid)                       // custom data type id (0-standard built-in data type)
{
    if (0x10 != size)
        return false;

    qstring o;
    if (0 != out)
    {
        uint32* v = (uint32*)value;
        uint32 dv[4] = {v[1], v[0], v[3], v[2]};
        double* d = (double*)value;
        out->sprnt("%0.lf %0.lf", d[0], d[1]);
    }

    return true;
}

static bool idaapi spu_print_4_floats(
    void *ud,                       // user-defined data
    qstring *out,                   // output buffer. may be NULL
    const void *value,              // value to print. may not be NULL
    asize_t size,                   // size of value in bytes
    ea_t current_ea,                // current address (BADADDR if unknown)
    int operand_num,                // current operand number
    int dtid)                       // custom data type id (0-standard built-in data type)
{
    if (0x10 != size)
        return false;

    qstring o;
    if (0 != out)
    {
        float* v = (float*)value;
        out->sprnt("%0.f %0.f %0.f %0.f", v[0], v[1], v[2], v[3]);
    }

    return true;
}

static bool idaapi spu_scan(                  // convert from uncolored string
                    void *ud,                 // user-defined data
                    bytevec_t *value,         // output buffer. may be NULL
                    const char *input,        // input string. may not be NULL
                    ea_t current_ea,          // current address (BADADDR if unknown)
                    int operand_num,          // current operand number (-1 if unknown)
                    qstring *errstr)          // buffer for error message
{
    return false;
}


static data_format_t custom_formats[] =
{
    {sizeof(data_format_t), 0, 0, "spu_2_dwords",  0, 0, 0x10, 0x21, spu_print_2_dwords,  spu_scan, 0},
    {sizeof(data_format_t), 0, 0, "spu_4_words",   0, 0, 0x10, 0x23, spu_print_4_words,   spu_scan, 0},
    {sizeof(data_format_t), 0, 0, "spu_8_hwords",  0, 0, 0x10, 0x27, spu_print_8_hwords,  spu_scan, 0},
    {sizeof(data_format_t), 0, 0, "spu_16_bytes",  0, 0, 0x10, 0x2F, spu_print_16_bytes,  spu_scan, 0},

    {sizeof(data_format_t), 0, 0, "spu_2_doubles", 0, 0, 0x10, 0x2E, spu_print_2_doubles, spu_scan, 0},
    {sizeof(data_format_t), 0, 0, "spu_4_floats",  0, 0, 0x10, 0x34, spu_print_4_floats,  spu_scan, 0},
};
static const uint32 custom_format_count = sizeof(custom_formats) / sizeof(custom_formats[0]);

extern void setup_registers();

//--------------------------------------------------------------------------
// Initialize PPC debugger plugin
static bool init_plugin(void)
{
	if (ph.id != PLFM_SPU)
		return false;

    setup_registers();

    for (int k = 0; k < custom_format_count; ++k)
    {
        int dfid = register_custom_data_format(0, &custom_formats[k]);
        if (dfid < 0)
            msg("---: %d - Could not register custom format: %s - %lld bytes - %d wide\n", (uint32)k, custom_formats[k].name, (uint64)custom_formats[k].value_size, (uint32)custom_formats[k].text_width);
        else
            msg("---: %d - Registered custom format: %s - %lld bytes - %d wide\n", (uint32)k, custom_formats[k].name, (uint64)custom_formats[k].value_size, (uint32)custom_formats[k].text_width);

        custom_formats[k].ud = (void*)dfid;
    }

    intvec_t dts;
    int dt_count = get_custom_data_types(&dts);
    for (int i = 0; i < dt_count; ++i)
    {
        const data_type_t* t = get_custom_data_type(dts[i]);
        msg("%d - Type: %s - %lld bytes\n", (uint32)i, t->name, (uint64)t->value_size);
    }

    intvec_t dfs;
    int df_count = get_custom_data_formats(&dfs, 0);
    for (int j = 0; j < df_count; ++j)
    {
        const data_format_t* f = get_custom_data_format(0, dfs[j]);
        msg("---: %d - Format: %s - %lld bytes - %d wide\n", (uint32)j, f->name, (uint64)f->value_size, (uint32)f->text_width);
    }

	return true;
}

//--------------------------------------------------------------------------
// Terminate PPC debugger plugin
static void term_plugin(void)
{
    gdb_deinit();

    for (int k = 0; k < custom_format_count; ++k)
    {
        if (!unregister_custom_data_format(0, (int)custom_formats[k].ud))
            msg("---: %d - Could not unregister custom format: %s - %lld bytes - %d wide\n", (uint32)k, custom_formats[k].name, (uint64)custom_formats[k].value_size, (uint32)custom_formats[k].text_width);
        else
            msg("---: %d - Unregistered custom format: %s - %lld bytes - %d wide\n", (uint32)k, custom_formats[k].name, (uint64)custom_formats[k].value_size, (uint32)custom_formats[k].text_width);

        custom_formats[k].ud = (void*)-1;
    }
}

//--------------------------------------------------------------------------
char comment[] = "SPU3 debugger plugin by revel8n.";

char help[] =
        "SPU3 debugger plugin by revel8n.\n"
		"\n"
		"This module lets you debug spu programs running in the anergistic emulator.\n";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_DBG,					// plugin flags
  init,							// initialize

  term,							// terminate. this pointer may be NULL.

  run,							// invoke plugin

  comment,						// long comment about the plugin
								// it could appear in the status line
								// or as a hint

  help,							// multiline help about the plugin

  "SPU3 debugger plugin",		// the preferred short name of the plugin

  ""							// the preferred hotkey to run the plugin
};

BOOL WINAPI DllMain( HANDLE hDllHandle, DWORD dwReason, LPVOID lpreserved )
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
        gdb_deinit();
    }

    return TRUE;    // ok
}
