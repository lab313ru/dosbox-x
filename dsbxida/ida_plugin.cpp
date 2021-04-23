#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <loader.hpp>

#include "ida_plugin.h"
#include "ida_registers.h"

extern debugger_t debugger;

static bool plugin_inited;
static bool under_debugger;
static bool recursive;

static ssize_t idaapi hook_dbg(void* user_data, int notification_code, va_list va)
{
    switch(notification_code)
    {
    case dbg_notification_t::dbg_process_start:
        under_debugger = true;
        break;

    case dbg_notification_t::dbg_process_exit:
        under_debugger = false;
        break;
    }
    return 0;
}

static ssize_t idaapi hook_dosbox_callback(void* user_data, int notification_code, va_list va)
{
    switch(notification_code)
    {
    case processor_t::ev_ana_insn:
    {
        insn_t* out = va_arg(va, insn_t*);

        ushort w = get_word(out->ea);

        if(w == 0x38FE && under_debugger) { // callback
            out->itype = static_cast<uint16>(dosbox_insn_type_t::DOSBOX_callback);
            out->size = 4;
            out->Op1.type = o_idpspec0;
            out->Op1.offb = 2;
            out->Op1.dtype = dt_word;
            out->Op1.value = get_word(out->ea + 2);

            return out->size;
        }
    } break;
    case processor_t::ev_emu_insn:
    {
        insn_t* insn = va_arg(va, insn_t*);

        if(insn->itype == static_cast<uint16>(dosbox_insn_type_t::DOSBOX_callback) && under_debugger) {
            insn->add_cref(insn->ea + insn->size, insn->Op1.offb, fl_F);
            return 1;
        }
    } break;
    case processor_t::ev_out_mnem:
    {
        outctx_t* outctx = va_arg(va, outctx_t*);

        if(outctx->insn.itype == static_cast<uint16>(dosbox_insn_type_t::DOSBOX_callback) && under_debugger) {
            outctx->out_custom_mnem("callback");

            return 1;
        }
    } break;
    case processor_t::ev_out_operand:
    {
        outctx_t* outctx = va_arg(va, outctx_t*);
        const op_t* op = va_arg(va, const op_t*);

        if(outctx->insn.itype == static_cast<uint16>(dosbox_insn_type_t::DOSBOX_callback) && under_debugger) {
            std::string callback_name;
            extern void get_callback_name(std::string & name, const int16_t index);
            get_callback_name(callback_name, op->value);

            if(!callback_name.empty()) {
                outctx->out_line(callback_name.c_str());
            }

            return 1;
        }
    } break;
    }

    return 0;
}

struct x86_events_visitor_t : public post_event_visitor_t
{
    ssize_t idaapi handle_post_event(ssize_t code, int notification_code, va_list va) override
    {
        switch(notification_code)
        {
        case processor_t::ev_get_idd_opinfo:
        {
            idd_opinfo_t* opinf = va_arg(va, idd_opinfo_t*);
            ea_t ea = va_arg(va, ea_t);
            int n = va_arg(va, int);
            int thread_id = va_arg(va, int);
            processor_t::regval_getter_t* getreg = va_arg(va, processor_t::regval_getter_t*);
            const regval_t* regvalues = va_arg(va, const regval_t*);

            if(recursive) {
                recursive = false;
                return code;
            }

            opinf->ea = BADADDR;
            opinf->debregidx = 0;
            opinf->modified = false;
            opinf->value.ival = 0;
            opinf->value_size = 4;

            recursive = true;
            ph.get_idd_opinfo(opinf, ea, n, thread_id, getreg, *regvalues);
            recursive = false;

            return 1;
        }
        }

        return code;
    }
} ctx;

static bool init_plugin(void) {
    if(inf.filetype != f_EXE && inf.filetype != f_COM)
        return false; // only MSDOS EXE or COM files

    if(ph.id != PLFM_386)
        return false; // only IBM PC

    return true;
}

static void print_version()
{
    static const char format[] = NAME " debugger plugin v%s;\nAuthor: DrMefistO [Lab 313] <newinferno@gmail.com>.";
    info(format, VERSION);
    msg(format, VERSION);
}

static plugmod_t* idaapi init(void) {
    if(init_plugin()) {
        dbg = &debugger;
        plugin_inited = true;
        under_debugger = false;
        recursive = false;

        register_post_event_visitor(HT_IDP, &ctx, nullptr);
        hook_to_notification_point(HT_IDP, hook_dosbox_callback, nullptr);
        hook_to_notification_point(HT_DBG, hook_dbg, NULL);

        print_version();
        return PLUGIN_KEEP;
    }

    return PLUGIN_SKIP;
}

static void idaapi term(void) {
    if(plugin_inited) {
        unhook_from_notification_point(HT_DBG, hook_dosbox_callback);
        unhook_from_notification_point(HT_DBG, hook_dbg);
        unregister_post_event_visitor(HT_IDP, &ctx);

        recursive = false;
        under_debugger = false;
        plugin_inited = false;
    }
}

static bool idaapi run(size_t arg) {
    return false;
}

char comment[] = NAME " debugger plugin by DrMefistO.";

char help[] =
NAME " debugger plugin by DrMefistO.\n"
"\n"
"This module lets you debug MSDOS executables in IDA.\n";

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_PROC | PLUGIN_DBG,
    init,
    term,
    run,
    comment,
    help,
    NAME " debugger plugin",
    ""
};
