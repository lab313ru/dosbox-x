#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <loader.hpp>

#include "ida_plugin.h"

extern debugger_t debugger;

static bool plugin_inited;
static bool recursive;

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
            processor_t::regval_getter_t * getreg = va_arg(va, processor_t::regval_getter_t *);
            const regval_t* regvalues = va_arg(va, const regval_t*);

            if (recursive) {
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
        recursive = false;

        register_post_event_visitor(HT_IDP, &ctx, nullptr);

        print_version();
        return PLUGIN_KEEP;
    }

    return PLUGIN_SKIP;
}

static void idaapi term(void) {
    if(plugin_inited) {
        unregister_post_event_visitor(HT_IDP, &ctx);

        recursive = false;
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
