#include "gen-cpp/IdaClient.h"
#include "gen-cpp/DosboxDebugger.h"
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/server/TNonblockingServer.h>
#include <thrift/transport/TNonblockingServerSocket.h>
#include <thrift/concurrency/ThreadFactory.h>

using namespace ::apache::thrift;
using namespace ::apache::thrift::protocol;
using namespace ::apache::thrift::transport;
using namespace ::apache::thrift::server;
using namespace ::apache::thrift::concurrency;

#include <ida.hpp>
#include <dbg.hpp>
#include <auto.hpp>
#include <segregs.hpp>
#include <intel.hpp>
#include <ieee.h>
#include <mutex>

#include "ida_plugin.h"
#include "ida_debmod.h"
#include "ida_registers.h"

static ::std::shared_ptr<DosboxDebuggerClient> client;
static ::std::shared_ptr<TNonblockingServer> srv;
static ::std::shared_ptr<TTransport> cli_transport;

static ::std::mutex list_mutex;
static eventlist_t events;
static ea_t base_addr;

static const char* const flags_reg[]{
    "CF",
    NULL,
    "PF",
    NULL,
    "AF",
    NULL,
    "ZF",
    "SF",
    "TF",
    "IF",
    "DF",
    "OF",
    "IOPL",
    "IOPL",
    "NT",
    NULL,
};

static register_info_t registers[] = {
    { "AX", 0, RC_GEN, dt_word, NULL, 0 },
    { "AX_DS", REGISTER_ADDRESS | REGISTER_READONLY, RC_GEN, dt_dword, NULL, 0 },
    { "AX_CS", REGISTER_ADDRESS | REGISTER_READONLY, RC_GEN, dt_dword, NULL, 0 },
    { "BX", 0, RC_GEN, dt_word, NULL, 0 },
    { "BX_DS", REGISTER_ADDRESS | REGISTER_READONLY, RC_GEN, dt_dword, NULL, 0 },
    { "BX_CS", REGISTER_ADDRESS | REGISTER_READONLY, RC_GEN, dt_dword, NULL, 0 },
    { "CX", 0, RC_GEN, dt_word, NULL, 0 },
    { "CX_DS", REGISTER_ADDRESS | REGISTER_READONLY, RC_GEN, dt_dword, NULL, 0 },
    { "CX_CS", REGISTER_ADDRESS | REGISTER_READONLY, RC_GEN, dt_dword, NULL, 0 },
    { "DX", 0, RC_GEN, dt_word, NULL, 0 },
    { "DX_DS", REGISTER_ADDRESS | REGISTER_READONLY, RC_GEN, dt_dword, NULL, 0 },
    { "DX_CS", REGISTER_ADDRESS | REGISTER_READONLY, RC_GEN, dt_dword, NULL, 0 },
    { "SI", 0, RC_GEN, dt_word, NULL, 0 },
    { "SI_DS", REGISTER_ADDRESS | REGISTER_READONLY, RC_GEN, dt_dword, NULL, 0 },
    { "DI", 0, RC_GEN, dt_word, NULL, 0 },
    { "DI_ES", REGISTER_ADDRESS | REGISTER_READONLY, RC_GEN, dt_dword, NULL, 0 },
    { "BP", 0, RC_GEN, dt_word, NULL, 0 },
    { "BP_SS", REGISTER_ADDRESS | REGISTER_FP | REGISTER_READONLY, RC_GEN, dt_dword, NULL, 0 },
    { "SP", 0, RC_GEN, dt_word, NULL, 0 },
    { "SP_SS", REGISTER_ADDRESS | REGISTER_SP | REGISTER_READONLY, RC_GEN, dt_dword, NULL, 0 },
    { "IP", 0, RC_GEN, dt_word, NULL, 0 },
    { "IP_CS", REGISTER_ADDRESS | REGISTER_IP | REGISTER_READONLY, RC_GEN, dt_dword, NULL, 0 },
    { "EFL", 0, RC_GEN, dt_word, flags_reg, 0xFD5 },

    { "CS", REGISTER_CS, RC_SEG, dt_word, NULL, 0 },
    { "CS_BASE", REGISTER_ADDRESS | REGISTER_READONLY, RC_SEG, dt_dword, NULL, 0 },
    { "DS", 0, RC_SEG, dt_word, NULL, 0 },
    { "DS_BASE", REGISTER_ADDRESS | REGISTER_READONLY, RC_SEG, dt_dword, NULL, 0 },
    { "ES", 0, RC_SEG, dt_word, NULL, 0 },
    { "ES_BASE", REGISTER_ADDRESS | REGISTER_READONLY, RC_SEG, dt_dword, NULL, 0 },
    { "FS", 0, RC_SEG, dt_word, NULL, 0 },
    { "FS_BASE", REGISTER_ADDRESS | REGISTER_READONLY, RC_SEG, dt_dword, NULL, 0 },
    { "GS", 0, RC_SEG, dt_word, NULL, 0 },
    { "GS_BASE", REGISTER_ADDRESS | REGISTER_READONLY, RC_SEG, dt_dword, NULL, 0 },
    { "SS", REGISTER_SS, RC_SEG, dt_word, NULL, 0 },
    { "SS_BASE", REGISTER_ADDRESS | REGISTER_READONLY, RC_SEG, dt_dword, NULL, 0 },

    { "ST0", 0, RC_FPU, dt_float, NULL, 0 },
    { "ST1", 0, RC_FPU, dt_float, NULL, 0 },
    { "ST2", 0, RC_FPU, dt_float, NULL, 0 },
    { "ST3", 0, RC_FPU, dt_float, NULL, 0 },
    { "ST4", 0, RC_FPU, dt_float, NULL, 0 },
    { "ST5", 0, RC_FPU, dt_float, NULL, 0 },
    { "ST6", 0, RC_FPU, dt_float, NULL, 0 },
    { "ST7", 0, RC_FPU, dt_float, NULL, 0 },
};

static const char* register_classes[] = {
    "General Registers",
    "Segment Registers",
    "FPU Registers",
    NULL
};

static void pause_execution()
{
    try {
        if(client) {
            client->pause();
        }
    }
    catch(...) {

    }
}

static void continue_execution()
{
    try {
        if(client) {
            client->resume();
        }
    }
    catch(...) {

    }
}

static void stop_server() {
    try {
        srv->stop();
    }
    catch(...) {

    }
}

static void finish_execution()
{
    try {
        if(client) {
            client->exit_emulation();
        }
    }
    catch(...) {

    }

    stop_server();
}

void get_callback_name(std::string& name, const int16_t index) {
    name.clear();

    try {
        if(client) {
            client->get_callback_name(name, index);
        }
    }
    catch(...) {

    }
}

static inline ea_t find_app_base(const SegRegisters& sregs) {
    try {
        if(client) {
            ea_t base = (ea_t)client->get_address(sregs.CS, 0);
            ea_t addr;

            addr = (ea_t)client->get_address(sregs.DS, 0);

            if(addr < base) {
                base = addr;
            }

            addr = (ea_t)client->get_address(sregs.SS, 0);

            if(addr < base) {
                base = addr;
            }

            return base;
        }
    } catch(...) {

    }

    return 0;
}

class IdaClientHandler : virtual public IdaClientIf {

public:
    void pause_event(const int16_t seg, const int32_t address) override {
        ::std::lock_guard<::std::mutex> lock(list_mutex);

        debug_event_t ev;
        ev.pid = 1;
        ev.tid = 1;
        ev.ea = to_ea((sel_t)(seg & 0xFFFF), (uval_t)address);
        ev.handled = true;
        ev.set_eid(PROCESS_SUSPENDED);
        events.enqueue(ev, IN_BACK);
    }

    void start_event(const SegRegisters& sregs) override {
        ::std::lock_guard<::std::mutex> lock(list_mutex);

        debug_event_t ev;
        ev.pid = 1;
        ev.tid = 1;
        ev.ea = BADADDR;
        ev.handled = true;

        base_addr = find_app_base(sregs);

        ev.set_modinfo(PROCESS_STARTED).name.sprnt("dosbox");
        ev.set_modinfo(PROCESS_STARTED).base = base_addr + 0x100;
        ev.set_modinfo(PROCESS_STARTED).size = 0;
        ev.set_modinfo(PROCESS_STARTED).rebase_to = base_addr + 0x100;

        events.enqueue(ev, IN_BACK);
    }

    void stop_event() override {
        ::std::lock_guard<::std::mutex> lock(list_mutex);

        debug_event_t ev;
        ev.pid = 1;
        ev.handled = true;
        ev.set_exit_code(PROCESS_EXITED, 0);

        events.enqueue(ev, IN_BACK);
    }
};

static void init_ida_server() {
    try {
        ::std::shared_ptr<IdaClientHandler> handler(new IdaClientHandler());
        ::std::shared_ptr<TProcessor> processor(new IdaClientProcessor(handler));
        ::std::shared_ptr<TNonblockingServerTransport> serverTransport(new TNonblockingServerSocket(9091));
        ::std::shared_ptr<TFramedTransportFactory> transportFactory(new TFramedTransportFactory());
        ::std::shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());

        srv = ::std::shared_ptr<TNonblockingServer>(new TNonblockingServer(processor, protocolFactory, serverTransport));
        ::std::shared_ptr<ThreadFactory> tf(new ThreadFactory());
        ::std::shared_ptr<Thread> thread = tf->newThread(srv);
        thread->start();
    }
    catch(...) {

    }
}

static void init_emu_client() {
    ::std::shared_ptr<TTransport> socket(new TSocket("127.0.0.1", 9090));
    cli_transport = ::std::shared_ptr<TTransport>(new TFramedTransport(socket));
    ::std::shared_ptr<TBinaryProtocol> protocol(new TBinaryProtocol(cli_transport));
    client = ::std::shared_ptr<DosboxDebuggerClient>(new DosboxDebuggerClient(protocol));

    show_wait_box("Waiting for DOSBOX-X emulation...");

    while(true) {
        if(user_cancelled()) {
            break;
        }

        try {
            cli_transport->open();
            break;
        }
        catch(...) {

        }
    }

    hide_wait_box();
}

static drc_t idaapi init_debugger(const char* hostname, int portnum, const char* password, qstring* errbuf)
{
    return DRC_OK;
}

static drc_t idaapi term_debugger(void)
{
    finish_execution();
    return DRC_OK;
}

static drc_t s_get_processes(procinfo_vec_t* procs, qstring* errbuf) {
    process_info_t info;
    info.name.sprnt("dosbox-x");
    info.pid = 1;
    procs->add(info);

    return DRC_OK;
}

static drc_t idaapi s_start_process(const char* path,
    const char* args,
    const char* startdir,
    uint32 dbg_proc_flags,
    const char* input_path,
    uint32 input_file_crc32,
    qstring* errbuf = NULL)
{
    ::std::lock_guard<::std::mutex> lock(list_mutex);
    events.clear();

    init_ida_server();
    init_emu_client();

    try {
        if(client) {
            client->start_emulation();
        }
    }
    catch(...) {
        return DRC_FAILED;
    }

    return DRC_OK;
}

static drc_t idaapi prepare_to_pause_process(qstring* errbuf)
{
    pause_execution();
    return DRC_OK;
}

static drc_t idaapi emul_exit_process(qstring* errbuf)
{
    finish_execution();

    return DRC_OK;
}

static gdecode_t idaapi get_debug_event(debug_event_t* event, int timeout_ms)
{
    while(true)
    {
        ::std::lock_guard<::std::mutex> lock(list_mutex);

        // are there any pending events?
        if(events.retrieve(event))
        {
            return events.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
        }
        if(events.empty())
            break;
    }
    return GDE_NO_EVENT;
}

static drc_t idaapi continue_after_event(const debug_event_t* event)
{
    dbg_notification_t req = get_running_notification();
    switch(event->eid())
    {
    case PROCESS_SUSPENDED:
        if(req == dbg_null || req == dbg_run_to) {
            continue_execution();
        }
        break;
    case PROCESS_EXITED:
        stop_server();
        break;
    }

    return DRC_OK;
}

static void rebase_sregs(const SegRegisters& regs) {
    // fix up segment registers
    // rebase segment registers
    for (auto i = static_cast<int>(DBG_REGS::R_SEG_FIRST); i <= static_cast<int>(DBG_REGS::R_SEG_LAST); ++i) {
        int sr = R_cs;
        sel_t value;

        switch (i) {
        case static_cast<int>(DBG_REGS::R_CS):
            sr = R_cs;
            value = regs.CS;
            break;
        case static_cast<int>(DBG_REGS::R_DS):
            sr = R_ds;
            value = regs.DS;
            break;
        case static_cast<int>(DBG_REGS::R_ES):
            sr = R_es;
            value = regs.ES;
            break;
        case static_cast<int>(DBG_REGS::R_FS):
            sr = R_fs;
            value = regs.FS;
            break;
        case static_cast<int>(DBG_REGS::R_GS):
            sr = R_gs;
            value = regs.GS;
            break;
        case static_cast<int>(DBG_REGS::R_SS):
            sr = R_ss;
            value = regs.SS;
            break;
        default:
            continue;
        }

        // update segreg change points
        int sra_num = get_sreg_ranges_qty(sr);
        for(int i = 0; i < sra_num; ++i)
        {
            sreg_range_t sra;
            if(!getn_sreg_range(&sra, sr, i))
                break;

            split_sreg_range(sra.start_ea, sr, value, SR_user, true);
        }
    }
}

static drc_t idaapi s_set_resume_mode(thid_t tid, resume_mode_t resmod) // Run one instruction in the thread
{
    SegRegisters regs;

    switch(resmod)
    {
    case RESMOD_INTO:    ///< step into call (the most typical single stepping)
        try {
            if(client) {
                client->step_into();
                client->get_seg_regs(regs);
                //rebase_sregs(regs);
            }
        }
        catch(...) {
            return DRC_FAILED;
        }

        break;
    case RESMOD_OVER:    ///< step over call
        try {
            if(client) {
                client->step_over();
                client->get_seg_regs(regs);
                //rebase_sregs(regs);
            }
        }
        catch(...) {
            return DRC_FAILED;
        }
        break;
    }

    return DRC_OK;
}

static drc_t idaapi read_registers(thid_t tid, int clsmask, regval_t* values, qstring* errbuf)
{
    SegRegisters sregs; bool sregs_filled = false;

    if(clsmask & RC_GEN)
    {
        CpuRegisters regs;

        try {
            if(client) {
                client->get_cpu_regs(regs);
                client->get_seg_regs(sregs);
                sregs_filled = true;

                values[static_cast<int>(DBG_REGS::R_AX)].ival = regs.EAX & 0xFFFF;
                values[static_cast<int>(DBG_REGS::R_AX_DS)].ival = to_ea((sel_t)(sregs.DS & 0xFFFF), (uval_t)(regs.EAX & 0xFFFF));
                values[static_cast<int>(DBG_REGS::R_AX_CS)].ival = to_ea((sel_t)(sregs.CS & 0xFFFF), (uval_t)(regs.EAX & 0xFFFF));
                values[static_cast<int>(DBG_REGS::R_BX)].ival = regs.EBX & 0xFFFF;
                values[static_cast<int>(DBG_REGS::R_BX_DS)].ival = to_ea((sel_t)(sregs.DS & 0xFFFF), (uval_t)(regs.EBX & 0xFFFF));
                values[static_cast<int>(DBG_REGS::R_BX_CS)].ival = to_ea((sel_t)(sregs.CS & 0xFFFF), (uval_t)(regs.EBX & 0xFFFF));
                values[static_cast<int>(DBG_REGS::R_CX)].ival = regs.ECX & 0xFFFF;
                values[static_cast<int>(DBG_REGS::R_CX_DS)].ival = to_ea((sel_t)(sregs.DS & 0xFFFF), (uval_t)(regs.ECX & 0xFFFF));
                values[static_cast<int>(DBG_REGS::R_CX_CS)].ival = to_ea((sel_t)(sregs.CS & 0xFFFF), (uval_t)(regs.ECX & 0xFFFF));
                values[static_cast<int>(DBG_REGS::R_DX)].ival = regs.EDX & 0xFFFF;
                values[static_cast<int>(DBG_REGS::R_DX_DS)].ival = to_ea((sel_t)(sregs.DS & 0xFFFF), (uval_t)(regs.EDX & 0xFFFF));
                values[static_cast<int>(DBG_REGS::R_DX_CS)].ival = to_ea((sel_t)(sregs.CS & 0xFFFF), (uval_t)(regs.EDX & 0xFFFF));
                values[static_cast<int>(DBG_REGS::R_SI)].ival = regs.ESI & 0xFFFF;
                values[static_cast<int>(DBG_REGS::R_SI_DS)].ival = to_ea((sel_t)(sregs.DS & 0xFFFF), (uval_t)(regs.ESI & 0xFFFF));
                values[static_cast<int>(DBG_REGS::R_DI)].ival = regs.EDI & 0xFFFF;
                values[static_cast<int>(DBG_REGS::R_DI_ES)].ival = to_ea((sel_t)(sregs.ES & 0xFFFF), (uval_t)(regs.EDI & 0xFFFF));
                values[static_cast<int>(DBG_REGS::R_BP)].ival = regs.EBP & 0xFFFF;
                values[static_cast<int>(DBG_REGS::R_BP_SS)].ival = to_ea((sel_t)(sregs.SS & 0xFFFF), (uval_t)(regs.EBP & 0xFFFF));
                values[static_cast<int>(DBG_REGS::R_SP)].ival = regs.ESP & 0xFFFF;
                values[static_cast<int>(DBG_REGS::R_SP_SS)].ival = to_ea((sel_t)(sregs.SS & 0xFFFF), (uval_t)(regs.ESP & 0xFFFF));
                values[static_cast<int>(DBG_REGS::R_IP)].ival = regs.EIP & 0xFFFF;
                values[static_cast<int>(DBG_REGS::R_IP_CS)].ival = to_ea((sel_t)(sregs.CS & 0xFFFF), (uval_t)(regs.EIP & 0xFFFF));
                values[static_cast<int>(DBG_REGS::R_EFL)].ival = regs.FLAGS & 0xFFFF;
            }
        }
        catch(...) {
            return DRC_FAILED;
        }
    }

    if(clsmask & RC_SEG)
    {
        try {
            if(client) {
                if (!sregs_filled) {
                    client->get_seg_regs(sregs);
                }

                SegBases bases;
                client->get_seg_bases(bases);

                values[static_cast<int>(DBG_REGS::R_CS)].ival = sregs.CS;
                values[static_cast<int>(DBG_REGS::R_CS_BASE)].ival = bases.CS_BASE;
                values[static_cast<int>(DBG_REGS::R_DS)].ival = sregs.DS;
                values[static_cast<int>(DBG_REGS::R_DS_BASE)].ival = bases.DS_BASE;
                values[static_cast<int>(DBG_REGS::R_ES)].ival = sregs.ES;
                values[static_cast<int>(DBG_REGS::R_ES_BASE)].ival = bases.ES_BASE;
                values[static_cast<int>(DBG_REGS::R_FS)].ival = sregs.FS;
                values[static_cast<int>(DBG_REGS::R_FS_BASE)].ival = bases.FS_BASE;
                values[static_cast<int>(DBG_REGS::R_GS)].ival = sregs.GS;
                values[static_cast<int>(DBG_REGS::R_GS_BASE)].ival = bases.GS_BASE;
                values[static_cast<int>(DBG_REGS::R_SS)].ival = sregs.SS;
                values[static_cast<int>(DBG_REGS::R_SS_BASE)].ival = bases.SS_BASE;
            }
        }
        catch(...) {
            return DRC_FAILED;
        }
    }

    if(clsmask & RC_FPU)
    {
        FpuRegisters regs;

        try {
            if(client) {
                client->get_fpu_regs(regs);

                values[static_cast<int>(DBG_REGS::R_ST0)].ival = regs.ST0;
                values[static_cast<int>(DBG_REGS::R_ST1)].ival = regs.ST1;
                values[static_cast<int>(DBG_REGS::R_ST2)].ival = regs.ST2;
                values[static_cast<int>(DBG_REGS::R_ST3)].ival = regs.ST3;
                values[static_cast<int>(DBG_REGS::R_ST4)].ival = regs.ST4;
                values[static_cast<int>(DBG_REGS::R_ST5)].ival = regs.ST5;
                values[static_cast<int>(DBG_REGS::R_ST6)].ival = regs.ST6;
                values[static_cast<int>(DBG_REGS::R_ST7)].ival = regs.ST7;
            }
        }
        catch(...) {
            return DRC_FAILED;
        }
    }

    return DRC_OK;
}

static drc_t idaapi write_register(thid_t tid, int regidx, const regval_t* value, qstring* errbuf)
{
    try {
        if(client) {
            switch (regidx) {
            case static_cast<int>(DBG_REGS::R_AX):
            case static_cast<int>(DBG_REGS::R_BX):
            case static_cast<int>(DBG_REGS::R_CX):
            case static_cast<int>(DBG_REGS::R_DX):
            case static_cast<int>(DBG_REGS::R_SI):
            case static_cast<int>(DBG_REGS::R_DI):
            case static_cast<int>(DBG_REGS::R_BP):
            case static_cast<int>(DBG_REGS::R_SP):
            case static_cast<int>(DBG_REGS::R_IP):
            case static_cast<int>(DBG_REGS::R_EFL):
                client->set_cpu_reg(static_cast<CpuRegister::type>(regidx), value->ival);
                break;
            }
            switch (regidx) {
                case static_cast<int>(DBG_REGS::R_CS):
                case static_cast<int>(DBG_REGS::R_DS):
                case static_cast<int>(DBG_REGS::R_ES):
                case static_cast<int>(DBG_REGS::R_FS):
                case static_cast<int>(DBG_REGS::R_GS):
                case static_cast<int>(DBG_REGS::R_SS):
                    client->set_seg_reg(static_cast<SegRegister::type>(regidx), value->ival);
                    break;
            }
            if(regidx >= static_cast<int>(DBG_REGS::R_ST0) && regidx <= static_cast<int>(DBG_REGS::R_ST7)) {
                double tmp;
#if IDA_SDK_VERSION >= 760
                value->fval.to_double(&tmp);
#else
                uint16_t vals[IEEE_NE];
                for (auto i = 0; i < IEEE_NE; ++i) { vals[i] = value->fval[i]; }

                tmp = ieee_realcvt(&tmp, vals, 8|(sizeof(tmp)/2-1));
#endif

                client->set_fpu_reg(static_cast<FpuRegister::type>(regidx), tmp);
            }
        }
    }
    catch(...) {
        return DRC_FAILED;
    }

    return DRC_OK;
}

static bool first_info = true;

static drc_t idaapi get_memory_info(meminfo_vec_t& areas, qstring* errbuf)
{
    if (!first_info) {
        return DRC_NOCHG;
    }

    memory_info_t info;
    int last_user_seg = 0;

    try {
        if (client) {
            std::string mem;
            int32_t addr = client->get_address(base_addr >> 4, 2);
            client->read_memory(mem, addr, 2);
            last_user_seg = *(uint16_t*)mem.c_str();
        }
    }
    catch(...) {
        return DRC_FAILED;
    }

    memory_info_t* mi = &areas.push_back();
    mi->start_ea = 0x0;
    mi->end_ea = 0x400;
    mi->end_ea--;
    mi->name = "INTS";
    mi->bitness = 0;
    mi->perm = SEGPERM_READ | SEGPERM_WRITE;
    mi->sbase = 0;

    mi = &areas.push_back();
    mi->start_ea = 0x400;
    mi->end_ea = 0x600;
    mi->end_ea--;
    mi->name = "BIOS";
    mi->bitness = 0;
    mi->perm = SEGPERM_READ;
    mi->sbase = 0x40;

    mi = &areas.push_back();
    mi->start_ea = 0x600;
    mi->end_ea = base_addr;
    mi->end_ea--;
    mi->name = "DOS?";
    mi->bitness = 0;
    mi->perm = SEGPERM_READ;
    mi->sbase = 0x60;

    //mi = &areas.push_back();
    //mi->start_ea = base_addr;
    //mi->end_ea = base_addr + 0x100;
    //mi->end_ea--;
    //mi->name = "PSP";
    //mi->bitness = 0;
    //mi->perm = SEGPERM_READ;
    //mi->sbase = base_addr >> 4;

    //mi = &areas.push_back();
    //mi->start_ea = base_addr + 0x200;
    //mi->end_ea = (ea_t)client->get_address(last_user_seg, 0x10);
    //mi->end_ea--;
    //mi->name = ".text"; // Not the best name; it also covers data/stack/...
    //mi->bitness = 0;
    //mi->perm = SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
    //mi->sbase = base_addr >> 4;

    // Don't remove this loop
    for(int i = 0; i < get_segm_qty(); ++i)
    {
        segment_t* segm = getnseg(i);

        info.start_ea = segm->start_ea;
        info.end_ea = segm->end_ea;

        qstring buf;
        get_segm_name(&buf, segm);
        info.name = buf;

        get_segm_class(&buf, segm);
        info.sclass = buf;

        info.sbase = get_segm_base(segm);

        info.perm = segm->perm;
        info.bitness = segm->bitness;
        areas.push_back(info);
    }
    // Don't remove this loop

    mi = &areas.push_back();
    mi->start_ea = 0xA0000;
    mi->end_ea = 0xB0000;
    mi->end_ea--;
    mi->name = "A000";
    mi->bitness = 0;
    mi->perm = SEGPERM_READ;
    mi->sbase = 0xa000;

    mi = &areas.push_back();
    mi->start_ea = 0xB0000;
    mi->end_ea = 0xB8000;
    mi->end_ea--;
    mi->name = "B000";
    mi->bitness = 0;
    mi->perm = SEGPERM_READ | SEGPERM_WRITE;
    mi->sbase = 0xb000;

    mi = &areas.push_back();
    mi->start_ea = 0xB8000;
    mi->end_ea = 0xC0000;
    mi->end_ea--;
    mi->name = "B800";
    mi->bitness = 0;
    mi->perm = SEGPERM_READ | SEGPERM_WRITE;
    mi->sbase = 0xb800;

    mi = &areas.push_back();
    mi->start_ea = 0xC0000;
    mi->end_ea = 0xC1000;
    mi->end_ea--;
    mi->name = "VIDBIOS";
    mi->bitness = 0;
    mi->perm = SEGPERM_READ | SEGPERM_EXEC;
    mi->sbase = 0xc000;

    mi = &areas.push_back();
    mi->start_ea = (ea_t)client->get_address(0xf000, 0);
    mi->end_ea = (ea_t)client->get_address(0xf000, 0x10000);
    mi->end_ea--;
    mi->name = "BIOS_MEM";
    mi->perm = SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
    mi->sbase = 0xf000;

    first_info = false;

    return DRC_OK;
}

static ssize_t idaapi read_memory(ea_t ea, void* buffer, size_t size, qstring* errbuf)
{
    std::string mem;

    try {
        if(client) {
            client->read_memory(mem, (int32_t)ea, (int32_t)size);

            memcpy(&((unsigned char*)buffer)[0], mem.c_str(), size);
        }
    }
    catch(...) {
        return DRC_FAILED;
    }

    return size;
}

static ssize_t idaapi write_memory(ea_t ea, const void* buffer, size_t size, qstring* errbuf)
{
    std::string mem((const char*)buffer);

    try {
        if(client) {
            client->write_memory((int32_t)ea, mem);
        }
    }
    catch(...) {
        return 0;
    }

    return size;
}

static drc_t idaapi update_bpts(int* nbpts, update_bpt_info_t* bpts, int nadd, int ndel, qstring* errbuf)
{
    for(int i = 0; i < nadd; ++i)
    {
        ea_t start = bpts[i].ea;

        for (auto x = 0; x < bpts[i].size; ++x) {
            DbgBreakpoint bp;
            bp.phys_addr = start + i;
            bp.enabled = true;

            switch(bpts[i].type)
            {
            case BPT_EXEC:
                bp.type = BpType::BP_PC;
                break;
            case BPT_READ:
                bp.type = BpType::BP_READ;
                break;
            case BPT_WRITE:
                bp.type = BpType::BP_WRITE;
                break;
            case BPT_RDWR:
                bp.type = BpType::BP_READ;
                break;
            }

            try {
                if(client) {
                    client->add_breakpoint(bp);
                }
            }
            catch(...) {
                return DRC_FAILED;
            }
        }

        bpts[i].code = BPT_OK;
    }

    for(int i = 0; i < ndel; ++i)
    {
        ea_t start = bpts[nadd + i].ea;

        for (auto x = 0; x < bpts[nadd + i].size; ++x) {
            DbgBreakpoint bp;
            bp.phys_addr = start + x;
            bp.enabled = true;

            switch(bpts[i].type)
            {
            case BPT_EXEC:
                bp.type = BpType::BP_PC;
                break;
            case BPT_READ:
                bp.type = BpType::BP_READ;
                break;
            case BPT_WRITE:
                bp.type = BpType::BP_WRITE;
                break;
            case BPT_RDWR:
                bp.type = BpType::BP_READ;
                break;
            }

            try {
                if(client) {
                    client->del_breakpoint(bp);
                }
            }
            catch(...) {
                return DRC_FAILED;
            }
        }

        bpts[nadd + i].code = BPT_OK;
    }

    *nbpts = (ndel + nadd);
    return DRC_OK;
}

static drc_t thread_get_sreg_base(ea_t* answer, thid_t tid, int sreg_value, qstring* errbuf) {
    try {
        if (client) {
            *answer = client->get_seg_base(sreg_value);
        }
    }
    catch(...) {
        return DRC_FAILED;
    }

    return DRC_OK;
}

static drc_t map_address(ea_t* mapped, ea_t off, const regval_t* regs, int regnum) {
    if (regs == NULL) {
        *mapped = off;
        return DRC_OK;
    }

    ea_t add = regs[regnum].ival;

    switch (regnum) {
    case static_cast<int>(DBG_REGS::R_AX):
    case static_cast<int>(DBG_REGS::R_BX):
    case static_cast<int>(DBG_REGS::R_CX):
    case static_cast<int>(DBG_REGS::R_DX):
        *mapped = to_ea((sel_t)(regs[static_cast<sel_t>(DBG_REGS::R_DS)].ival & 0xFFFF), (uval_t)add);
        break;
    case static_cast<int>(DBG_REGS::R_SP):
    case static_cast<int>(DBG_REGS::R_BP):
        *mapped = to_ea((sel_t)(regs[static_cast<sel_t>(DBG_REGS::R_SS)].ival & 0xFFFF), (uval_t)add);
        break;
    case static_cast<int>(DBG_REGS::R_DI):
        *mapped = to_ea((sel_t)(regs[static_cast<sel_t>(DBG_REGS::R_ES)].ival & 0xFFFF), (uval_t)add);
        break;
    case static_cast<int>(DBG_REGS::R_SI):
        *mapped = to_ea((sel_t)(regs[static_cast<sel_t>(DBG_REGS::R_DS)].ival & 0xFFFF), (uval_t)add);
        break;
    case static_cast<int>(DBG_REGS::R_IP):
        *mapped = to_ea((sel_t)(regs[static_cast<sel_t>(DBG_REGS::R_CS)].ival & 0xFFFF), (uval_t)add);
        break;
    case static_cast<int>(DBG_REGS::R_AX_DS):
    case static_cast<int>(DBG_REGS::R_AX_CS):
    case static_cast<int>(DBG_REGS::R_BX_DS):
    case static_cast<int>(DBG_REGS::R_BX_CS):
    case static_cast<int>(DBG_REGS::R_CX_DS):
    case static_cast<int>(DBG_REGS::R_CX_CS):
    case static_cast<int>(DBG_REGS::R_DX_DS):
    case static_cast<int>(DBG_REGS::R_DX_CS):
    case static_cast<int>(DBG_REGS::R_SI_DS):
    case static_cast<int>(DBG_REGS::R_DI_ES):
    case static_cast<int>(DBG_REGS::R_BP_SS):
    case static_cast<int>(DBG_REGS::R_SP_SS):
    case static_cast<int>(DBG_REGS::R_IP_CS):
        *mapped = add;
        break;
    case static_cast<int>(DBG_REGS::R_EFL):
    case static_cast<int>(DBG_REGS::R_ST0):
    case static_cast<int>(DBG_REGS::R_ST1):
    case static_cast<int>(DBG_REGS::R_ST2):
    case static_cast<int>(DBG_REGS::R_ST3):
    case static_cast<int>(DBG_REGS::R_ST4):
    case static_cast<int>(DBG_REGS::R_ST5):
    case static_cast<int>(DBG_REGS::R_ST6):
    case static_cast<int>(DBG_REGS::R_ST7):
        *mapped = BADADDR;
        break;
    default:
        *mapped = to_ea((sel_t)add, 0);
        break;
    }

    return DRC_OK;
}

static drc_t rebase_if_required_to(ea_t new_base) {
    ea_t currentbase = to_ea((sel_t)(inf.baseaddr & 0xFFFF), 0);
    ea_t imagebase = new_base;

    if (imagebase != currentbase) {
        adiff_t delta = imagebase - currentbase;
        int ok = rebase_program(delta, MSF_NETNODES | MSF_FIXONCE);

        if (ok != MOVE_SEGM_OK) {
            msg("Failed to rebase program, error code %d\n", ok);
            warning("Failed to rebase program, error code %d\n", ok);

            return DRC_FAILED;
        }
    }

    return DRC_OK;
}

static ssize_t idaapi idd_notify(void*, int msgid, va_list va) {
    drc_t retcode = DRC_NONE;
    qstring* errbuf;

    switch(msgid)
    {
    case debugger_t::ev_init_debugger:
    {
        const char* hostname = va_arg(va, const char*);

        int portnum = va_arg(va, int);
        const char* password = va_arg(va, const char*);
        errbuf = va_arg(va, qstring*);
        QASSERT(1522, errbuf != NULL);
        retcode = init_debugger(hostname, portnum, password, errbuf);
    }
    break;

    case debugger_t::ev_term_debugger:
        retcode = term_debugger();
        break;

    case debugger_t::ev_get_processes:
    {
        procinfo_vec_t* procs = va_arg(va, procinfo_vec_t*);
        errbuf = va_arg(va, qstring*);
        retcode = s_get_processes(procs, errbuf);
    }
    break;

    case debugger_t::ev_start_process:
    {
        const char* path = va_arg(va, const char*);
        const char* args = va_arg(va, const char*);
        const char* startdir = va_arg(va, const char*);
        uint32 dbg_proc_flags = va_arg(va, uint32);
        const char* input_path = va_arg(va, const char*);
        uint32 input_file_crc32 = va_arg(va, uint32);
        errbuf = va_arg(va, qstring*);
        retcode = s_start_process(path,
            args,
            startdir,
            dbg_proc_flags,
            input_path,
            input_file_crc32,
            errbuf);
    }
    break;

    case debugger_t::ev_get_debapp_attrs:
    {
        debapp_attrs_t* out_pattrs = va_arg(va, debapp_attrs_t*);
        out_pattrs->addrsize = 4;
        out_pattrs->is_be = false;
        out_pattrs->platform = "dosbox";
        out_pattrs->cbsize = sizeof(debapp_attrs_t);
        retcode = DRC_OK;
    }
    break;

    case debugger_t::ev_rebase_if_required_to:
    {
        ea_t new_base = va_arg(va, ea_t);
        retcode = rebase_if_required_to(new_base);
    }
    break;

    case debugger_t::ev_request_pause:
        errbuf = va_arg(va, qstring*);
        retcode = prepare_to_pause_process(errbuf);
        break;

    case debugger_t::ev_exit_process:
        errbuf = va_arg(va, qstring*);
        retcode = emul_exit_process(errbuf);
        break;

    case debugger_t::ev_get_debug_event:
    {
        gdecode_t* code = va_arg(va, gdecode_t*);
        debug_event_t* event = va_arg(va, debug_event_t*);
        int timeout_ms = va_arg(va, int);
        *code = get_debug_event(event, timeout_ms);
        retcode = DRC_OK;
    }
    break;

    case debugger_t::ev_resume:
    {
        debug_event_t* event = va_arg(va, debug_event_t*);
        retcode = continue_after_event(event);
    }
    break;

    //case debugger_t::ev_set_exception_info:
    //{
    //    exception_info_t* info = va_arg(va, exception_info_t*);
    //    int qty = va_arg(va, int);
    //    g_dbgmod.dbg_set_exception_info(info, qty);
    //    retcode = DRC_OK;
    //}
    //break;

    //case debugger_t::ev_suspended:
    //{
    //    bool dlls_added = va_argi(va, bool);
    //    thread_name_vec_t* thr_names = va_arg(va, thread_name_vec_t*);
    //    retcode = DRC_OK;
    //}
    //break;

    case debugger_t::ev_thread_suspend:
    {
        thid_t tid = va_argi(va, thid_t);
        pause_execution();
        retcode = DRC_OK;
    }
    break;

    case debugger_t::ev_thread_continue:
    {
        thid_t tid = va_argi(va, thid_t);
        continue_execution();
        retcode = DRC_OK;
    }
    break;

    case debugger_t::ev_set_resume_mode:
    {
        thid_t tid = va_argi(va, thid_t);
        resume_mode_t resmod = va_argi(va, resume_mode_t);
        retcode = s_set_resume_mode(tid, resmod);
    }
    break;

    case debugger_t::ev_read_registers:
    {
        thid_t tid = va_argi(va, thid_t);
        int clsmask = va_arg(va, int);
        regval_t* values = va_arg(va, regval_t*);
        errbuf = va_arg(va, qstring*);
        retcode = read_registers(tid, clsmask, values, errbuf);
    }
    break;

    case debugger_t::ev_write_register:
    {
        thid_t tid = va_argi(va, thid_t);
        int regidx = va_arg(va, int);
        const regval_t* value = va_arg(va, const regval_t*);
        errbuf = va_arg(va, qstring*);
        retcode = write_register(tid, regidx, value, errbuf);
    }
    break;

    case debugger_t::ev_thread_get_sreg_base:
    {
        ea_t* answer = va_arg(va, ea_t*);
        thid_t tid = va_argi(va, thid_t);
        int sreg_value = va_arg(va, int);
        errbuf = va_arg(va, qstring*);
        retcode = thread_get_sreg_base(answer, tid, sreg_value, errbuf);
    }
    break;

    case debugger_t::ev_get_memory_info:
    {
        meminfo_vec_t* ranges = va_arg(va, meminfo_vec_t*);
        errbuf = va_arg(va, qstring*);
        retcode = get_memory_info(*ranges, errbuf);
    }
    break;

    case debugger_t::ev_read_memory:
    {
        size_t* nbytes = va_arg(va, size_t*);
        ea_t ea = va_arg(va, ea_t);
        void* buffer = va_arg(va, void*);
        size_t size = va_arg(va, size_t);
        errbuf = va_arg(va, qstring*);
        ssize_t code = read_memory(ea, buffer, size, errbuf);
        *nbytes = code >= 0 ? code : 0;
        retcode = code >= 0 ? DRC_OK : DRC_NOPROC;
    }
    break;

    case debugger_t::ev_write_memory:
    {
        size_t* nbytes = va_arg(va, size_t*);
        ea_t ea = va_arg(va, ea_t);
        const void* buffer = va_arg(va, void*);
        size_t size = va_arg(va, size_t);
        errbuf = va_arg(va, qstring*);
        ssize_t code = write_memory(ea, buffer, size, errbuf);
        *nbytes = code >= 0 ? code : 0;
        retcode = code >= 0 ? DRC_OK : DRC_NOPROC;
    }
    break;

    case debugger_t::ev_update_bpts:
    {
        int* nbpts = va_arg(va, int*);
        update_bpt_info_t* bpts = va_arg(va, update_bpt_info_t*);
        int nadd = va_arg(va, int);
        int ndel = va_arg(va, int);
        errbuf = va_arg(va, qstring*);
        retcode = update_bpts(nbpts, bpts, nadd, ndel, errbuf);
    }
    break;

    case debugger_t::ev_map_address:
    {
        ea_t* mapped = va_arg(va, ea_t*);
        ea_t off = va_arg(va, ea_t);
        const regval_t* regs = va_arg(va, const regval_t*);
        int regnum = va_arg(va, int);
        retcode = map_address(mapped, off, regs, regnum);
    }
    break;

    //case debugger_t::ev_bin_search:
    //{
    //    ea_t* ea = va_arg(va, ea_t*);
    //    ea_t start_ea = va_arg(va, ea_t);
    //    ea_t end_ea = va_arg(va, ea_t);
    //    const compiled_binpat_vec_t* ptns = va_arg(va, const compiled_binpat_vec_t*);
    //    int srch_flags = va_arg(va, int);
    //    errbuf = va_arg(va, qstring*);
    //    if (ptns != NULL)
    //        retcode = g_dbgmod.dbg_bin_search(ea, start_ea, end_ea, *ptns, srch_flags, errbuf);
    //}
    //break;
    default:
        retcode = DRC_NONE;
    }

    return retcode;
}

debugger_t debugger {
    IDD_INTERFACE_VERSION,
    NAME,
    DEBUGGER_ID_X86_DOSBOX_EMULATOR,
    "metapc",

    DBG_FLAG_NOHOST | DBG_FLAG_CAN_CONT_BPT | DBG_FLAG_SAFE | DBG_FLAG_FAKE_ATTACH | DBG_FLAG_NOPASSWORD |
    DBG_FLAG_NOSTARTDIR | DBG_FLAG_NOPARAMETERS | DBG_FLAG_ANYSIZE_HWBPT | DBG_FLAG_DEBTHREAD | DBG_FLAG_PREFER_SWBPTS,
    DBG_HAS_GET_PROCESSES | DBG_HAS_REQUEST_PAUSE | DBG_HAS_SET_RESUME_MODE | DBG_HAS_THREAD_SUSPEND | DBG_HAS_THREAD_CONTINUE | DBG_HAS_CHECK_BPT | DBG_HAS_MAP_ADDRESS | DBG_HAS_THREAD_GET_SREG_BASE,

    register_classes,
    RC_GEN,
    registers,
    qnumber(registers),

    0x1000,

    NULL,
    0,
    0,

    DBG_RESMOD_STEP_INTO | DBG_RESMOD_STEP_OVER,

    NULL,
    idd_notify
};

