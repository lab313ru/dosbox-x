enum CpuRegister {
  EAX,
  EBX,
  ECX,
  EDX,
  ESI,
  EDI,
  EBP,
  ESP,
  EIP,
  FLAGS,
}

struct CpuRegisters {
  1:i32 EAX,
  2:i32 EBX,
  3:i32 ECX,
  4:i32 EDX,
  5:i32 ESI,
  6:i32 EDI,
  7:i32 EBP,
  8:i32 ESP,
  15:i32 EIP,
  16:i16 FLAGS,
}

enum SegRegister {
  CS,
  DS,
  ES,
  FS,
  GS,
  SS,
}

struct SegRegisters {
  1:i16 CS,
  2:i16 DS,
  3:i16 ES,
  4:i16 FS,
  5:i16 GS,
  6:i16 SS,
}

struct SegBases {
  1:i32 CS_BASE,
  2:i32 DS_BASE,
  3:i32 ES_BASE,
  4:i32 FS_BASE,
  5:i32 GS_BASE,
  6:i32 SS_BASE,
}

enum FpuRegister {
  ST0,
  ST1,
  ST2,
  ST3,
  ST4,
  ST5,
  ST6,
  ST7,
}

struct FpuRegisters {
  1:double ST0,
  2:double ST1,
  3:double ST2,
  4:double ST3,
  5:double ST4,
  6:double ST5,
  7:double ST6,
  8:double ST7,
}

enum BpType {
  BP_PC = 1,
  BP_READ = 2,
  BP_WRITE = 4,
}

struct DbgBreakpoint {
  1:BpType type,
  2:i32 phys_addr,
  3:bool enabled,
}

service DosboxDebugger {
  i32 get_cpu_reg(1:CpuRegister reg),
  CpuRegisters get_cpu_regs(),
  void set_cpu_reg(1:CpuRegister reg, 2:i32 value),

  i16 get_seg_reg(1:SegRegister reg),
  SegRegisters get_seg_regs(),
  void set_seg_reg(1:SegRegister reg, 2:i16 value),

  i32 get_seg_base(1:i16 seg_val),
  SegBases get_seg_bases(),

  double get_fpu_reg(1:FpuRegister reg),
  FpuRegisters get_fpu_regs(),
  void set_fpu_reg(1:FpuRegister reg, 2:double value),

  binary read_memory(1:i32 phys_addr, 2:i32 size),
  void write_memory(1:i32 phys_addr, 2:binary data),

  void add_breakpoint(1:DbgBreakpoint bpt),
  void del_breakpoint(1:DbgBreakpoint bpt),

  void pause(),
  void resume(),
  void start_emulation(),
  void exit_emulation(),

  void step_into(),
  void step_over(),
}

service IdaClient {
  oneway void start_event(1:i32 base),
  oneway void pause_event(1:i16 seg, 2:i32 address),
  oneway void stop_event(),
}
