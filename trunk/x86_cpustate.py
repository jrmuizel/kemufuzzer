# This file is part of KEmuFuzzer.
# 
# KEmuFuzzer is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
# 
# KEmuFuzzer is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along with
# KEmuFuzzer.  If not, see <http://www.gnu.org/licenses/>.

import struct, os
from ctypes import *
import subprocess
from elf import Elf

# Dump format:
#
# HEADER + CPU[0] + CPU[1] + .... + MEM
#

KEMUFUZZER_HYPERCALL_START_TESTCASE = 0x23
KEMUFUZZER_HYPERCALL_STOP_TESTCASE  = 0x45

CPU_STATE_MAGIC   = 0xEFEF
CPU_STATE_VERSION = 0x0001
MAX_MSRS          = 0x20
HYPERCALL_LEN     = 0x2         # length of a "hypercall" instruction (in bytes)


X86_MSR_IA32_SYSENTER_CS            = 0x174
X86_MSR_IA32_SYSENTER_ESP           = 0x175
X86_MSR_IA32_SYSENTER_EIP           = 0x176
X86_MSR_IA32_APICBASE               = 0x1b
X86_MSR_EFER                        = 0xc0000080
X86_MSR_STAR                        = 0xc0000081
X86_MSR_PAT                         = 0x277
X86_MSR_VM_HSAVE_PA                 = 0xc0010117
X86_MSR_IA32_PERF_STATUS            = 0x198

EXCEPTIONS = {
    0 : "#DE (Divide Error)",
    1 : "#DB (RESERVED)",
    2 : "-- (NMI)",
    3 : "#BP (Breakpoint)",
    4 : "#OF (Overflow)",
    5 : "#BR (BOUND Range Exceeded)",
    6 : "#UD (Undefined Opcode)",
    7 : "#NM (No Match Coprocessor)",
    8 : "#DF (Double Fault)",
    9 : "-- (Coprocessor Segment Overrun)",
    10 : "#TS (Invalid TSS)",
    11 : "#NP (Segment Not Present)",
    12 : "#SS (Stack Segment Fault)",
    13 : "#GP (General Protection)",
    14 : "#PF (Page Fault)",
    15 : "-- (RESERVED)",
    16 : "#MF (x87 FPU Floating-Point Error)",
    17 : "#AC (Alignment Check)",
    18 : "#MC (Machine Check)",
    19 : "#XM (SIMD Floating-Point Exception)",
    0xFFFF : "#NONE (No Exception)",
}

class Timeout(Exception):
    pass

class Crash(Exception):
    pass

def is_valid_type(typ):
    return ((typ & ~0x1) == 0)

def my_from_buffer_copy(claz, raw, offset=0):
    # Get a pointer to 'raw'
    p = c_char_p(raw)

    # Instantiate object & initialize move memory
    obj = claz()
    memmove(pointer(obj), p, sizeof(claz))

    return obj

class fpust_t(Structure):
    _pack_   = 1
    _fields_ = [("mantissa", c_uint64),
                ("expsign",  c_uint16),
                ("reserved", c_uint8*6)]

class fpuxmm_t(Structure):
    _pack_   = 1
    _fields_ = [("data", c_uint8*16),]

class fpu_state_t(Structure):
    _pack_   = 1
    _fields_ = [("fcw",          c_uint16),
                ("fsw",          c_uint16),
                ("ftw",          c_uint8),
                ("unused",       c_uint8),
                ("fop",          c_uint16),
                ("fpuip",        c_uint32),
                ("cs",           c_uint16),
                ("reserved0",    c_uint16),
                ("fpudp",        c_uint32),
                ("ds",           c_uint16),
                ("reserved1",    c_uint16),
                ("mxcsr",        c_uint32),
                ("mxcsr_mask",   c_uint32),

                ("st",           fpust_t*8),
                ("xmm",          fpuxmm_t*8),
                ("xmm_reserved", fpuxmm_t*14)]

assert sizeof(fpu_state_t) == 512

PRE_TESTCASE     = 0
POST_TESTCASE    = 1
CRASH_TESTCASE   = 0x10
TIMEOUT_TESTCASE = 0x20
IO_TESTCASE      = 0x40

(EMULATOR_QEMU, EMULATOR_BOCHS, EMULATOR_VIRTUALBOX, EMULATOR_VMWARE, EMULATOR_KVM) = xrange(5)
EMULATORS = {
    EMULATOR_BOCHS : "BOCHS",
    EMULATOR_KVM : "KVM",
    EMULATOR_VIRTUALBOX : "VBOX",
    EMULATOR_VMWARE : "VMWARE",
    EMULATOR_QEMU : "QEMU",
    }


class header_t(Structure):
    _pack_   = 1
    _fields_ = [("magic",     c_uint16),
                ("version",   c_uint16),
                ("emulator",  c_uint),
                ("kernel_version",  c_char*16),
                ("kernel_checksum", c_char*64),
                ("testcase_checksum",  c_char*64),
                ("type",      c_uint),
                ("cpusno",    c_uint8),
                ("mem_size",  c_uint32),
                ("ioports",   c_uint8*2)]

class regs_state_t(Structure):
    _pack_   = 1
    _fields_ = [("rax",    c_uint64), ("rbx",    c_uint64), ("rcx",    c_uint64), ("rdx",    c_uint64),
                ("rsi",    c_uint64), ("rdi",    c_uint64), ("rsp",    c_uint64), ("rbp",    c_uint64),
                ("r8",     c_uint64), ("r9",     c_uint64), ("r10",    c_uint64), ("r11",    c_uint64),
                ("r12",    c_uint64), ("r13",    c_uint64), ("r14",    c_uint64), ("r15",    c_uint64),
                ("rip",    c_uint64), ("rflags", c_uint64)]

class segment_reg_t(Structure):
    _pack_   = 1
    _fields_ = [("base",     c_uint64),
                ("limit",    c_uint32),
                ("selector", c_uint16),
                ("type",     c_uint8),
                ("present",  c_uint8), ("dpl",  c_uint8), ("db",  c_uint8), ("s",  c_uint8), 
                ("l",  c_uint8), ("g",  c_uint8), ("avl",  c_uint8),
                ("unusable",  c_uint8)]

class dtable_reg_t(Structure):
    _pack_   = 1
    _fields_ = [("base",  c_uint64),
                ("limit", c_uint16)]

class sregs_state_t(Structure):
    _pack_   = 1
    _fields_ = [("cs", segment_reg_t),  ("ds", segment_reg_t), ("es", segment_reg_t), 
                ("fs", segment_reg_t),  ("gs", segment_reg_t), ("ss", segment_reg_t),
                ("tr", segment_reg_t),  ("ldt", segment_reg_t),
                ("idtr", dtable_reg_t), ("gdtr", dtable_reg_t),
                ("cr0", c_uint64), ("cr1", c_uint64), ("cr2", c_uint64), ("cr3", c_uint64), 
                ("cr4", c_uint64), ("cr8", c_uint64),
                ("dr0", c_uint64), ("dr1", c_uint64), ("dr2", c_uint64), ("dr3", c_uint64), 
                ("dr6", c_uint64), ("dr7", c_uint64), 
                ("efer", c_uint64)]

class msr_reg_t(Structure):
    _pack_   = 1
    _fields_ = [("idx", c_uint32), 
                ("val", c_uint64)]

class msrs_state_t(Structure):
    _pack_   = 1
    _fields_ = [("n",        c_uint32), 
                ("msr_regs", msr_reg_t*MAX_MSRS)]

class exception_state_t(Structure):
    _pack_   = 1
    _fields_ = [("vector", c_uint32), 
                ("error_code", c_uint32)]    

class cpu_state_t(Structure):
    _pack_   = 1
    _fields_ = [("fpu_state",       fpu_state_t),
                ("regs_state",      regs_state_t),
                ("sregs_state",     sregs_state_t),
                ("exception_state", exception_state_t),
                ("msrs_state",      msrs_state_t)]

################################################################################

def exception_has_error_code(x):
    EXC_WITH_ERRCODE = [8, 10, 11, 12, 13, 14, 17]

    if x in EXC_WITH_ERRCODE:
        r = True
    else:
        r = False

    return r

class X86DumpHeader(header_t):
    def __str__(self):
        s = ""
    
        s +=  "* magic:             %.4x\n" % self.magic
        s +=  "* version:           %.4x\n" % self.version

        if self.emulator in EMULATORS:
            tmp = EMULATORS[self.emulator]
        else:
            tmp = "unknown"
        s +=  "* emulator:          %s (%d)\n" % (tmp, self.emulator)
        s +=  "* kernel version:    %s\n" % (self.kernel_version)
        s +=  "* kernel checksum:   %s\n" % (self.kernel_checksum)
        s +=  "* testcase checksum: %s\n" % (self.testcase_checksum)

        tmp = []

        if (self.type & 1) == PRE_TESTCASE:
            tmp = "PRE testcase"
        elif (self.type & 1) == POST_TESTCASE:
            tmp = "POST testcase"
        else:
            tmp = "unknown"

        if (self.type & CRASH_TESTCASE) == CRASH_TESTCASE:
            tmp += ", CRASHED"
        elif (self.type & TIMEOUT_TESTCASE) == TIMEOUT_TESTCASE:
            tmp += ", TIMED_OUT"
        elif (self.type & IO_TESTCASE) == IO_TESTCASE:
            tmp += ", I/O"

        s += "* type:              %s (%d)\n" % (tmp, self.type)
    
        s += "* CPUs:              %.2x\n" % self.cpusno
        s += "* memory:            %.8x (%d)\n" % (self.mem_size, self.mem_size)
        s += "* ioports:           %.2x %.2x\n" % (self.ioports[0], self.ioports[1])
        s += "\n"
    
        return s

def dump_flags(v):
    s = ""

    for offset, letter in [(18,'a'), (17,'v'), (16,'r'), (14,'n'),
                           (11,'o'), (10,'d'),  (9,'i'),  (8,'t'), (7,'s'), 
                           (6,'z'),  (4,'x'),  (2,'p'),  (1,'c')]:
        if ((v >> offset) & 1) == 1:
            s += letter.upper()
        else:
            s += letter.lower()

    return s

def seg2str(name, seg):
    s = ""
    
    return s

def reg2str(name, reg):
    return "%-5s %.16x" % (name + ":", reg)

dump = None

class X86DumpCpuState(cpu_state_t):
    def __str__(self):
        assert dump

        instr = disasm(dump.mem.data[self.regs_state.rip + self.sregs_state.cs.base:self.regs_state.rip + self.sregs_state.cs.base+20])[:1]
        if instr:
            if dump.kernel and dump.kernel.findSection(self.regs_state.rip + self.sregs_state.cs.base):
                sec = " (%s)" % dump.kernel.findSection(self.regs_state.rip + self.sregs_state.cs.base).getName()
            else:
                sec = ""
            instr = "%s%s" % (" ".join(instr[0][2:]), sec)
        else:
            instr = "??????"
        
        s = ""
        # regs_state
        s += "* %-24s %s\n  %-24s\n" % \
            (reg2str("RIP", self.regs_state.rip), instr,
             reg2str("RFLAGS", self.regs_state.rflags) + " (%s)" % dump_flags(self.regs_state.rflags))
        s += "  %-24s %-24s\n" % \
            (reg2str("RSP", self.regs_state.rsp), reg2str("RBP", self.regs_state.rbp))
        s += "  %-24s %-24s %-24s\n" % \
            (reg2str("RAX", self.regs_state.rax), reg2str("RBX", self.regs_state.rbx), reg2str("RCX", self.regs_state.rcx))
        s += "  %-24s %-24s %-24s\n" % \
            (reg2str("RDX", self.regs_state.rdx), reg2str("RSI", self.regs_state.rsi), reg2str("RDI", self.regs_state.rdi))
        # TODO: print only if CPU is working with 64 bits
        s += "  %-24s %-24s %-24s\n" % \
            (reg2str("R08", self.regs_state.r8), reg2str("R09", self.regs_state.r9), reg2str("R10", self.regs_state.r10))
        s += "  %-24s %-24s %-24s\n" % \
            (reg2str("R1", self.regs_state.r11), reg2str("R12", self.regs_state.r12), reg2str("R13", self.regs_state.r13))
        s += "  %-24s %-24s\n" % \
            (reg2str("R14", self.regs_state.r14), reg2str("R15", self.regs_state.r15))            
        s += "\n"

        # sregs_state
        s += "* CS:   %.4x (%.2x %.16x %.8x)\n  DS:   %.4x (%.2x %.16x %.8x)\n  ES:   %.4x (%.2x %.16x %.8x)\n  FS:   %.4x (%.2x %.16x %.8x)\n  GS:   %.4x (%.2x %.16x %.8x)\n  SS:   %.4x (%.2x %.16x %.8x)\n" % \
            (self.sregs_state.cs.selector, self.sregs_state.cs.type, self.sregs_state.cs.base, self.sregs_state.cs.limit, \
             self.sregs_state.ds.selector, self.sregs_state.ds.type, self.sregs_state.ds.base, self.sregs_state.ds.limit, \
             self.sregs_state.es.selector, self.sregs_state.es.type, self.sregs_state.es.base, self.sregs_state.es.limit, \
             self.sregs_state.fs.selector, self.sregs_state.fs.type, self.sregs_state.fs.base, self.sregs_state.fs.limit, \
             self.sregs_state.gs.selector, self.sregs_state.gs.type, self.sregs_state.gs.base, self.sregs_state.gs.limit, \
             self.sregs_state.ss.selector, self.sregs_state.ss.type, self.sregs_state.ss.base, self.sregs_state.ss.limit)

        s += "* TR:   %.4x (%.2x %.16x %.8x)\n  LDT:  %.4x (%.2x %.16x %.8x)\n" % \
            (self.sregs_state.tr.selector,  self.sregs_state.tr.type,  self.sregs_state.tr.base,  self.sregs_state.tr.limit, \
             self.sregs_state.ldt.selector, self.sregs_state.ldt.type, self.sregs_state.ldt.base, self.sregs_state.ldt.limit)

        s += "* IDTR: (%.16x %.8x)\n  GDTR: (%.16x %.8x)\n" % \
            (self.sregs_state.idtr.base, self.sregs_state.idtr.limit, \
             self.sregs_state.gdtr.base, self.sregs_state.gdtr.limit)

        s += "* %-24s %-24s %-24s\n" % \
            (reg2str("CR0", self.sregs_state.cr0), reg2str("CR1", self.sregs_state.cr1), reg2str("CR2", self.sregs_state.cr2))
        s += "  %-24s %-24s %-24s\n" % \
            (reg2str("CR3", self.sregs_state.cr3), reg2str("CR4", self.sregs_state.cr4), reg2str("CR8", self.sregs_state.cr8))

        s += "* %-24s %-24s %-24s\n" % \
            (reg2str("DR0", self.sregs_state.dr0), reg2str("DR1", self.sregs_state.dr1), reg2str("DR2", self.sregs_state.dr2))
        s += "  %-24s %-24s %-24s\n" % \
            (reg2str("DR3", self.sregs_state.dr3), reg2str("DR6", self.sregs_state.dr6), reg2str("DR7", self.sregs_state.dr7))

        s += "* EFER: %.16x\n" % (self.sregs_state.efer)
        s += "\n"

        # fpu_state
        s += "* FCW: %.4x    FSW: %.4x    FTW: %.2x   unused: %.2x   FOP: %.4x\n" % \
            (self.fpu_state.fcw, self.fpu_state.fsw, self.fpu_state.ftw, self.fpu_state.unused, self.fpu_state.fop)

        s +=  "* FPUIP: %.16x   CS: %.4x  RES0: %.4x\n  FPUDP: %.16x   DS: %.4x\n  RES1: %.4x   MXCSR: %.8x   MXCSR_MASK: %.8x\n" % \
            (self.fpu_state.fpuip, self.fpu_state.cs, self.fpu_state.reserved0, self.fpu_state.fpudp, \
             self.fpu_state.ds, self.fpu_state.reserved1, self.fpu_state.mxcsr, self.fpu_state.mxcsr_mask)

        for i in range(8):
            if i == 0:
                s += "*"
            else:
                s += " "
            s +=  " ST%d: (%.16x %.4x %s)\n" % \
                (i, self.fpu_state.st[i].mantissa, self.fpu_state.st[i].expsign, \
                 "".join(["%.2x" % c for c in self.fpu_state.st[i].reserved]))
        s += "\n"

        # MSRs
        s += "* MSR registers (%d)\n" % self.msrs_state.n
        for i in range(self.msrs_state.n):
            msr = self.msrs_state.msr_regs[i]
            s += "   - #%.8x -> %.16x\n" % (msr.idx, msr.val)

        s += "\n"        

        # exception_state
        s += "* Exception state: %-16s\n  Error code:      %.8x\n" % (EXCEPTIONS[self.exception_state.vector], 
                                                                      self.exception_state.error_code)
        
        return s

class X86DumpMemory():
    def __init__(self, raw):
        self.data = raw

    def __str__(self):
        s = ""
        s += "* %d (0x%.8x) bytes [%s ...]\n" % \
            (len(self.data), len(self.data), " ".join(["%.2x" % ord(c) for c in self.data[:32]]))
        return s

class X86Dump():
    def __init__(self, raw, kernel_dir = None):
        # Read a header_t structure
        self.hdr = my_from_buffer_copy(X86DumpHeader, raw)
        assert self.hdr.magic == CPU_STATE_MAGIC and self.hdr.version == CPU_STATE_VERSION

        if not is_valid_type(self.hdr.type):
            # INVALID state
            self.cpus = []
            self.mem = X86DumpMemory("")
        else:
            # VALID state
            # Read 0+ cpu_state_t structures
            self.cpus = []
            next_byte = sizeof(header_t)
            for i in range(self.hdr.cpusno):
                cpu = my_from_buffer_copy(X86DumpCpuState, raw[next_byte:])
                next_byte += sizeof(cpu_state_t)
                self.cpus.append(cpu)

            # Read memory
            self.mem = X86DumpMemory(raw[next_byte:])

            # Fix DR7 register (if needed)
            for i in range(len(self.cpus)):
                self.__fix_dr7(i)

        # Parse kernel's symbols
        if kernel_dir and os.path.isfile(os.path.join(kernel_dir, self.hdr.kernel_checksum)):
            self.kernel = Elf(os.path.join(kernel_dir, self.hdr.kernel_checksum))
        else:
            self.kernel = None

    def __pop(self, x, y):
        # TODO: pop 64-bit
        return struct.unpack("I", self.mem.data[x + 4 * y:(x + 4 * y) + 4])[0]

    def __push(self, x, y, w):
        # TODO: pop 64-bit
        self.mem.data = self.mem.data[:x + 4 *y] + struct.pack("I", w) + self.mem.data[(x + 4 * y) + 4:]
        assert self.__pop(x, y) == w

    def parse_seg(self, i, sel):
        unpack8 = lambda b: struct.unpack('B', b)[0]
        pack8 = lambda b: struct.pack('B', b)

        cpu = self.cpus[i]

        # Read GDT entry
        gdt_base = cpu.sregs_state.gdtr.base
        gdt_limit = cpu.sregs_state.gdtr.limit

        # Extract i-th entry
        gdt_idx = sel >> 3
        assert gdt_idx*8 <= gdt_limit and (gdt_idx*8+8) < gdt_limit
        addr = gdt_idx*8 + gdt_base
        data = self.mem.data[addr:addr+8]

        seg = segment_reg_t()

        # Parse i-th descriptor
        tmp = data[2] + data[3] + data[4] + data[7]
        seg.base = struct.unpack("I", tmp)[0]        
        seg.selector = sel
        seg.type = ((unpack8(data[5])) & 0xf)
        seg.s = ((unpack8(data[5]) >> 4) & 0x1)
        seg.dpl = ((unpack8(data[5]) >> 5) & 0x3)
        seg.present = ((unpack8(data[5]) >> 7) & 0x1)
        seg.avl = ((unpack8(data[6]) >> 4) & 0x1)
        seg.l = ((unpack8(data[6]) >> 5) & 0x1)
        seg.db = ((unpack8(data[6]) >> 6) & 0x1)
        seg.g = ((unpack8(data[6]) >> 7) & 0x1)
        tmp = data[0] + data[1] + pack8(unpack8(data[6]) & 0xf) + '\x00'
        seg.limit = struct.unpack("I", tmp)[0]
        # Scale the limit according to 'granularity'
        # if seg.g: 
        #    seg.limit = seg.limit << 12 | 0xfff

        seg.unusable = 0                                   
        
        return seg

    def __fix_dr7(self, i):
        if self.hdr.type == POST_TESTCASE and \
                (self.hdr.emulator == EMULATOR_KVM or \
                     self.hdr.emulator == EMULATOR_VMWARE or \
                     self.hdr.emulator == EMULATOR_VIRTUALBOX):

            cpu = self.cpus[i]
            rsp = cpu.regs_state.rsp + cpu.sregs_state.ss.base

            stack_dr7 = self.__pop(rsp, 0)
            cpu.sregs_state.dr7 = stack_dr7
                      
    def guess_guest_ctx(self, i):
        cpu = self.cpus[i]
        
        # Refresh descriptors
        seg = cpu.sregs_state
        seg.cs = self.parse_seg(i, seg.cs.selector)
        seg.es = self.parse_seg(i, seg.es.selector)
        seg.ds = self.parse_seg(i, seg.ds.selector)
        seg.fs = self.parse_seg(i, seg.fs.selector)
        seg.gs = self.parse_seg(i, seg.gs.selector)
        seg.ss = self.parse_seg(i, seg.ss.selector)

        rsp = cpu.regs_state.rsp + cpu.sregs_state.ss.base

        # Stack contents:
        # --------------
        # |     DR7    | <--- RSP
        # | error code | <--- only with certain exceptions
        # |     EIP    |
        # |     CS     |
        # |    EFLAGS  |
        # |     ESP    | <--- only on privilege level switch
        # |     SS     | <--- only on privilege level switch
        #
        # We wipe the content of the stack to avoid duplicated differences

        stack_dr7 = self.__pop(rsp, 0)
        self.__push(rsp, 0, 0x12345678)
        stack_error_code = 0
        
        if exception_has_error_code(cpu.exception_state.vector):
            stack_error_code = self.__pop(rsp, 1)
            self.__push(rsp, 1, 0x12345678)
            rsp += 4

        stack_rip = self.__pop(rsp, 1)
        self.__push(rsp, 1, 0x12345678)
        stack_cs  = self.__pop(rsp, 2)
        self.__push(rsp, 2, 0x12345678)
        stack_rflags = self.__pop(rsp, 3)
        self.__push(rsp, 3, 0x12345678)
        stack_rsp = None
        stack_ss = None

        # Privilege level switch
        if stack_cs & 3 !=  cpu.sregs_state.cs.selector & 3:
            stack_esp = self.__pop(rsp, 4)
            self.__push(rsp, 4, 0x12345678)
            stack_ss = self.__pop(rsp, 5)
            self.__push(rsp, 5, 0x12345678)

        # The exception handler is called using "int" and thus EIP points to
        # the next instruction
        if cpu.exception_state.vector == 0xFFFF:
            stack_rip = stack_rip - 2

        # Update the state of the guest
        cpu.regs_state.rip = stack_rip
        cpu.regs_state.rflags = stack_rflags
        cpu.exception_state.error_code = stack_error_code
        if stack_rsp is not None:
            cpu.regs_state.rsp = stack_rsp

        # Sanity check on stack contents
        assert stack_dr7 == cpu.sregs_state.dr7, \
            "[!] Stack DR7 (0x%.8x) != CPU DR7 (0%.8x)" % (stack_dr7, cpu.sregs_state.dr7)

        # Update the segment selectors/descriptors (cs & ss)
        cpu.sregs_state.cs = self.parse_seg(i, stack_cs)
        if stack_ss is not None:  
            cpu.sregs_state.ss = self.parse_seg(i, stack_ss)

    def __str__(self):
        s = ""

        s += "[HEADER]\n" + str(self.hdr)
    
        for i in range(self.hdr.cpusno):
            s += "[CPU #%d]\n" % i
            global dump
            dump = self
            s += str(self.cpus[i])

            s += "\n[GDT #%d]\n" % i
            for sel in range(8,24):
                seg = self.parse_seg(i, sel << 3)
                s += "   [%.2d] [%.2x] Base:%.8x Limit:%.8x Type:%.4x \n" % (sel, seg.selector, seg.base, seg.limit, seg.type)
                

        s += "\n[MEMORY]\n" + str(self.mem)

        return s

def disasm(s, base = 0):
    p = subprocess.Popen(["ndisasm", "-u", "-"], 
                         stdin=subprocess.PIPE, 
                         stdout=subprocess.PIPE)
    out = p.communicate(s)[0]

    insts = []
    for l in out.split("\n"):
        l = l.strip(" \t\r\n")
        if len(l) == 0:
            continue
        l = l.split()
        l = [int(l[0], 16) + base] + l[1:]
        insts.append(l)

    return insts

if __name__ == "__main__":
    import sys, gzip

    args = {
        "update_guest" : os.getenv("KEMUFUZZER_UPDATE_GUEST", False),
        "kernel_dir" : os.getenv("KEMUFUZZER_KERNEL_DIR", None)
        }

    for i in sys.argv[1:]:
        try:
            a, v = i.split(":")
            args[a] = v
        except Exception:
            dump = i
        
    try:
        f = gzip.open(dump).read()
    except IOError:
        f = open(dump).read()

    d = X86Dump(f, kernel_dir = args["kernel_dir"])
    if args["update_guest"]:
        for i in range(len(d.cpus)):
            d.guess_guest_ctx(i)

    print d
