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

import socket, time, ctypes, math
from x86_cpustate import *

# Enable/disable GDB protocol debugging
DEBUG_MODE   = False

# Modify this to choose between a 32-bit or 64-bit CPU
CPU_BITS = 32

# GDB stop reasons
GDB_SIGNAL_0       = 0
GDB_SIGNAL_INT     = 2
GDB_SIGNAL_TRAP    = 5
GDB_SIGNAL_UNKNOWN = 143

# Input parsing states
STATE_IDLE      = 0
STATE_GETDATA   = 1
STATE_GETCHKSUM = 2

# GDB breakpoint/watchpoint types
GDB_BREAKPOINT_SW     = 0
GDB_BREAKPOINT_HW     = 1
GDB_WATCHPOINT_WRITE  = 2
GDB_WATCHPOINT_READ   = 3
GDB_WATCHPOINT_ACCESS = 4

# Number of CPU registers
if CPU_BITS == 32:
    CPU_NB_REGS = 8
else:
    CPU_NB_REGS = 16

NUM_CORE_REGS = CPU_NB_REGS * 2 + 25

# Indices in registry buffer
IDX_IP_REG    = CPU_NB_REGS
IDX_FLAGS_REG = IDX_IP_REG + 1
IDX_SEG_REGS  = IDX_FLAGS_REG + 1
IDX_FP_REGS   = IDX_SEG_REGS + 6
IDX_XMM_REGS  = IDX_FP_REGS + 16
IDX_MXCSR_REG = IDX_XMM_REGS + CPU_NB_REGS

# General-purpose registers map
if CPU_BITS == 64:
    # see gdb-7.0/gdb/regformats/reg-x86-64.dat
    GPR_MAP = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"]
    GPR_MAP.extend(["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"])
else:
    # see gdb-7.0/gdb/regformats/reg-i386.dat    
    GPR_MAP = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]

# Segment selectors map
SEGS_MAP = ["cs", "ss", "ds", "es", "fs", "gs"]

def hexify(data):
    s = ""
    for c in data:
        s += "%.2x" % ord(c)
    return s

def unhexify(data):
    s = ""
    for i in range(0, len(data), 2):
        n = int(data[i:i+2], 16)
        s += chr(n)
    return s

def decode_register(data, i, sz):
    x = data[i:i+sz/8*2]
    # Transform from little-endian format
    w = ""
    for j in range(0, len(x), 2):
        w = x[j:j+2] + w
    v = int(w, 16)
    n = i + sz/8*2
    return (v, n)

class GDBClient:
    def __init__(self, host, port, ver=None):
        self.__host    = host
        self.__port    = port
        self.__stream  = None
        self.__version = ver    # GDB server variant
        self.__breakpoints = []

    def _calculate_checksum(self, data):
        c = 0
        for x in data:
            c = (c + ord(x)) % 256
        return c

    def _getpkt(self):
        state = STATE_IDLE

        done   = False
        data   = None
        chksum = None
        while not done:
            c = self.__stream.read(1)
            if False and DEBUG_MODE:
                print "[D] {GDBClient} Read character '%s' (%d)" % (c, ord(c))

            if state == STATE_IDLE:
                if c == '+':
                    # ACK packet
                    data = c
                    done = True
                    continue
                elif c == '$':
                    # Start of a new packet
                    state = STATE_GETDATA
                    data = ""
                else:
                    # Unexpected character -- ignore it
                    pass
            elif state == STATE_GETDATA:
                if c == '#':
                    # End of data & start of checksum
                    state = STATE_GETCHKSUM
                    chksum = ""
                else:
                    data += c
            elif state == STATE_GETCHKSUM:
                chksum += c
                if len(chksum) == 2:
                    # Verify checksum
                    if self._calculate_checksum(data) == int(chksum, 16):
                        done = True
                    else:
                        # NACK & Reset
                        print "[D] {GDBClient} Checksum verification failed for $%s#%.2x (expected: %.2x)" % \
                            (data, int(chksum, 16), self._calculate_checksum(data))
                        self._putpkt('-')
                        state  = STATE_IDLE
                        data   = None
                        chksum = None

        if DEBUG_MODE:
            print "[D] {GDBClient} Received packet '%s'" % data

        return data
                

    def _putack(self):
        if DEBUG_MODE:
            print "[D] {GDBClient} Sending ACK"

        self.__stream.write('+')
        self.__stream.flush()

    def _putpkt(self, data):
        c = self._calculate_checksum(data)
        p = "$%s#%.2x" % (data, c)

        if DEBUG_MODE:
            print "[D] {GDBClient} Sending packet '%s'" % p

        self.__stream.write(p)
        self.__stream.flush()

    def _parsestoppkt(self, data):
        r = None
        if data[0] == 'T':
            r = int(data[1:3], 16)
            if DEBUG_MODE:
                print "[D] {GDBClient} Target interrupted by signal #%d (%.2x)" % (r, r)
        else:
            assert False, "[!] {GDBClient} Unexpected stop reason"
        return r

    def reconnect(self):
        # Kill current connection and create a new one, restoring existing
        # breakpoints
        bb = self.__breakpoints[:]
        del self.__breakpoints[:]
        self.kill()

        self.connect()
        for a,t,s in bb:
            self.setBreakpoint(addr=a, typ=t, sz=s)

    def connect(self):
        n_tries = 0

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        connected = False
        while not connected:
            try:
                s.connect((self.__host, self.__port))
                connected = True
            except socket.error, e:
                if n_tries > 10:
                    raise e
                n_tries += 1
                print "[W] {GDBClient} Connection attempt #%d has failed" % n_tries
                time.sleep(1)

        self.__stream = s.makefile()

        # Connection established
        self._putpkt("qSupported")   # Ask capabilities to server
        assert self._getpkt() == '+' # Wait for ACK
        self._getpkt()               # Read capabilities
        self._putack()               # Send ACK

    def detach(self):
        self._putpkt("D")            # Send detach command
        assert self._getpkt() == '+' # Wait for ACK

    def readMemory(self, baseaddr, totalsz):
        MAX_BLOCK_SIZE = 256

        raw = ""
        
        for i in range(int(math.ceil(totalsz/float(MAX_BLOCK_SIZE)))):
            addr = baseaddr + (i*MAX_BLOCK_SIZE)
            sz = min(totalsz-(i*MAX_BLOCK_SIZE), MAX_BLOCK_SIZE)

            m = "m%x,%x" % (addr, sz)
            self._putpkt(m)
            assert self._getpkt() == '+'
            data = self._getpkt()
            self._putack()               # Send ACK

            assert len(data) == sz*2, "[!] Not enough data (received: %d bytes -- expected: %d bytes)" % (len(data), sz*2)

            for i in range(0, len(data), 2):
                b = data[i:i+2]
                raw += chr(int(b, 16))

        return raw

    def writeMemory(self, addr, raw):
        m = "M%x,%d:" % (addr, len(raw)/2)
        for c in raw:
            m += "%.2x" % ord(c)
        self._putpkt(m)
        assert self._getpkt() == '+'
        assert self._getpkt() == 'OK'       

    def setBreakpoint(self, addr, typ=GDB_BREAKPOINT_SW, sz=1):
        if addr in [a for a,t,s in self.__breakpoints]:
            # Already exists
            return True

        m = "Z%s,%.8x,%d" % (typ, addr, sz)
        self._putpkt(m)
        assert self._getpkt() == '+'
        p = self._getpkt()
        self._putack()

        if p == '':
            # No more breakpoints available
            return False

        assert p == 'OK'
        self.__breakpoints.append((addr, typ, sz))
        return True

    def getBreakpoint(self, addr):
        bb = []
        for a,t,s in self.__breakpoints:
            if a == addr:
                bb.append((a,t,s))
        return bb

    def delBreakpoint(self, addr):
        # Remove *all* the breakpoints at the supplied address
        removed = []
        for a,t,s in self.__breakpoints:
            if a == addr:
                m = "z%s,%.8x,%d" % (t, a, s)
                self._putpkt(m)
                assert self._getpkt() == '+'
                assert self._getpkt() == 'OK'
                self._putack()
                removed.append((a, t, s))

        for t in removed:
            self.__breakpoints.remove(t)

    def doSingleStep(self):
        self._putpkt("s")
        assert self._getpkt() == '+'
        ans = self._getpkt()
        self._putack()

        r = self._parsestoppkt(ans)
        assert r == GDB_SIGNAL_TRAP
        return r

    def resume(self):
        # Check for a breakpoint at current position
        rip = self.getRegister('rip')
        if DEBUG_MODE:
            print "[D] {GDBClient} Resuming from address %.8x" % rip

        bb  = self.getBreakpoint(rip)
        if len(bb) > 0:
            # We have some breakpoint at address 'rip'. Check any of
            # these breakpoints is on-execution.
            tt = set([x[1] for x in bb])
            if GDB_BREAKPOINT_SW in tt or GDB_BREAKPOINT_HW in tt:
                self.delBreakpoint(rip)
                self.doSingleStep()
                for a, t, s in bb:
                    r = self.setBreakpoint(addr=a, typ=t, sz=s)
                    assert r == True

        self._putpkt("c")
        assert self._getpkt() == '+'
        ans = self._getpkt()
        self._putack()

        return self._parsestoppkt(ans)

    def getRegister(self, r):
        cpu = self.getRegisters()
        if r == "rip":
            v = cpu.regs_state.rip
        else:
            assert False, "[!] {GDBClient} Unknown register '%s'" % r

        return v

    def getRegisters(self):
        self._putpkt("g")
        assert self._getpkt() == '+'
        data = self._getpkt()

        cpu = X86DumpCpuState()
        memset(byref(cpu), 0, sizeof(cpu))

        i = 0
        for rnum in range(NUM_CORE_REGS):
            if i >= len(data):
                # No more data...
                break

            if rnum < CPU_NB_REGS:
                # General purpose register
                v, i = decode_register(data, i, CPU_BITS)
                cpu.regs_state.__setattr__(GPR_MAP[rnum], ctypes.c_uint64(v))
            elif rnum == IDX_IP_REG:
                # RIP register
                v, i = decode_register(data, i, CPU_BITS)
                cpu.regs_state.rip = ctypes.c_uint64(v)
            elif rnum == IDX_FLAGS_REG:
                # RFLAGS register
                v, i = decode_register(data, i, CPU_BITS)
                cpu.regs_state.rflags = ctypes.c_uint64(v)
            elif IDX_SEG_REGS <= rnum < IDX_SEG_REGS+6:
                # Segment selector
                v, i = decode_register(data, i, CPU_BITS)
                cpu.sregs_state.__getattribute__(SEGS_MAP[rnum-IDX_SEG_REGS]).selector = ctypes.c_uint16(v)
            elif IDX_FP_REGS <= rnum < IDX_FP_REGS+8:
                # ST registers: 64-bit mantissa + 16-bit exponent
                man, i = decode_register(data, i, 64)
                exp, i = decode_register(data, i, 16)
                cpu.fpu_state.st[rnum-IDX_FP_REGS].mantissa = ctypes.c_uint64(man)
                cpu.fpu_state.st[rnum-IDX_FP_REGS].expsign  = ctypes.c_uint16(exp)
            elif IDX_FP_REGS+8 <= rnum < IDX_FP_REGS+16:
                v, i = decode_register(data, i, CPU_BITS)
                if rnum == IDX_FP_REGS+8:
                    # "fpuc"
                    cpu.fpu_state.fcw = ctypes.c_uint16(v)
                elif rnum == IDX_FP_REGS+9:
                    # "fpus"
                    cpu.fpu_state.fsw = ctypes.c_uint16(v)
                elif rnum == IDX_FP_REGS+10:
                    # "ftag"
                    cpu.fpu_state.ftw = ctypes.c_uint8(v)
                elif rnum == IDX_FP_REGS+11:
                    # "fiseg"
                    cpu.fpu_state.cs = ctypes.c_uint16(v)
                elif rnum == IDX_FP_REGS+12:
                    # "fioff"
                    cpu.fpu_state.fpuip = ctypes.c_uint32(v)
                elif rnum == IDX_FP_REGS+13:
                    # "foseg"
                    cpu.fpu_state.ds = ctypes.c_uint16(v)
                elif rnum == IDX_FP_REGS+14:
                    # "fooff"
                    cpu.fpu_state.fpudp = ctypes.c_uint32(v)
                elif rnum == IDX_FP_REGS+15:
                    # "fop"
                    cpu.fpu_state.fop = ctypes.c_uint16(v)

            elif IDX_XMM_REGS <= rnum < IDX_XMM_REGS+CPU_NB_REGS:
                # XMM registers
                v, i = decode_register(data, i, 128)
                regs.append(("xmm%d" % (rnum-IDX_XMM_REGS), v))
            elif rnum == IDX_MXCSR_REG:
                # MXCSR
                v, i = decode_register(data, i, CPU_BITS)
                cpu.fpu_state.mxcsr = ctypes.c_uint32(v)

        assert i == len(data), "[!] {GDBClient} Register data is longer than expected"

        self._putack()

        if self.__version == "vmware":
            self.getVMwareRegisters(cpu)

        return cpu

    def _putmonitor(self, m):
        p = "qRcmd,%s" % hexify(m)
        self._putpkt(p)        
        assert self._getpkt() == '+'

        ans = ""
        while True:
            p = self._getpkt()
            self._putack()

            if p == "OK":
                # A command response with no output
                break
            elif p == "":
                # An empty reply indicates that "qRcmd" is not recognized
                ans = None
            elif p[0] == "O":
                # Intermediate `Ooutput' console output packets
                ans += unhexify(p[1:])
            else:
                ans += unhexify(p)

        return ans

    # Receives in input a cpu_state_t structure to update.
    def getVMwareRegisters(self, cpu):
        ans = self._putmonitor("help r")
        assert ans.startswith("Dump hidden register")

        for l in ans.split("\n")[2:]:
            l = l.strip()
            data = self._putmonitor("r %s" % l)
            data = data.strip("\n ")
            if "not supported in real mode" in data:
                pass
            elif len(data) == 0:
                # Empty line
                continue
            else:
                if data.startswith("cr"):
                    # Control register
                    v = int(data.split("=")[1], 16)
                    cpu.sregs_state.__setattr__(l, ctypes.c_uint64(v))
                elif l in ["gdtr", "idtr"]:
                    # GDTr/IDTr
                    data = data.replace(l, "").strip().split()
                    assert len(data) == 2
                    data = (int(data[0].split("=")[1], 16), int(data[1].split("=")[1], 16))
                    # 'data' is now a (base, limit) pair

                    x = cpu.sregs_state.__getattribute__(l)
                    x.base  = data[0]
                    x.limit = data[1]
                elif l in ["cs", "ds", "es", "fs", "gs", "ss", "ldtr"]:
                    if l == "ldtr":
                        l = "ldt"
                        data = data.replace("sel ", "")

                    data = data.split()[1::2]
                    x = cpu.sregs_state.__getattribute__(l)

                    x.selector = ctypes.c_uint16(int(data[0],16))
                    x.base     = ctypes.c_uint64(int(data[1],16))
                    x.limit    = ctypes.c_uint32(int(data[2],16))
                    x.type     = ctypes.c_uint8(int(data[3],16))
                    x.s        = ctypes.c_uint8(int(data[4],16))
                    x.dpl      = ctypes.c_uint8(int(data[5],16))
                    x.present  = ctypes.c_uint8(int(data[6],16))
                    x.db       = ctypes.c_uint8(int(data[7],16))
                else:
                    assert False, "[!] {GDBClient} Unexpected register '%s': %s" % (l, data)

    def __del__(self):
        self.kill()

    def kill(self):
        if self.__stream is not None:
            print "[*] {GDBClient} Closing connection with %s:%d" % (self.__host, self.__port)
            self.__stream.close()
            self.__stream = None


