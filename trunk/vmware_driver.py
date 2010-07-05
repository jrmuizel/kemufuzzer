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

import os, sys, hashlib
KEMUFUZZER_PATH = os.path.dirname(os.path.abspath(sys.argv[0]))
sys.path.append(KEMUFUZZER_PATH)

import subprocess, signal, gzip, tempfile, shutil, struct
from gdb import GDBClient
from x86_cpustate import *
from elf import Elf

KERNEL_FILE  = os.path.join(KEMUFUZZER_PATH, "kernel/kernel")
DISK_FILE    = os.path.join(KEMUFUZZER_PATH, "kernel/floppy.img")
VMX_FILE     = os.path.join(KEMUFUZZER_PATH, "../emulatori/vmware-workstation7/bee.vmx")
VMDK_FILE    = os.path.join(KEMUFUZZER_PATH, "../emulatori/vmware-workstation7/bee.vmdk")

MEMORY_SIZE         = 4 * 1024 * 1024

DEFAULT_PRESTATE_FILE  = "/tmp/vmware-dump-pre.gz"
DEFAULT_POSTSTATE_FILE = "/tmp/vmware-dump-post.gz"

EXCEPTION_NONE      = 0xFFFF

# Maps a DPL to a pair (name, selector) for its TSS.
DPL_TO_TSS = {0: ('tss3', (0x20|0)), 
              1: ('tss4', (0x28|1)), 
              2: ('tss5', (0x30|2)), 
              3: ('tss6', (0x38|3)),
              4: ('tssVM', (0xd3))}

##################################################

def alarm_handler(signum, frame):
    raise Timeout()

def parse_seg(sel, cpu, mem):
    unpack8 = lambda b: struct.unpack('B', b)[0]
    pack8 = lambda b: struct.pack('B', b)

    # Read GDT entry
    gdt_base = cpu.sregs_state.gdtr.base
    gdt_limit = cpu.sregs_state.gdtr.limit

    # Extract i-th entry
    gdt_idx = sel >> 3

    if not (gdt_idx*8 <= gdt_limit and (gdt_idx*8+8) < gdt_limit):
        # Invalid GDT index
        print "[W] Invalid GDT selector %.4x (index: %.4x, limit: %.4x)" % (sel, gdt_idx, gdt_limit)
        return None

    addr = gdt_idx*8 + gdt_base
    data = mem[addr:addr+8]

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

class Emulator:
    def __init__(self, cmdline, memorysz, kernel, disk):
        self.kernel = kernel
        self.disk = disk
        self.cmdline  = cmdline
        self.memorysz = memorysz
        self.pid = None

    def run(self):
        p = subprocess.Popen(self.cmdline.split())
        self.pid = p.pid

    def kill(self):
        self.pid = None

    def isRunning(self):
        return self.pid is not None

    def getGDBVersion(self):
        abstract()

    def getGDBPort(self):
        abstract()

    def dumpState(self, filename, typ, tcfinger):
        abstract()

    def __del__(self):
        self.kill()

class EmulatorQEMU(Emulator):
    def __init__(self, memorysz = 0, kernel = KERNEL_FILE, disk = DISK_FILE):
        Emulator.__init__(self, cmdline, memorysz, kernel, disk)

    def getGDBVersion(self):
        return "qemu"

    def getGDBPort(self):
        return 1234

    def kill(self):
        if self.isRunning():
            print "[*] Killing emulator process #%d" % self.pid
            os.kill(self.pid, signal.SIGTERM)
            Emulator.kill(self)

class EmulatorVMware(Emulator):
    def __init__(self, cmd_start, cmd_stop, cmd_suspend, memorysz = 0, 
                 vmx = VMX_FILE, kernel = KERNEL_FILE, disk = DISK_FILE):
        self.vmx = vmx
        self.cmd_start = cmd_start
        self.cmd_stop = cmd_stop
        self.cmd_suspend = cmd_suspend

        Emulator.__init__(self, cmd_start, memorysz, kernel, disk)

    def getGDBVersion(self):
        return "vmware"

    def getGDBPort(self):
        return 8832

    def kill(self):
        if self.isRunning():
            print "[*] Stopping vmware process #%d" % self.pid
            os.system(self.cmd_stop)
            Emulator.kill(self)
        
    def dumpState(self, gdb, filename, typ, tcfinger, exc = EXCEPTION_NONE, tasks = None):
        assert typ in [PRE_TESTCASE, POST_TESTCASE], "[!] Invalid dump type #%d" % typ
        
        hdr = header_t()
        hdr.magic      = CPU_STATE_MAGIC
        hdr.version    = CPU_STATE_VERSION
        hdr.emulator   = EMULATOR_VMWARE
        hdr.kernel_version="protected mode +"
        hdr.kernel_checksum= hashlib.md5(open(KERNEL_FILE).read()).hexdigest()
	hdr.testcase_checksum = tcfinger
        hdr.type       = typ
        hdr.cpusno     = 1
        hdr.mem_size   = self.memorysz
        hdr.ioports[0] = KEMUFUZZER_HYPERCALL_START_TESTCASE
        hdr.ioports[1] = KEMUFUZZER_HYPERCALL_STOP_TESTCASE

        # Read current CPU state
        cpu = gdb.getRegisters()

        if tasks is not None:
            # Check if RIP falls inside a task area
            for n, v in tasks.iteritems():
                if v[0] <= cpu.regs_state.rip <= v[1]:
                    cpu.regs_state.rip -= v[0]
        
        # Update exception state
        cpu.exception_state.vector = c_uint32(exc)
        cpu.exception_state.error_code = c_uint32(0)

        # Read system memory
        mem = self.readAllMemory(gdb)

        # Normalize state
        hdr, cpus, mem = self.__normalize(typ, hdr, [cpu], mem)
        cpu = cpus[0]

        # Write data to file
        f = gzip.open(filename, 'w')
        s = string_at(byref(hdr), sizeof(hdr))
        f.write(s)
        s = string_at(byref(cpu), sizeof(cpu))        
        f.write(s)
        f.write(mem)
        f.close()

    def __normalize(self, typ, hdr, cpus, mem):
        elf = Elf(self.kernel)

        for i in range(hdr.cpusno):
            c = cpus[i]

            #### Normalize task-register (TR) ####
            c.sregs_state.tr.present  = 0x1
            c.sregs_state.tr.type     = 0xb
            c.sregs_state.tr.limit    = 0x68

            if typ == PRE_TESTCASE:
                # Use 'main' TSS
                c.sregs_state.tr.base     = elf.getSymbol('tss0').getAddress()
                c.sregs_state.tr.dpl      = 0x0
                c.sregs_state.tr.selector = 0x8
            else:
                pop = lambda x,y: struct.unpack("I", mem[x + 4 * y:(x + 4 * y) + 4])[0]

                # Choose the correct TSS for current CPL
                rsp = c.regs_state.rsp + c.sregs_state.ss.base
                if exception_has_error_code(c.exception_state.vector):
                    rsp += 4

                stack_cs_sel  = pop(rsp, 2)
                stack_cs = parse_seg(stack_cs_sel, c, mem)
                if stack_cs is not None:
                    c.sregs_state.tr.dpl      = stack_cs.dpl
                    c.sregs_state.tr.base     = elf.getSymbol(DPL_TO_TSS[stack_cs.dpl][0]).getAddress()
                    c.sregs_state.tr.selector = DPL_TO_TSS[stack_cs.dpl][1]

            #### Normalize MSR registers ####
            c.msrs_state.n = 3

            c.msrs_state.msr_regs[0].idx = X86_MSR_IA32_SYSENTER_CS
            c.msrs_state.msr_regs[0].val = 0x68

            c.msrs_state.msr_regs[1].idx = X86_MSR_IA32_SYSENTER_ESP
            c.msrs_state.msr_regs[1].val = 0x800

            c.msrs_state.msr_regs[2].idx = X86_MSR_IA32_SYSENTER_EIP
            c.msrs_state.msr_regs[2].val = elf.getSection('.tcring0').getLowAddr()

            #### Normalize segment descriptors ####

            # Fix granularity bits (both in pre- and post-states)
            c.sregs_state.cs.g     = 1
            c.sregs_state.ds.g     = 1
            c.sregs_state.es.g     = 1
            c.sregs_state.fs.g     = 1
            c.sregs_state.gs.g     = 1
            c.sregs_state.ss.g     = 1

            if typ == PRE_TESTCASE:
                # PRE-normalization
                gdt = elf.getSymbol('gdt').getAddress()

                for s in [c.sregs_state.ds, c.sregs_state.es, c.sregs_state.fs,
                          c.sregs_state.gs, c.sregs_state.ss]:
                    # Mark as accessed
                    s.type |= 1

                    # Fix GDT
                    gdt_index = s.selector >> 3
                    gdt_addr  = gdt + (gdt_index * 8) + 4
                    data = struct.unpack("I", mem[gdt_addr:gdt_addr+4])[0]
                    data |= 0x100
                    data = struct.pack("I", data)
                    mem = mem[:gdt_addr] + data + mem[gdt_addr+4:]

        return (hdr, cpus, mem)

    def readAllMemory(self, gdb=None):
        # 1. Suspend VMware
        os.system(self.cmd_suspend)

        # 2. Detach debugger
        if gdb:
            gdb.kill()

        # 3. Read memory image
        f = open(self.vmx.replace(".vmx", ".vmem"), 'r')
        data = f.read()
        f.close()

        # 4. Resume VMware
        self.run()

        # 5. Re-connect debugger
        if gdb:
            gdb.reconnect()

        return data

###########################################################################

def read_beefinger():
    rev, md5 = None, None

    f = open('beefinger.h', 'r')
    for l in f.readlines():
        l = l.strip(" \t\n\r")
        if not l.startswith("#define"):
            continue
        l = l.replace("#define", "").strip()
        if l.startswith("BEE_SVN"):
            rev = l.split()[-1].replace('"', "")
        elif l.startswith("BEE_MD5"):
            md5 = l.split()[-1].replace('"', "")
    f.close()
    assert rev is not None and md5 is not None, "[!] Error parsing BEE fingerprint file"

    s = "%s-%s" % (rev, md5)
    return s

def load_symbols(k):
    symbols = {}
    tasks   = {0: [0,0], 1: [0,0], 2: [0,0], 3: [0,0], 4:[0,0]}

    cmdline = "nm %s" % k
    p = subprocess.Popen(cmdline.split(), stdout=subprocess.PIPE)

    for l in p.stdout.readlines():
        # Symbols
        l = l.strip().split()
        if l[-1].startswith("notify_int") or \
                l[-1] in ["tcring0", "tcring1", "tcring2", "tcring3", "tcringvm", "testcase_start"]:
            symbols[l[-1]] = int(l[0], 16)

        # Tasks
        if l[-1].startswith("tcring"):
            # check tcringvm - VM8086
            if l[-1].startswith("tcringvm"):
                v= int(l[0], 16)
                if l[-1].endswith("end"):
                    tasks[4][1]=v-1;
                else:
                    tasks[4][0]=v;
            else:
                n = int(l[-1][6])
                v = int(l[0], 16)
                if l[-1].endswith("end"):
                    tasks[n][1] = v-1
                else:
                    tasks[n][0] = v

    return symbols, tasks

def show_help():
    print "Syntax: python %s" % sys.argv[0]

def compare_symbols(a,b):
    data = [a,b]
    for i in range(len(data)):
        v = data[i]
        if v.startswith("notify_int"):
            v = int(v.replace("notify_int", ""))
        elif v.startswith("tcring") or v == "testcase_start":
            # HACK: raise priority of V
            v = -1
        data[i] = v
    return cmp(data[0], data[1])

def guess_exit_reason(rip, symbol_name):
    if symbol_name == "tcringXend":
        # Testcase completed with no exception
        r = EXCEPTION_NONE
    elif symbol_name.startswith("notify_int"):
        r = int(symbol_name.replace("notify_int", ""))
    elif symbol_name == "testcase_start":
        # Reboot -- Simulate a crash
        print "[!] Reboot detected!"
        r = None
    else:
        assert False, "[!] Unknown post symbol '%s' (@%.8x)" % (symbol_name, rip)
    return r

def init_cmds(disk, vmx, gui):
    qemu_start     = "qemu -fda %s -s -S" % disk

    if gui:
        display = "gui"
    else:
        display = "nogui"
    vmware_start   = "vmrun -T ws start %s %s" % (vmx, display)
    vmware_stop    = "vmrun -T ws stop %s" % vmx
    vmware_suspend = "vmrun -T ws suspend %s" % vmx

    return qemu_start, vmware_start, vmware_stop, vmware_suspend

def run(kernel = KERNEL_FILE, disk = DISK_FILE, gui = False, timeout = None): 
    assert os.path.isfile(kernel) and os.path.isfile(disk)

    vmx = prepare_vmx(disk)
    assert os.path.isfile(vmx)

    qemu_start, vmware_start, vmware_stop, vmware_suspend = init_cmds(disk, vmx, gui)

    prestate  = os.environ.get("KEMUFUZZER_PRE_STATE", DEFAULT_PRESTATE_FILE)
    poststate = os.environ.get("KEMUFUZZER_POST_STATE", DEFAULT_POSTSTATE_FILE)
    tcfinger  = os.environ.get("KEMUFUZZER_TESTCASE_CHECKSUM", "????????????????")

    assert tcfinger is not None

    print "[*] Loading symbols from kernel image..."
    symbols, tasks = load_symbols(kernel)
    assert "tcring0" in symbols and "testcase_start" in symbols

    # Build the symbol that marks the end of a testcase
    symbols['tcringXend'] = symbols['notify_int31']
    
    # 'tcringX' symbols are not needed anymore
    for i in range(4):
        n = "tcring%d" % i
        if symbols.has_key(n):
            del symbols[n]

    # Build reverse symbols map
    reverse_symbols = {}
    for k,v in symbols.iteritems():
        reverse_symbols[v] = k

    print "[*] Starting emulator (vmx: %s, disk: %s) ..." % (vmx, disk)
    emu = EmulatorVMware(cmd_start = vmware_start, cmd_stop = vmware_stop, 
                         cmd_suspend = vmware_suspend,
                         memorysz = MEMORY_SIZE, vmx = vmx,
                         kernel = kernel, disk = disk)
    emu.run()
    gdb = GDBClient(host="127.0.0.1", port=emu.getGDBPort(), ver=emu.getGDBVersion())
    gdb.connect()
    print "[*] Debugger connected!"

    # Set breakpoints
    i = 0
    kk = symbols.keys()
    kk.sort(cmp=compare_symbols)

    set_breakpoints = []
    for k in kk:
        v = symbols[k]
        i += 1
        r = gdb.setBreakpoint(v)
        if not r:
            print "[W] No more breakpoints available for symbol '%s'" % k
            break
        else:
            set_breakpoints.append(k)
    print "[*] A breakpoint has been set at the following symbols: %s" % set_breakpoints

    # Set timeout
    if timeout is not None:
        print "[*] Setting timeout to %d seconds" % timeout
        signal.signal(signal.SIGALRM, alarm_handler)
        signal.alarm(timeout)

    # Continue until the testcase begins
    print "[*] Resuming execution"
    r = gdb.resume()
    rip = gdb.getRegister('rip')
    if reverse_symbols.get(rip) == "testcase_start" or reverse_symbols.get(rip).startswith("tcring"):
        r = EXCEPTION_NONE
    print "[*] Execution interrupted with reason %.2x" % r
    print "\t- RIP: %.8x (%s)" % (rip, reverse_symbols.get(rip))
    print "\t- raw data @%.8x: %s" % (rip, repr(gdb.readMemory(rip, 16)))
    assert reverse_symbols.get(rip) == "testcase_start"

    tmpfilename = tempfile.mktemp(prefix = "kemufuzzer-")
    emu.dumpState(gdb, tmpfilename, PRE_TESTCASE, tcfinger, exc = r, tasks = tasks)
    shutil.move(tmpfilename, prestate)
    print "[*] Pre-execution state dumped to '%s'" % prestate

    # Continue until next exception
    print "[*] Resuming execution"
    r = gdb.resume()
    rip = gdb.getRegister('rip')
    r = guess_exit_reason(rip, reverse_symbols.get(rip))

    if r is None:
        # Execution has crashed
        if timeout is not None:
            signal.alarm(0)
        raise Crash()

    print "[*] Execution interrupted with reason %.2x" % r
    print "\t- RIP: %.8x (%s)" % (rip, reverse_symbols.get(rip))
    print "\t- raw data @%.8x: %s" % (rip, repr(gdb.readMemory(rip, 16)))

    emu.dumpState(gdb, tmpfilename, POST_TESTCASE, tcfinger, r, tasks = tasks)
    shutil.move(tmpfilename, poststate)
    print "[*] Post-execution state dumped to '%s'" % poststate

    # All done, detach
    gdb.detach()
    print "[*] Debugger detached!"

    # Disable the alarm
    if timeout is not None:
        signal.alarm(0)

    # Stop emulator
    del emu

    # Delete temporary files
    print "[*] Flushing temporary files.."
    for x in ["vmxf", "vmsd", "vmx.lck", "vmx"] :
        n = vmx.replace(".vmx", ".%s" % x)
        if os.path.isdir(n):
            shutil.rmtree(n)
        elif os.path.isfile(n):
            os.unlink(n)

def prepare_vmx(disk):
    template = """
#!/usr/bin/vmware
.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "7"
maxvcpus = "4"
scsi0.present = "TRUE"
memsize = "4"
ide0:0.present = "TRUE"
ide0:0.fileName = "%s"
ide1:0.present = "FALSE"
ide1:0.fileName = "/dev/hdc"
ide1:0.deviceType = "cdrom-raw"
floppy0.startConnected = "TRUE"
floppy0.fileName = "%s"
floppy0.autodetect = "TRUE"
sound.present = "FALSE"
sound.fileName = "-1"
sound.autodetect = "TRUE"
pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
pciBridge5.present = "TRUE"
pciBridge5.virtualDev = "pcieRootPort"
pciBridge5.functions = "8"
pciBridge6.present = "TRUE"
pciBridge6.virtualDev = "pcieRootPort"
pciBridge6.functions = "8"
pciBridge7.present = "TRUE"
pciBridge7.virtualDev = "pcieRootPort"
pciBridge7.functions = "8"
vmci0.present = "TRUE"
roamingVM.exitBehavior = "go"
displayName = "bee"
guestOS = "other"
nvram = "bee.nvram"
virtualHW.productCompatibility = "hosted"
extendedConfigFile = "bee.vmxf"
ide1:0.startConnected = "FALSE"
floppy0.fileType = "file"
floppy0.clientDevice = "FALSE"
sound.startConnected = "FALSE"
uuid.location = "56 4d c9 20 8c 69 9a e3-59 d0 d0 3e 24 66 65 8e"
uuid.bios = "56 4d c9 20 8c 69 9a e3-59 d0 d0 3e 24 66 65 8e"
cleanShutdown = "TRUE"
replay.supported = "TRUE"
replay.filename = ""
ide0:0.redo = ""
pciBridge0.pciSlotNumber = "17"
pciBridge4.pciSlotNumber = "21"
pciBridge5.pciSlotNumber = "22"
pciBridge6.pciSlotNumber = "23"
pciBridge7.pciSlotNumber = "24"
scsi0.pciSlotNumber = "16"
sound.pciSlotNumber = "32"
vmci0.pciSlotNumber = "33"
vmotion.checkpointFBSize = "16777216"
vmci0.id = "-536728653"

logging = "FALSE"
debugStub.listen.guest32 = "1"
monitor.debugOnStartGuest32 = "TRUE"   # halt on first instruction
debugStub.hideBreakpoints= "1"
checkpoint.vmState = ""
""" % (os.path.abspath(VMDK_FILE), os.path.abspath(disk))

    fd, name = tempfile.mkstemp(prefix="kemufuzzer-vmx-", suffix=".vmx")

    os.write(fd, template)
    os.close(fd)

    return name

if __name__ == "__main__":
    kernel = KERNEL_FILE
    disk   = DISK_FILE

    for a in sys.argv[1:]:
        n,v = a.split(":")
        if n == 'kernel':
            kernel = v
        elif n == 'disk':
            disk = v
        else:
            assert False, "[!] Unknown option '%s'" % n

    run(kernel = kernel, disk = disk)
