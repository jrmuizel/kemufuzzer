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

import os, sys, pickle, subprocess, tempfile, shutil
from elf import Elf

NULL = open("/dev/null")

def getasm(s, mode="i386"):
    tmp = tempfile.mktemp()
    f = open(tmp, "w")
    f.write(s)
    f.close()
    p = subprocess.Popen(["objdump", "-D", "-m", mode, "-b", "binary", tmp], 
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)

    out, err = p.communicate(s)

    insts = []
    for l in out.split("\n")[7:]:
        l = l.strip(" \t\r\n")
        if len(l) == 0 or l == "...":
            continue

	if len(l.split("\t")) < 3: continue

        addr, code, att = l.split("\t")

        addr = int(addr.strip(":"), 16)
        code = code.strip(" ")
        att = att.strip(" ")
        insts.append((addr, code, att))

    os.unlink(tmp)

    return insts

# Test-case instance (already mutated and complied)
class TestCase:
    def __init__(self, rings, start_ring):
        self.start_ring = start_ring
        self.rings = rings

    def save(self, fname):
        f = open(fname, "w")
        pickle.dump(self, f)
        f.close()

    @staticmethod
    def load(fname):
        f = open(fname)
        r = pickle.load(f)
        f.close()
        return r

    def __str__(self):
        s = ""

        for r in self.rings:
            if len(self.rings[r]) == 0:
                asm = "  <empty>"
            else:
                if r == 4:
                    mode = "i8086"
                else:
                    mode = "i386"
                asm = "\n".join(["  %.4x   %-24s %s" % (i[0], i[1], i[2]) for i in getasm(self.rings[r], mode)])

            if r == self.start_ring:
                tmp = "*"
            else:
                tmp = " "

            if r == 4:
                name = "vm8086"
            else:
                name = "%d" % r

            s += "[%sRING %s]\n%s\n" % (tmp, name, asm)

        return s

######################################################################

# Extract symbols from the kernel
def symbols(f):
    syms = {}

    f = Elf(f)
    for s in ["tcstartring"]:
        s = f.getSymbol(s)
        assert s
        syms[s.getName()] = (s.getAddress(), s.getSize(), f.getOffset(s.getAddress()))
    for s in [".tcring0", ".tcring1", ".tcring2", ".tcring3", ".tcringvm"]:
        s = f.getSection(s)
        assert s
        syms[s.getName()] = (s.getLowAddr(), s.getSize(), s.getOffset())

    return syms


# Patch a binary file
def patchfile(fname, offset, buf):    
    if not buf:
        return
    print "      [*] Patching file @%.8x (%d bytes)" % (offset, len(buf))
    f = open(fname, "r+")
    f.seek(offset, 0)
    f.write(buf)
    f.close()

# Generate a patched kernel and floppy image
def patch(src, patchfunc, *patchfunc_args):
    dest_kernel = tempfile.mktemp(prefix = "kemufuzzer-kernel-")
    dest_floppy = tempfile.mktemp(prefix = "kemufuzzer-floppy-")

    src_kernel, src_floppy = src

    print "[*] Generating new kernel '%s' -> '%s'" % (src_kernel, dest_kernel)
    print "[*] Generating new floppy '%s' -> '%s'" % (src_floppy, dest_floppy)

    # duplicate the kernel
    shutil.copy(src_kernel, dest_kernel)
    # duplicate the image
    shutil.copy(src_floppy, dest_floppy)

    # patch the kernel
    print "[*] Patching kernel '%s'" % (dest_kernel)
    patchfunc(dest_kernel, *patchfunc_args)

    # update the image
    print "[*] Updating floppy '%s'" % (dest_floppy)
    cmdline = "mdel -i %s %s ::" % (dest_floppy, os.path.basename(src_kernel))
    p = subprocess.Popen(cmdline.split(), stdout = NULL, stderr = NULL)
    os.waitpid(p.pid, 0)
    cmdline = "mcopy -i %s %s ::%s" % (dest_floppy, dest_kernel, os.path.basename(src_kernel))
    p = subprocess.Popen(cmdline.split(), stdout = NULL, stderr = NULL)
    os.waitpid(p.pid, 0)


    # delete the temporary kernel
    print "[*] Destroying kernel '%s'" % (dest_kernel)
    os.unlink(dest_kernel)

    return dest_floppy

# Apply the patches to the kernel image
def patchfunc_tc(f, *args):
    s = symbols(f)
    tc = args[0]

    rings_gdt = {0: 0x20, 1: 0x29, 2: 0x32, 3: 0x3b, 4: 0xd3}
    
    # pushf; popf; jump +0; outb; jump +2; 0xffff; hlt
    # endtc = "\x9c\x9d\xeb\x00\xe6\x45\xeb\x02\xff\xff\xf4"
    # outboffset = 4
    # int 31
    endtc = "\xcd\x1f"
    
    # Patch long jump used to invoke the TC
    print "   [*] Setting start ring to %d" % (tc.start_ring)
    patchfile(f, s["tcstartring"][2], chr(rings_gdt[tc.start_ring]))

    # Load each TC in the appropriate section
    for r, o in tc.rings.iteritems():
        if o:
            if r == 4:
                # "ring 4" is a fake ring that indicates code to be executed in vm86-mode
                base = s[".tcringvm"][2]
                name = "vm86"
            else:
                base = s[".tcring%d" % r][2]
                name = "ring%d" % r

            print "   [*] Installing %s code (%d bytes) %s" % (name, len(o), repr(o))
            patchfile(f, base, o)
            patchfile(f, base + len(o), endtc)

def tcgen(t, k, f):
    assert t.endswith(".testcase")
    tc = TestCase.load(t)
    return patch((k, f), patchfunc_tc, tc)

