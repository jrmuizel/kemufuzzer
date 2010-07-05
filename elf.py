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

# Copyright notice
# ================
# 
# Copyright (C) 2006-2010
#     Lorenzo Martignoni <lorenzo@idea.sec.dico.unimi.it>
#     Roberto Paleari <roberto@idea.sec.dico.unimi.it>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.  
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.


import mmap, os, struct
import traceback
import warnings
warnings.filterwarnings('ignore', category=FutureWarning)

###############################################################################
# Executable file abstraction
###############################################################################
class File(object):
    def __init__(self, name = None, buf = None):
	self.__name = name
	if self.__name is not None:
	    self.__size = os.path.getsize(name)
	    self.__fileobject = open(name, "rb")
	    # self.__buf = mmap.mmap(self.__fileobject.fileno(), self.__size, mmap.MAP_SHARED, mmap.ACCESS_READ)
            self.__buf = self.__fileobject.read()
            self.__fileobject = None
	else:
	    assert buf is not None
	    self.__buf = buf
	    self.__size = len(self.__buf)
	    self.__fileobject = None

	self.__sections = []
	self.__symbols = {}
	self.__symbols_names = {}
        self.__libraries = {}
        self.__entrypoint = 0x0
        self.__imagebase = 0x0
        self.__type = "raw"
        self.__machine = None

    # def __del__(self):
	# if self.__name is not None:
	#    self.__buf.close()
	#    self.__fileobject.close()

    def __str__(self):
        r = "File (%s): %s (%d bytes)\n" % (self.__type, self.__name, self.__size)
        r+= "Imagebase: %.8x\n" % (self.__imagebase)
        r += "\nSections:\n"
        for s in self.__sections:
            r += " * " + str(s) + "\n"

        r += "\nSymbols:\n"
        for s in self.__symbols.itervalues():
            r += " * " + str(s) + "\n"

        r += "\nLibraries:\n"
        for s in self.__libraries.itervalues():
            r += " * " + str(s) + "\n"

        return r
        
    def get(self, address, size):
	abstract()

    def getQWord(self, address):
        qword = self.get(address, 8)
        return struct.unpack("Q", qword)[0]

    def getDWord(self, address):
        dword = self.get(address, 4)
        return struct.unpack("L", dword)[0]

    def getWord(self, address):
        dword = self.get(address, 2)
        return struct.unpack("H", dword)[0]

    def getByte(self, address):
        dword = self.get(address, 1)
        return struct.unpack("B", dword)[0]

    def getName(self):
        return self.__name

    def setType(self, t):
        self.__type = t

    def getType(self):
        return self.__type

    def getMachine(self):
        return self.__machine

    def setMachine(self, m):
        self.__machine = m

    def getCode(self, start = None, stop = None):
	if start is not None:
	    if stop is not None:
		return self.__buf[start:stop]
	    else:
		return self.__buf[start:]
	else:
	    return self.__buf

    def getOffset(self, addr):
        sec = self.findSection(addr)
        return sec.getOffset() + (addr - sec.getLowAddr())

    def addSection(self, sec):
        self.__sections.append(sec)
	# sort sections by address to speedup search
	self.__sections.sort(lambda x,y: int(x.getLowAddr() - y.getLowAddr()))
    

    def delSection(self, sec):
        j = 0
        for i in self.__sections:
            if i == sec or i.getName() == sec.name or i.getLowAddr() == sec.getLowAddr():
                self.__sections.remove(j)
                
            j += 1

    def findSection(self, address = None):
        """
        Return the section holding the address, if any or the section with the
        corresponding name
        """

        if address:
            # search a section by address (binary search)
            if isinstance(address, int) or isinstance(address, long):
                i = 0
                j = len(self.__sections)
                # binary search
                while j - i > 0:
                    k = (j - i) / 2 + i
                    # exact match
                    if address >= self.__sections[k].getLowAddr() and address <= self.__sections[k].getHighAddr():
                        return self.__sections[k]            
                    # process the 1st half
                    elif address < self.__sections[k].getLowAddr():
                        j = k
                    # process the 2nd half
                    else:
                        i = k + 1

                # assert None, "Address %.8x does not seem to belong to any section" % address
                return None

            # search a section by name (linear search)
            elif isinstance(address, str):
                for s in self.__sections:
                    if s.getName() == address:
                        return s

                # assert None, "Section %s not found" % address
                return None

        return self.__sections


    def getLowAddr(self):
        lowaddr = 0xFFFFFFFF
        
        for s in self.getSection():
            if s.getLowAddr() < lowaddr:
                lowaddr = s.getLowAddr()

        return lowaddr


    def getHighAddr(self):
        highaddr = 0
        
        for s in self.getSection():
            if s.getHighAddr() > highaddr:
                highaddr = s.getHighAddr()

        return highaddr
    

    def getSection(self, s = None):
        return self.findSection(s)

    def resolv(self, address):
	abstract()

    def addLibrary(self, lib):
	self.__libraries[lib.getName()] = lib

    def findLibrary(self, name = None):
        if name is None: return self.__libraries.values();

        if name in self.__libraries:
            return self.__libraries[name]
        
        for l in self.__libraries.itervalues():
            r = l.findLibrary(name)
            if r:
                return r

        return None

    def addSymbol(self, s):
	# FIXME: here we are implicitly prioritizing
	# symbols as they appear in symbol tables
	if s.getAddress() not in self.__symbols:
	    self.__symbols[s.getAddress()] = s
            self.__symbols_names[s.getName()] = s

    def getSymbol(self, s = None):
	if s is None:
            return self.__symbols.values()
	elif s in self.__symbols:
	    return self.__symbols[s]
        elif s in self.__symbols_names:
            return self.__symbols_names[s]
	else:
	    return None

    def setEntryPoint(self, x):
        self.__entrypoint = x


    def getEntryPoint(self):
        return self.__entrypoint

    def getImageBase(self):
        return self.__imagebase

    def setImageBase(self, ib):
        self.__imagebase = ib


SECTION_EXECUTABLE = 0x1
SECTION_WRITABLE = 0x2
SECTION_DYNAMIC = 0x4
SECTION_INITIALIZED = 0x8
SECTION_USERCODE = 0x10

class Section(object):
    def __init__(self, name = None, lowaddr = None, highaddr = None, content = None, attribute = None, offset = None):
	self.__name = name
	self.__lowaddr = lowaddr
	self.__highaddr = highaddr
	self.__content = content
	self.__attribute = attribute
	self.__offset = offset

    def getLowAddr(self):
	return self.__lowaddr

    def getHighAddr(self):
	return self.__highaddr

    def getSize(self):
        return self.__highaddr - self.__lowaddr

    def getOffset(self):
	return self.__offset

    def setOffset(self, offset):
        self.__offset = offset

    def getName(self):
	return self.__name

    def isCode(self):
	return self.__attribute & SECTION_EXECUTABLE

    def isData(self):
	return not self.__attribute & SECTION_EXECUTABLE

    def isReadWrite(self):
	return self.__attribute & SECTION_WRITABLE
	
    def isUserCode(self):
	return self.__attribute & SECTION_EXECUTABLE and self.__attribute & SECTION_USERCODE

    def isInitialized(self):
	return self.__attribute & SECTION_INITIALIZED

    def __str__(self):
	f = ""
	if self.isInitialized():
	    f += "I"
	if self.isData():
	    f += "D"
	if self.isCode():
	    f += "X"
	if self.isReadWrite():
	    f += "W"
	if self.isUserCode():
	    f += "U"

	return "%-30s %0.8x-%0.8x %.8x %0.6d [%s]" % (self.__name, self.__lowaddr, self.__highaddr, self.__offset, self.__highaddr - self.__lowaddr, f)

SYMBOL_DATA = 0x1
SYMBOL_FUNCTION = 0x2
SYMBOL_NOTYPE = 0x3

class Symbol:
    def __init__(self, name = None, address = None, symtype = None, size = None):
	self.__size = size
	self.__name = name
	self.__address = address
	self.__type = symtype

    def __str__(self):
        if self.__type == SYMBOL_FUNCTION:
            t = "F"
        elif self.__type == SYMBOL_DATA:
            t = "D"
        elif self.__type == SYMBOL_NOTYPE:
            t = "-"
        else:
            t = "?"
        
	return "%-30s %0.8x (%0.6d) [%s]" % (self.__name, self.__address, self.__size, t)

    def isFunction(self):
	return self.__type == SYMBOL_FUNCTION

    def isData(self):
	return self.__type == SYMBOL_DATA

    def getName(self):
	return self.__name

    def getAddress(self):
	return self.__address

    def setAddress(self, addr):
        self.__address = addr

    def getSize(self):
        return self.__size

class Library:
    def __init__(self, name = None):
        self.__name = name

    def __str__(self):
        return "%s" % self.__name

    def getName(self):
	return self.__name

###############################################################################
# Elf file abstraction
###############################################################################

MACHINE_I386 = 0
MACHINE_X86_64 = 1

EI_MAG0       = 0
EI_MAG1       = 1
EI_MAG2       = 2
EI_MAG3       = 3
EI_CLASS      = 4
EI_DATA       = 5
EI_VERSION    = 6
EI_OSABI      = 7
EI_ABIVERSION = 8
EI_PAD        = 9
EI_NIDENT     = 16

ELFCLASS32    = 1               # Elf32
ELFCLASS64    = 2               # Elf64

ET_NONE       = 0               # No file type 
ET_REL        = 1               # Relocatable file
ET_EXEC       = 2               # Executable file 
ET_DYN        = 3               # Shared object file 
ET_CORE       = 4               # Core file 

ET_NUM        = 5               # Number of defined types 
ET_LOOS       = 0xfe00          # OS-specific range start 
ET_HIOS       = 0xfeff          # OS-specific range end 
ET_LOPROC     = 0xff00          # Processor-specific range start 
ET_HIPROC     = 0xffff          # Processor-specific range end 

SHT_NULL          = 0             # Section header table entry unused
SHT_PROGBITS      = 1             # Program data
SHT_SYMTAB        = 2             # Symbol table
SHT_STRTAB        = 3             # String table
SHT_RELA          = 4             # Relocation entries with addends
SHT_HASH          = 5             # Symbol hash table
SHT_DYNAMIC       = 6             # Dynamic linking information
SHT_NOTE          = 7             # Notes
SHT_NOBITS        = 8             # Program space with no data (bss)
SHT_REL           = 9             # Relocation entries, no addends
SHT_SHLIB         = 10            # Reserved
SHT_DYNSYM        = 11            # Dynamic linker symbol table
SHT_INIT_ARRAY    = 14            # Array of constructors
SHT_FINI_ARRAY    = 15            # Array of destructors
SHT_PREINIT_ARRAY = 16            # Array of pre-constructors
SHT_GROUP         = 17            # Section group
SHT_SYMTAB_SHNDX  = 18            # Extended section indeces
SHT_NUM           = 19            # Number of defined types 
SHT_LOOS          = 0x60000000L    # Start OS-specific
SHT_GNU_LIBLIST   = 0x6ffffff7L    # Prelink library list
SHT_CHECKSUM      = 0x6ffffff8L    # Checksum for DSO content
SHT_LOSUNW        = 0x6ffffffaL    # Sun-specific low bound
SHT_SUNW_move     = 0x6ffffffaL
SHT_SUNW_COMDAT   = 0x6ffffffbL
SHT_SUNW_syminfo  = 0x6ffffffcL
SHT_GNU_verdef    = 0x6ffffffdL    # Version definition section
SHT_GNU_verneed   = 0x6ffffffeL    # Version needs section
SHT_GNU_versym    = 0x6fffffffL    # Version symbol table
SHT_HISUNW        = 0x6fffffffL    # Sun-specific high bound
SHT_HIOS          = 0x6fffffffL    # End OS-specific type
SHT_LOPROC        = 0x70000000L    # Start of processor-specific
SHT_HIPROC        = 0x7fffffffL    # End of processor-specific
SHT_LOUSER        = 0x80000000L    # Start of application-specific
SHF_WRITE            = (1 << 0)   # Writable
SHF_ALLOC            = (1 << 1)   # Occupies memory during execution
SHF_EXECINSTR        = (1 << 2)   # Executable
SHF_MERGE            = (1 << 4)   # Might be merged
SHF_STRINGS          = (1 << 5)   # Contains nul-terminated strings
SHF_INFO_LINK        = (1 << 6)   # `sh_info' contains SHT index
SHF_LINK_ORDER       = (1 << 7)   # Preserve order after combining
SHF_OS_NONCONFORMING = (1 << 8)   # Non-standard OS specific handling
SHF_GROUP            = (1 << 9)   # Section is member of a group
SHF_TLS              = (1 << 10)  # Section hold thread-local data
SHF_MASKOS           = 0x0ff00000L # OS-specific.
SHF_MASKPROC         = 0xf0000000L # Processor-specific
SHF_ORDERED          = (1 << 30)  # Special ordering requirement
SHF_EXCLUDE          = (1 << 31)  # Section is excluded unless

PT_NULL    = 0     # Program header table entry unused 
PT_LOAD    = 1     # Loadable program segment
PT_DYNAMIC = 2     # Dynamic linking information 
PT_INTERP  = 3     # Program interpreter 
PT_NOTE    = 4     # Auxiliary information 
PT_SHLIB   = 5     # Reserved 
PT_PHDR    = 6     # Entry for header table itself 
PT_TLS     = 7     # Thread-local storage segment 
PT_NUM     = 8     # Number of defined types 
PT_LOOS    = 0x60000000L  # Start of OS-specific 
PT_GNU_EH_FRAME = 0x6474e550L  # GCC .eh_frame_hdr segment 
PT_GNU_STACK 	= 0x6474e551L  # Indicates stack executability 
PT_GNU_RELRO 	= 0x6474e552L  # Read-only after relocation 
PT_LOSUNW 	= 0x6ffffffaL
PT_SUNWBSS   	= 0x6ffffffaL  # Sun Specific segment 
PT_SUNWSTACK 	= 0x6ffffffbL  # Stack segment 
PT_HISUNW 	= 0x6fffffffL
PT_HIOS      	= 0x6fffffffL  # End of OS-specific 
PT_LOPROC 	= 0x70000000L  # Start of processor-specific 
PT_HIPROC 	= 0x7fffffffL  # End of processor-specific 

PF_X     = (1 << 0) # Segment is executable 
PF_W     = (1 << 1) # Segment is writable 
PF_R     = (1 << 2) # Segment is readable 
PF_MASKOS   = 0x0ff00000L  # OS-specific 
PF_MASKPROC = 0xf0000000L  # Processor-specific 

STT_NOTYPE   = 0     # Symbol type is unspecified 
STT_OBJECT   = 1     # Symbol is a data object 
STT_FUNC     = 2     # Symbol is a code object 
STT_SECTION  = 3     # Symbol associated with a section 
STT_FILE     = 4     # Symbol's name is file name 
STT_COMMON   = 5     # Symbol is a common data object 
STT_TLS      = 6     # Symbol is thread-local data object
STT_NUM      = 7     # Number of defined types.  
STT_LOOS     = 10    # Start of OS-specific 
STT_HIOS     = 12    # End of OS-specific 
STT_LOPROC   = 13    # Start of processor-specific 
STT_HIPROC   = 15    # End of processor-specific 

STB_LOCAL    = 0     # Local symbol
STB_GLOBAL   = 1     # Global symbol
STB_WEAK     = 2     # Weak symbol

DT_NULL      = 0     # Marks end of dynamic section 
DT_NEEDED    = 1     # Name of needed library 
DT_PLTRELSZ  = 2     # Size in bytes of PLT relocs 
DT_PLTGOT    = 3     # Processor defined value 
DT_HASH      = 4     # Address of symbol hash table 
DT_STRTAB    = 5     # Address of string table 
DT_SYMTAB    = 6     # Address of symbol table 
DT_RELA      = 7     # Address of Rela relocs 
DT_RELASZ    = 8     # Total size of Rela relocs 
DT_RELAENT   = 9     # Size of one Rela reloc 
DT_STRSZ     = 10    # Size of string table 
DT_SYMENT    = 11    # Size of one symbol table entry 
DT_INIT      = 12    # Address of init function 
DT_FINI      = 13    # Address of termination function 
DT_SONAME    = 14    # Name of shared object 
DT_RPATH     = 15    # Library search path (deprecated) 
DT_SYMBOLIC  = 16    # Start symbol search here 
DT_REL       = 17    # Address of Rel relocs 
DT_RELSZ     = 18    # Total size of Rel relocs 
DT_RELENT    = 19    # Size of one Rel reloc 
DT_PLTREL    = 20    # Type of reloc in PLT 
DT_DEBUG     = 21    # For debugging; unspecified 
DT_TEXTREL   = 22    # Reloc might modify .text 
DT_JMPREL    = 23    # Address of PLT relocs 
DT_BIND_NOW  = 24    # Process relocations of object 
DT_INIT_ARRAY = 25    # Array with addresses of init fct 
DT_FINI_ARRAY = 26    # Array with addresses of fini fct 
DT_INIT_ARRAYSZ  = 27    # Size in bytes of DT_INIT_ARRAY 
DT_FINI_ARRAYSZ  = 28    # Size in bytes of DT_FINI_ARRAY 
DT_RUNPATH   = 29    # Library search path 
DT_FLAGS     = 30    # Flags for the object being loaded 
DT_ENCODING  = 32    # Start of encoded range 
DT_PREINIT_ARRAY   = 32      # Array with addresses of preinit fct
DT_PREINIT_ARRAYSZ = 33    # size in bytes of DT_PREINIT_ARRAY 
DT_NUM       = 34    # Number used 
DT_LOOS      = 0x6000000dL  # Start of OS-specific 
DT_HIOS      = 0x6ffff000L  # End of OS-specific 
DT_LOPROC    = 0x70000000L  # Start of processor-specific 
DT_HIPROC    = 0x7fffffffL  # End of processor-specific 

def qword(buf):
  return struct.unpack("Q", buf[0:8])[0]

def dword(buf):
  return struct.unpack("I", buf[0:4])[0]

def word(buf):
  return struct.unpack("H", buf[0:2])[0]

def byte(buf):
  return struct.unpack("B", buf[0])[0]

class ElfEhdr:
  def __init__(self, buf):
    abstract()
    
class ElfShdr:
  def __init__(self, buf):
    abstract()
        
class ElfPhdr:
  def __init__(self, buf):
    abstract()

class ElfRel:
  def __init__(self):
    abstract()

  def size(self):
    abstract()

class ElfSym:
  def __init__(self):
    abstract()

  def size(self):
    abstract()

class ElfDyn:
  def __init__(self):
    abstract()

  def size(self):
    abstract()

################################################################################
# ELF32
################################################################################
class Elf32Ehdr(ElfEhdr):
  def __init__(self, buf):
    self.e_ident = buf[0:16]
    self.e_type = struct.unpack("H", buf[16:18])[0]
    self.e_machine = struct.unpack("H", buf[18:20])[0] 
    self.e_version = struct.unpack("I", buf[20:24])[0] 
    self.e_entry = struct.unpack("I", buf[24:28])[0] 
    self.e_phoff = struct.unpack("I", buf[28:32])[0] 
    self.e_shoff = struct.unpack("I", buf[32:36])[0] 
    self.e_flags = struct.unpack("I", buf[36:40])[0] 
    self.e_ehsize = struct.unpack("H", buf[40:42])[0]
    self.e_phentsize = struct.unpack("H", buf[42:44])[0]
    self.e_phnum = struct.unpack("H", buf[44:46])[0]
    self.e_shentsize = struct.unpack("H", buf[46:48])[0] 
    self.e_shnum = struct.unpack("H", buf[48:50])[0] 
    self.e_shstrndx = struct.unpack("H", buf[50:52])[0]

class Elf32Shdr(ElfShdr):
  def __init__(self, buf):
    self.sh_name = struct.unpack("I", buf[0:4])[0]
    self.sh_type = struct.unpack("I", buf[4:8])[0]
    self.sh_flags = struct.unpack("I", buf[8:12])[0]
    self.sh_addr = struct.unpack("I", buf[12:16])[0]
    self.sh_offset = struct.unpack("I", buf[16:20])[0]
    self.sh_size = struct.unpack("I", buf[20:24])[0]
    self.sh_link = struct.unpack("I", buf[24:28])[0]
    self.sh_info = struct.unpack("I", buf[28:32])[0]
    self.sh_addraling = struct.unpack("I", buf[32:36])[0]
    self.sh_entsize = struct.unpack("I", buf[36:40])[0]
    
class Elf32Phdr(ElfPhdr):
  def __init__(self, buf):
    self.p_type = struct.unpack("I", buf[0:4])[0]
    self.p_offset = struct.unpack("I", buf[4:8])[0]
    self.p_vaddr = struct.unpack("I", buf[8:12])[0]
    self.p_paddr = struct.unpack("I", buf[12:16])[0]
    self.p_filesiz = struct.unpack("I", buf[16:20])[0]
    self.p_memsz = struct.unpack("I", buf[20:24])[0]
    self.p_flags = struct.unpack("I", buf[24:28])[0]
    self.p_align = struct.unpack("I", buf[28:32])[0]  

class Elf32Rel(ElfRel):
  def __init__(self, buf):
    self.r_offset = struct.unpack("I", buf[0:4])[0] # Address
    self.r_info = struct.unpack("I", buf[4:8])[0]   # Relocation type and symbol
                                                    # index

class Elf32Sym(ElfSym):
  def __init__(self, buf):
    self.st_name  = struct.unpack("I", buf[0:4])[0]    # Symbol name (string tbl
                                                       # index)
    self.st_value = struct.unpack("I", buf[4:8])[0]    # symbol value
    self.st_size  = struct.unpack("I", buf[8:12])[0]   # symbol size
    self.st_info  = byte(buf[12:13])  # symbol type and binding
    self.st_other = byte(buf[13:14])  # symbol visibility
    self.st_shndx = struct.unpack("H", buf[14:16])[0]  # section index

class Elf32Dyn(ElfDyn):
  def __init__(self, buf):
    self.d_tag = struct.unpack("i", buf[0:4])[0] # dynamic entry type
    self.d_val = struct.unpack("I", buf[4:8])[0] # Integer value
    self.d_ptr = self.d_val

def ELF32_ST_BIND(val):
    return ((val) >> 4)

def ELF32_ST_TYPE(val):
    return ((val) & 0xf)

def ELF32_ST_INFO(sym, type):
    return (((sym) << 4) + ((type) & 0xf))

def ELF32_R_SYM(val):
    return ((val) >> 8)

def ELF32_R_TYPE(val):
    return ((val) & 0xff)

def ELF32_R_INFO(sym, type):
    return (((sym) << 8) + ((type) & 0xff))

################################################################################
# ELF64
################################################################################
class Elf64Ehdr(ElfEhdr):
  def __init__(self, buf):
    self.e_ident = buf[0:16]
    self.e_type = word(buf[16:18])
    self.e_machine = word(buf[18:20])
    self.e_version = dword(buf[20:24])
    self.e_entry = qword(buf[24:32])
    self.e_phoff = qword(buf[32:40])
    self.e_shoff = qword(buf[40:48])
    self.e_flags = dword(buf[48:52])
    self.e_ehsize = word(buf[52:54])
    self.e_phentsize = word(buf[54:56])
    self.e_phnum = word(buf[56:58])
    self.e_shentsize = word(buf[58:60])
    self.e_shnum = word(buf[60:62])
    self.e_shstrndx = word(buf[62:64])

class Elf64Shdr(ElfShdr):
  def __init__(self, buf):
    self.sh_name = dword(buf[0:4])
    self.sh_type = dword(buf[4:8])
    self.sh_flags = qword(buf[8:16])
    self.sh_addr = qword(buf[16:24])
    self.sh_offset = qword(buf[24:32])
    self.sh_size = qword(buf[32:40])
    self.sh_link = dword(buf[40:44])
    self.sh_info = dword(buf[44:48])
    self.sh_addraling = qword(buf[48:56])
    self.sh_entsize = qword(buf[56:64])
    
class Elf64Phdr(ElfPhdr):
  def __init__(self, buf):
    self.p_type = dword(buf[0:4])
    self.p_flags = dword(buf[4:8])
    self.p_offset = qword(buf[8:16])
    self.p_vaddr = qword(buf[16:24])
    self.p_paddr = qword(buf[24:32])
    self.p_filesiz = qword(buf[32:40])
    self.p_memsz = qword(buf[40:48])
    self.p_align = qword(buf[48:56])

class Elf64Rel(ElfRel):
  def __init__(self, buf):
    self.r_offset = qword(buf[0:8])  # Address
    self.r_info = qword(buf[8:16])   # Relocation type and symbol
                                     # index

class Elf64Sym(ElfSym):
  def __init__(self, buf):
    self.st_name  = dword(buf[0:4])     # Symbol name (string tbl
                                        # index)
    self.st_info  = byte(buf[4:5])      # symbol type and binding
    self.st_other = byte(buf[5:6])      # symbol visibility

    self.st_shndx = word(buf[6:8])      # section index
    self.st_value = qword(buf[8:16])    # symbol value
    self.st_size  = qword(buf[16:24])   # symbol size

class Elf64Dyn(ElfDyn):
  def __init__(self, buf):
    self.d_tag = struct.unpack("q", buf[0:8])[0] # dynamic entry type
    self.d_val = qword(buf[8:16]) # Integer value
    self.d_ptr = self.d_val

def ELF64_ST_BIND(val):
    return ((val) >> 4)

def ELF64_ST_TYPE(val):
    return ((val) & 0xf)

def ELF64_ST_INFO(sym, type):
    return (((sym) << 4) + ((type) & 0xf))

def ELF64_R_SYM(val):
    return ((val) >> 32)

def ELF64_R_TYPE(val):
    return ((val) & 0xffffffffL)

def ELF64_R_INFO(sym, type):
    return (((sym) << 32) + ((type) & 0xffffffffL))


################################################################################
# ELF32 - ELF64
################################################################################

def parse_et_rel(self, name, buf, ei_class):
  # parse elf header
  if ei_class == ELFCLASS32:
    ehdr = Elf32Ehdr(self.buf)
  elif ei_class == ELFCLASS64:
    ehdr = Elf64Ehdr(self.buf)

  shdr = []
  shdrmap = {}
  rels = []
  libraries = []
  
  dynamic = None
  
  # the section header string table index is ehdr.e_shstrndx
  start = ehdr.e_shstrndx * ehdr.e_shentsize + ehdr.e_shoff
  
  if ei_class == ELFCLASS32:
    strtab = Elf32Shdr(self.buf[start:start+ehdr.e_shentsize])
  elif ei_class == ELFCLASS64:
    strtab = Elf64Shdr(self.buf[start:start+ehdr.e_shentsize])

  strtab = strtab.sh_offset
  
  # parse section headers and build the list
  for shno in range(ehdr.e_shnum):
    start = shno * ehdr.e_shentsize + ehdr.e_shoff
    if ei_class == ELFCLASS32:
      sh = Elf32Shdr(self.buf[start:start+ehdr.e_shentsize])
    elif ei_class == ELFCLASS64:
      sh = Elf64Shdr(self.buf[start:start+ehdr.e_shentsize])

    name = self.buf[strtab + sh.sh_name:strtab + sh.sh_name + 25].split("\x00")[0]
    
    start = sh.sh_offset
    # sections like .bss are not sotred on file
    if sh.sh_type == SHT_NOBITS:
      stop = start
    else:
      stop = start + sh.sh_size
      
    # we have found the dynamic section
    if sh.sh_type == SHT_DYNAMIC:
      dynamic = sh

    if sh.sh_type == SHT_REL:
      rels.append(sh)

    # if sh.sh_type == SHT_RELA:
    #  rels.append(sh)

    # setup section attributes
    attribute = 0
    if sh.sh_flags & SHF_EXECINSTR:
      attribute |= SECTION_EXECUTABLE
    if sh.sh_flags & SHF_WRITE:
      attribute |= SECTION_WRITABLE
    if start != stop:
      attribute |= SECTION_INITIALIZED

    if name == ".text":
      attribute |= SECTION_USERCODE

    # Instantiate the section
    sec = Section(name = name, lowaddr = sh.sh_addr, highaddr = sh.sh_addr + sh.sh_size, content = self.buf[start:stop], attribute = attribute, offset = sh.sh_offset)
    shdr.append(sec)
    shdrmap[sh.sh_addr] = sh

    if sh.sh_flags & SHF_ALLOC:
        self.sections.append(sec)

class Elf(File):
  def __init__(self, name = None, buf = None):
    File.__init__(self, name, buf)
    
    self.e_indent = self.getCode()[0:16]
    self.ei_class = byte(self.e_indent[EI_CLASS])
    self.ei_osabi = byte(self.e_indent[EI_OSABI])
    self.ei_abiversion = byte(self.e_indent[EI_ABIVERSION])

    if self.ei_class == ELFCLASS32:
      ehdr = Elf32Ehdr(self.getCode())
      self.setType("ELF32")
    elif self.ei_class == ELFCLASS64:
      ehdr = Elf64Ehdr(self.getCode())
      self.setType("ELF64")
    else:
      assert False

    # save ELF header
    self.__ehdr = ehdr

    if ehdr.e_machine == 0x3:
      self.setMachine(MACHINE_I386)
    elif ehdr.e_machine == 0x3e:
      self.setMachine(MACHINE_X86_64)
    else:
      assert False, "Unknown machine %d" % ehdr.e_machine

    if ehdr.e_type == ET_REL:
        parse_et_rel(self, name, buf, self.ei_class)
        return
    elif ehdr.e_type == ET_DYN:
        # shared object file
        # return
        pass
    
    shdr = []               # section objects
    shdrmap = {}            # [base address] -> [section header] map
    rels = []               # relocations
    libraries = []          # needed libraries

    dynamic = None          # reference to .dynamic section
    # --- DEBUG
    syms = None             # reference to .symtab section
    # --- END

    # the section header string table index is ehdr.e_shstrndx
    start = ehdr.e_shstrndx * ehdr.e_shentsize + ehdr.e_shoff

    if self.ei_class == ELFCLASS32:
      strtab = Elf32Shdr(self.getCode(start,start+ehdr.e_shentsize))
    elif self.ei_class == ELFCLASS64:
      strtab = Elf64Shdr(self.getCode(start,start+ehdr.e_shentsize))
    else:
      assert False

    strtab = strtab.sh_offset

    # parse section headers and build the list
    for shno in range(ehdr.e_shnum):
      start = shno * ehdr.e_shentsize + ehdr.e_shoff
      if self.ei_class == ELFCLASS32:
        sh = Elf32Shdr(self.getCode(start, start+ehdr.e_shentsize))
      elif self.ei_class == ELFCLASS64:
        sh = Elf64Shdr(self.getCode(start, start+ehdr.e_shentsize))

      name = self.getCode(strtab + sh.sh_name, strtab + sh.sh_name + 25).split("\x00")[0]

      start = sh.sh_offset
      # sections like .bss are not stored on file
      if sh.sh_type == SHT_NOBITS:
        stop = start
      else:
        stop = start + sh.sh_size

      if sh.sh_type == SHT_DYNAMIC:
        # we have found the dynamic section
        dynamic = sh
      elif sh.sh_type == SHT_REL:
        # relocatable section
        rels.append(sh)
      elif sh.sh_type == SHT_RELA:
        # relocatable section
        rels.append(sh)
      # --- DEBUG
      elif sh.sh_type == SHT_SYMTAB:
        # symbols table
        syms = sh
      # --- END
      
      # setup section attributes
      attribute = 0
      if sh.sh_flags & SHF_EXECINSTR:
        attribute |= SECTION_EXECUTABLE
      if sh.sh_flags & SHF_WRITE:
        attribute |= SECTION_WRITABLE
      if start != stop:
        attribute |= SECTION_INITIALIZED

      if name == ".text":
        attribute |= SECTION_USERCODE

      # Instantiate the section
      sec = Section(name = name, lowaddr = sh.sh_addr, highaddr = sh.sh_addr + sh.sh_size, \
                         content = self.getCode(start, stop), attribute = attribute, \
                         offset = sh.sh_offset)
      shdr.append(sec)
      shdrmap[sh.sh_addr] = sh

    # parse the program headers and build the list
    for phno in range(ehdr.e_phnum):
      start = phno * ehdr.e_phentsize + ehdr.e_phoff
      if self.ei_class == ELFCLASS32:
        ph = Elf32Phdr(self.getCode(start, start + ehdr.e_phentsize))
      elif self.ei_class == ELFCLASS64:
        ph = Elf64Phdr(self.getCode(start, start + ehdr.e_phentsize))

      if ph.p_type == PT_LOAD:
        # loadable segment
        for s in shdr:
          if s.getLowAddr() >= ph.p_vaddr and s.getHighAddr() <= ph.p_vaddr + ph.p_memsz:
            # store only sections that will be loaded in memory at runtime
            self.addSection(s)

    # extract symbols from .symtab and resolve them
    if syms:
      # read .symtab entries
      ssyms = []
      for s in range(syms.sh_size / syms.sh_entsize):
        start = syms.sh_offset + s * syms.sh_entsize
        if self.ei_class == ELFCLASS32:
          ssyms.append(Elf32Sym(self.getCode(start, start+syms.sh_entsize)))
        elif self.ei_class == ELFCLASS64:       
          ssyms.append(Elf64Sym(self.getCode(start, start+syms.sh_entsize)))
      
      # build file.Symbol objects
      for x in ssyms:
        start = shdr[syms.sh_link].getOffset() + x.st_name
        name = self.getCode(start, start + 50).split("\x00")[0]
        
        if self.ei_class == ELFCLASS32:
          typ = ELF32_ST_TYPE(x.st_info)
        elif self.ei_class == ELFCLASS64:
          typ = ELF64_ST_TYPE(x.st_info)
        else:
          assert False

        if typ & STT_FUNC:
            typ = SYMBOL_FUNCTION
        elif typ & STT_OBJECT:
            typ = SYMBOL_DATA
        else:
            typ = SYMBOL_NOTYPE

        s = Symbol(name = name, size = x.st_size, \
                        address = x.st_value, \
                        symtype = typ)
        self.addSymbol(s)

    # process the dynamic section to locate the string table and the symbol
    # table
    dynstr, dynsym = None, None
    if dynamic:
      for d in range(dynamic.sh_size / dynamic.sh_entsize):
        start = dynamic.sh_offset + d * dynamic.sh_entsize
        if self.ei_class == ELFCLASS32:
          d = Elf32Dyn(self.getCode(start, start + dynamic.sh_entsize))
        elif self.ei_class == ELFCLASS64:
          d = Elf64Dyn(self.getCode(start, start + dynamic.sh_entsize))
        else:
          assert False

        if d.d_tag == DT_SYMTAB:
          # holds a symbol table address
          dynsym = shdrmap[d.d_val]
        elif d.d_tag == DT_STRTAB:
          # holds a string table address
          dynstr = shdrmap[d.d_val]
        elif d.d_tag == DT_NEEDED:
          # holds the string table (pointed by DT_STRTAB) offset of a 
          # null-terminated string, giving the name of a needed library
          libraries.append(d)

      assert dynstr is not None
      assert dynsym is not None
        
      # resolve the symbols address & name
      dynsyms = []
      for d in range(dynsym.sh_size / dynsym.sh_entsize):
        # build the list of dynamic symbols
        start = dynsym.sh_offset + d * dynsym.sh_entsize
        if self.ei_class == ELFCLASS32:
          dynsyms.append(Elf32Sym(self.getCode(start, start+dynsym.sh_entsize)))
        elif self.ei_class == ELFCLASS64:
          dynsyms.append(Elf64Sym(self.getCode(start, start+dynsym.sh_entsize)))
        else:
          assert False
    
      # add dynamic symbols
      for dsn in range(len(dynsyms)):
        d = dynsyms[dsn]
        # get symbol name
        name = d.st_name
        name = self.getCode(dynstr.sh_offset+name, dynstr.sh_offset+name+50).split("\x00")[0]

        # get symbol type
        typ  = d.st_info
        if   typ & STT_FUNC:        typ = SYMBOL_FUNCTION
        elif typ & STT_OBJECT:      typ = SYMBOL_DATA
        else:                       typ = SYMBOL_NOTYPE

        s = Symbol(name = name, size = d.st_size, address = d.st_value, symtype = typ)
        self.addSymbol(s)
      
      for rr in rels:
        # the symbol table section associated to this relocatable section
        # should always be .dynsym; otherwise, we must modify the following
        # loop
        assert shdrmap[shdr[rr.sh_link].getLowAddr()] == dynsym

        for r in range(rr.sh_size / rr.sh_entsize):
          # get the r-th rel entry
          start = rr.sh_offset + r * rr.sh_entsize
          if self.ei_class == ELFCLASS32:
            s = Elf32Rel(self.getCode(start, start+rr.sh_entsize))
          elif self.ei_class == ELFCLASS64:
            s = Elf64Rel(self.getCode(start, start+rr.sh_entsize))
          else:
            assert False

          # get the corresponding symbol
          if self.ei_class == ELFCLASS32:
            symnum = ELF32_R_SYM(s.r_info)
          elif self.ei_class == ELFCLASS64:
            symnum = ELF64_R_SYM(s.r_info)
          else:
            assert False

          size = dynsyms[symnum].st_size
          typ  = dynsyms[symnum].st_info
          if typ & STT_FUNC:
            # the symbol is associated with a function in the executable code
            typ = SYMBOL_FUNCTION
          elif typ & STT_OBJECT:
            # the symbol is associated with a data object (variable, array, ...)
            typ = SYMBOL_DATA
          else:
            typ = SYMBOL_NOTYPE

          # offset in the symtab
          name = dynsyms[symnum].st_name
          # extract the name from the strtab
          name = self.getCode(dynstr.sh_offset+name, dynstr.sh_offset+name+50).split("\x00")[0]

          # instantiate the symbol and store the symbol in the local map for future access
          s = Symbol(name = name, size = size, address = s.r_offset, symtype = typ)
          self.addSymbol(s)
      
    for l in libraries:
      name = self.getCode(dynstr.sh_offset + l.d_val, dynstr.sh_offset + l.d_val + 50).split("\x00")[0]
      lib = Library(name)
      self.addLibrary(lib)

        # -- parse library object file
        # pp = None
        # import os
        # for lp in [".", "/lib", "/usr/lib", "/usr/local/lib"]:
        #     if os.path.isfile(os.path.join(lp, name)):
        #         pp = os.path.join(lp, name)
        #         break
        #     if not pp:
        #         raise Error("unable to load shared library: %s" % name)
        # debug(DEBUG_ELF, " * Analyzing library '%s';\n", name)
        # self.addLibrary(Elf(pp))
        
  def getEhdr(self):
    return self.__ehdr

  def get(self, address, size = 4):
    """Return the content of a cell as stored on the file"""
    offset = None

    # find the section to which the address belongs
    sec = self.findSection(address)
    if sec:
      offset = sec.getOffset() + address - sec.getLowAddr()

    assert offset is not None
    
    return self.getCode(offset, offset+size)

if __name__ == "__main__":
  import sys
  e = Elf(sys.argv[1])
  print e
