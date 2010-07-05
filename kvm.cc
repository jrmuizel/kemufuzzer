// This file is part of KEmuFuzzer.
// 
// KEmuFuzzer is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// KEmuFuzzer is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
// 
// You should have received a copy of the GNU General Public License along with
// KEmuFuzzer.  If not, see <http://www.gnu.org/licenses/>.

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <udis86.h>
#include <unistd.h>
#include <zlib.h>

#include "kvm.h"
#include "x86_cpustate.h"

char kernel_version[16];
char kernel_checksum[64];
char testcase_checksum[64];

#define set_kvm_segment(dst, src) {  \
    dst.base = src.base;	     \
    dst.limit = src.limit;	     \
    dst.selector = src.selector;     \
    dst.type = src.type;	     \
    dst.present = src.present;	     \
    dst.dpl = src.dpl;		     \
    dst.db = src.db;		     \
    dst.s = src.s;		     \
    dst.l = src.l;		     \
    dst.g = src.g;		     \
    dst.avl = src.avl;		     \
    dst.unusable = src.unusable;     \
  }

#define set_kvm_table(dst, src) { \
    dst.base = src.base;	  \
    dst.limit = src.limit;	  \
  }

#define get_kvm_segment(dst, src) {  \
    dst.base = src.base;	     \
    dst.limit = src.limit;	     \
    dst.selector = src.selector;     \
    dst.type = src.type;	     \
    dst.present = src.present;	     \
    dst.dpl = src.dpl;		     \
    dst.db = src.db;		     \
    dst.s = src.s;		     \
    dst.l = src.l;		     \
    dst.g = src.g;		     \
    dst.avl = src.avl;		     \
  }

#define get_kvm_table(dst, src) { \
    dst.base = src.base;	  \
    dst.limit = src.limit;	  \
  }


VCPU::VCPU(KVM *k, int s) {
  int r;

  kvm = k;
  slot = s;

  cpu_fd = ioctl(kvm->vm_fd, KVM_CREATE_VCPU, s);
  assert(cpu_fd != -1);
  
  r = ioctl(kvm->fd, KVM_GET_VCPU_MMAP_SIZE, 0);
  assert(r != -1);

  run = (struct kvm_run *) mmap(NULL, r, PROT_READ|PROT_WRITE, MAP_SHARED, cpu_fd, 0);
  assert(run);

  exception = EXCEPTION_NONE;
}

VCPU::~VCPU() {
  ;
}

void VCPU::SetRegs(struct kvm_regs *r) {
  int i;

  i = ioctl(cpu_fd, KVM_SET_REGS, r);
  assert(i != -1);
}

void VCPU::GetRegs(struct kvm_regs *r) {
  int i;

  i = ioctl(cpu_fd, KVM_GET_REGS, r);
  assert(i != -1);
}

void VCPU::SetSregs(struct kvm_sregs *r) {
  int i;

  i = ioctl(cpu_fd, KVM_SET_SREGS, r);
  assert(i != -1);
}

void VCPU::GetSregs(struct kvm_sregs *r) {
  int i;

  i = ioctl(cpu_fd, KVM_GET_SREGS, r);
  assert(i != -1);
}

void VCPU::SetFPU(struct kvm_fpu *r) {
  int i;

  i = ioctl(cpu_fd, KVM_SET_FPU, r);
  assert(i != -1);
}

void VCPU::GetFPU(struct kvm_fpu *r) {
  int i;

  i = ioctl(cpu_fd, KVM_GET_FPU, r);
  assert(i != -1);
}

void VCPU::SetMSRs(struct kvm_msr_entry *msrs, int n) {
  int i;
  struct kvm_msrs *kmsrs;

  if (n == 0) return;

  kmsrs = (struct kvm_msrs*) malloc(sizeof(*kmsrs) + n*sizeof(*msrs));
  assert(kmsrs);

  kmsrs->nmsrs = n;
  memcpy(kmsrs->entries, msrs, n*(sizeof *msrs));
  i = ioctl(cpu_fd, KVM_SET_MSRS, kmsrs);
  assert (i != -1);

  free(kmsrs);
}
 
void VCPU::GetMSRs(struct kvm_msr_entry *msrs, int *n) {
  int i;
  struct kvm_msrs *kmsrs;
  struct kvm_msr_list *kmsrslist;

  // Get the list of available MSRS
  kmsrslist = (struct kvm_msr_list*) malloc(sizeof(*kmsrslist) + MAX_MSRS*sizeof(__u32));
  assert(kmsrslist);
  kmsrslist->nmsrs = MAX_MSRS;
  i = ioctl(kvm->fd, KVM_GET_MSR_INDEX_LIST, kmsrslist);
  assert (i != -1);

  // Get the data stored in each MSR
  *n = kmsrslist->nmsrs;
  kmsrs = (struct kvm_msrs*) malloc(sizeof(*kmsrs) + *n*sizeof(*msrs));
  assert(kmsrs);
  
  kmsrs->nmsrs = *n;
  for (i = 0; i < *n; i++) {
    kmsrs->entries[i].index = kmsrslist->indices[i];
  }

  i = ioctl(cpu_fd, KVM_GET_MSRS, kmsrs);
  assert (i != -1);

  memcpy(msrs, kmsrs->entries, *n*sizeof(*msrs));

  free(kmsrs);
  free(kmsrslist);
}

struct kvm_run *VCPU::Run() {
  int r;

  r = ioctl(cpu_fd, KVM_RUN, 0);
  assert(r != -1);

  return run;
}

void VCPU::SetException(int e) {
  exception = e;
}

int VCPU::Bits() {
  struct kvm_sregs sr;

  GetSregs(&sr);

  if (!(sr.cr0 & CR0_PE)) {
    return 16;
  } else if (!(sr.efer & EFER_LME)) {
    return 32;
  } else {
    return 64;
  }
}

int VCPU::GetMem(void *base, unsigned int size, uint8_t *buf) {
  int r;
  uint64_t i;
  struct kvm_translation t;

  // Slow but safe way (no assumpion on page size)
  for (i = 0; i < size ; i++) {
    memset(&t, 0, sizeof(t));
    t.linear_address = ADDR(base) + i;
    r = ioctl(cpu_fd, KVM_TRANSLATE, &t);
    assert(r == 0);
    assert(t.valid);
    buf[i] = *((uint8_t *) (t.physical_address + ADDR(kvm->Mem())));
  }

  return 0;
}

int VCPU::SetMem(void *base, unsigned int size, uint8_t *buf) {
  int r;
  uint64_t i;
  struct kvm_translation t;

  // Slow but safe way (no assumpion on page size)
  for (i = 0; i < size ; i++) {
    memset(&t, 0, sizeof(t));
    t.linear_address = ADDR(base) + i;
    r = ioctl(cpu_fd, KVM_TRANSLATE, &t);
    assert(r == 0);
    assert(t.valid);
    *((uint8_t *) (t.physical_address + ADDR(kvm->Mem()))) = buf[i];
  }

  return 0;
}

void VCPU::Disasm(void *addr, FILE *f) {
  ud_t ud_obj;
  uint8_t buf[32];
  int r;

  ud_init(&ud_obj);
  ud_set_mode(&ud_obj, CPU_BITS);
  ud_set_syntax(&ud_obj, UD_SYN_ATT);

  r = GetMem(addr, sizeof(buf), buf);
  assert(r != -1);

  ud_set_input_buffer(&ud_obj, buf, sizeof(buf));
  ud_set_pc(&ud_obj, ADDR(addr));
  
  r = ud_disassemble(&ud_obj);

  fprintf(f, "%s [%s]", ud_insn_asm(&ud_obj), ud_insn_hex(&ud_obj));
}

void VCPU::DumpMem(void *addr, int len, FILE *f, bool ascii) {
  int i;
  uint8_t c;
  
  for (i = 0; i < len; i++) {
    GetMem((void *) (ADDR(addr) + i), 1, &c);
    if (ascii) {
      fprintf(f, isascii(c) ? "%c" : "%2x ", c);
    } else {
      fprintf(f, "%2x ", c);
    }
  }
  fprintf(f, "\n");
}

KVM::KVM(int c, unsigned int len) {
  Init(c, len);
}

KVM::KVM(const char *fname) {
  header_t h;
  file f;
  unsigned int r;

  // Load state from disk
  f = fopen(fname, "r");
  assert(f);

  r = fread(f, &h, sizeof(h));
  assert(r == sizeof(h));
  fclose(f);

  // Sanity checks
  assert(h.magic == EXPECTED_MAGIC);
  assert(h.version == EXPECTED_VERSION);

  Init(h.cpusno, h.mem_size);
  Load(fname);
}

void KVM::Init(int c, unsigned int len) {

  int r;
  void *ptr;
  struct kvm_userspace_memory_region memory;
  struct kvm_irqchip irqchip;

  // Open /dev/kvm
  fd = open("/dev/kvm", O_RDWR);
  assert(fd != -1);

  // A customized KVM is required to work
  r = ioctl(fd, KVM_GET_API_VERSION, 0);
  assert(r == EXPECTED_KVM_API_VERSION);

  vm_fd = ioctl(fd, KVM_CREATE_VM, 0);
  assert(vm_fd != -1);

  // Arch create??
  r = ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_SET_TSS_ADDR);
  assert(r > 0);
  r = ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_PIT);
  assert(r > 0);
  r = ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_IRQCHIP);
  assert(r > 0);
#if 0
  // this address is 3 pages before the bios, and the bios should present
  // as unavaible memory   
  r = ioctl(vm_fd, KVM_SET_TSS_ADDR, 0xfffbd000);
  assert(r != -1);
  r = ioctl(vm_fd, KVM_CREATE_PIT, 0);
  assert(r != -1);
#endif

  // Use kernel-simulated PIC
  r = ioctl(vm_fd, KVM_CREATE_IRQCHIP);
  assert(r != -1);

  // Update the internal state of the PIC to increase irq_base
  // Master PIC
  memset(&irqchip, 0, sizeof(struct kvm_irqchip));
  irqchip.chip_id = 0; 
  r = ioctl(vm_fd, KVM_GET_IRQCHIP, &irqchip);
  assert(r != -1);
  irqchip.chip.pic.irq_base = 0x20;
  r = ioctl(vm_fd, KVM_SET_IRQCHIP, &irqchip);
  assert(r != -1);
  // Slave PIC
  memset(&irqchip, 0, sizeof(struct kvm_irqchip));
  irqchip.chip_id = 1; // Slave PIC
  r = ioctl(vm_fd, KVM_GET_IRQCHIP, &irqchip);
  assert(r != -1);
  irqchip.chip.pic.irq_base = 0x28;
  r = ioctl(vm_fd, KVM_SET_IRQCHIP, &irqchip);
  assert(r != -1);

  // XXX: what about the IO/APIC?

  // Allocate physical mem
  ptr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  assert(ptr != MAP_FAILED);

  memset(ptr, 0, len);

  memory.memory_size = len;
  memory.guest_phys_addr = 0;
  memory.flags = KVM_MEM_LOG_DIRTY_PAGES;
  memory.userspace_addr = (unsigned long) ptr;
  memory.slot = 0;
  r = ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &memory);
  assert(r != -1);

  vm_mem = ptr;
  vm_mem_size = len;

  cpusno = c;
  for (r = 0; r < cpusno; r++) {
    vcpus[r] = new VCPU(this, r);
  }

  state_type = (type_t) 0;
  ioports[0] = 0; ioports[1] = 0;
}

KVM::~KVM() {
  int r;

  for (r = 0; r < cpusno; r++) {
    delete vcpus[r];
  }

  // Destroy phisical mem
}

VCPU *KVM::Cpu(int s) {
  assert(s < cpusno);
  return vcpus[s];
}

void *KVM::Mem() {
  return vm_mem;
}

uint8_t KVM::GetIoPort(int p) {
  assert (p >= 0 && p < 2);
  return ioports[p];
}

void KVM::SetStateType(type_t t) {
  state_type = t;
}

void KVM::SetIoPort(int i, uint8_t p) {
  assert (i >= 0 && i < 2);
  ioports[i] = p;
}

type_t KVM::GetStateType() {
  return state_type;
}

void KVM::Load(const char *fname) {
  cpu_state_t s;
  header_t h;
  unsigned int r;
  int i;
  kvm_regs kregs;
  kvm_sregs ksregs;
  kvm_fpu kfpu;
  struct kvm_msr_entry msrs[MAX_MSRS];
  file f;

  // Load state from disk
  f = fopen(fname, "r");
  assert(f);

  r = fread(f, &h, sizeof(h));
  assert(r == sizeof(h));

  // Sanity checks
  assert(h.magic == EXPECTED_MAGIC);
  assert(h.version == EXPECTED_VERSION);
  assert(h.cpusno == cpusno);
  assert(h.mem_size == vm_mem_size);

  strncpy(kernel_version, h.kernel_version, sizeof(kernel_version));
  strncpy(kernel_checksum, h.kernel_checksum, sizeof(kernel_checksum));
  strncpy(testcase_checksum,  h.testcase_checksum, sizeof(testcase_checksum));

  state_type = h.type;
  ioports[0] = h.ioports[0];
  ioports[1] = h.ioports[1];

  for (i = 0; i < cpusno; i++) {
    r = fread(f, &s, sizeof(s));
    assert(r == sizeof(s));

    // Load registers
    kregs.rax = s.regs_state.rax;
    kregs.rbx = s.regs_state.rbx;
    kregs.rcx = s.regs_state.rcx;
    kregs.rdx = s.regs_state.rdx;
    kregs.rsi = s.regs_state.rsi;
    kregs.rdi = s.regs_state.rdi;
    kregs.rsp = s.regs_state.rsp;
    kregs.rbp = s.regs_state.rbp;
    kregs.rip = s.regs_state.rip;
    kregs.rflags = s.regs_state.rflags;
    kregs.r8 = s.regs_state.r8;
    kregs.r9 = s.regs_state.r9;
    kregs.r10 = s.regs_state.r10;
    kregs.r11 = s.regs_state.r11;
    kregs.r12 = s.regs_state.r12;
    kregs.r13 = s.regs_state.r13;
    kregs.r14 = s.regs_state.r14;
    kregs.r15 = s.regs_state.r15;

    // Load Sregisters
    set_kvm_segment(ksregs.cs, s.sregs_state.cs);
    set_kvm_segment(ksregs.ds, s.sregs_state.ds);
    set_kvm_segment(ksregs.es, s.sregs_state.es);
    set_kvm_segment(ksregs.fs, s.sregs_state.fs);
    set_kvm_segment(ksregs.gs, s.sregs_state.gs);
    set_kvm_segment(ksregs.ss, s.sregs_state.ss);
    set_kvm_segment(ksregs.tr, s.sregs_state.tr);
    set_kvm_segment(ksregs.ldt, s.sregs_state.ldt);

    set_kvm_table(ksregs.idt, s.sregs_state.idtr);
    set_kvm_table(ksregs.gdt, s.sregs_state.gdtr);

    ksregs.cr0 = s.sregs_state.cr0;
    ksregs.cr2 = s.sregs_state.cr2;
    ksregs.cr3 = s.sregs_state.cr3;
    ksregs.cr4 = s.sregs_state.cr4;
    ksregs.cr8 = s.sregs_state.cr8;
    ksregs.efer = s.sregs_state.efer;

    // Load fpu
    memcpy(&kfpu.fpr, &s.fpu_state.st, sizeof(s.fpu_state.st));
    kfpu.fcw = s.fpu_state.fcw;
    kfpu.fsw = s.fpu_state.fsw;
    kfpu.ftwx = s.fpu_state.ftw;
    kfpu.last_opcode = s.fpu_state.fop;
    memcpy(&kfpu.last_ip, &s.fpu_state.fpuip, 8);
    memcpy(&kfpu.last_dp, &s.fpu_state.fpudp, 8);
    kfpu.mxcsr = s.fpu_state.mxcsr;
    memcpy(&kfpu.xmm, &s.fpu_state.xmm, sizeof(s.fpu_state.xmm));
    vcpus[i]->SetRegs(&kregs);
    vcpus[i]->SetSregs(&ksregs);
    vcpus[i]->SetFPU(&kfpu);

    // Load msrs
    for (r=0; r<s.msrs_state.n; r++) {
      msrs[r].index = s.msrs_state.msr_regs[r].idx;
      msrs[r].data  = s.msrs_state.msr_regs[r].val;
    }
    vcpus[i]->SetMSRs(msrs, s.msrs_state.n);
  }

  r = fread(f, vm_mem, vm_mem_size);
  assert(r == vm_mem_size);

  fclose(f);
}

void KVM::Save(const char *fname) {
  file f;
  unsigned int r;
  int i;
  cpu_state_t s;
  header_t h;
  kvm_regs kregs;
  kvm_sregs ksregs;
  kvm_fpu kfpu;
  struct kvm_msr_entry msrs[MAX_MSRS];

  // Dump state to disk
  f = fopen(fname, "w");
  assert(f);

  memset(&s, 0, sizeof(s));

  // Fill header
  h.magic = EXPECTED_MAGIC;
  h.version = EXPECTED_VERSION;
  h.emulator = EMULATOR_KVM;
  if (getenv("KEMUFUZZER_KERNEL_VERSION")) {
    strncpy(h.kernel_version, getenv("KEMUFUZZER_KERNEL_VERSION"), sizeof(h.kernel_version));
  } else {
    strncpy(h.kernel_version, kernel_version, sizeof(h.kernel_version));
  }
  if (getenv("KEMUFUZZER_KERNEL_CHECKSUM")) {
    strncpy(h.kernel_checksum, getenv("KEMUFUZZER_KERNEL_CHECKSUM"), sizeof(h.kernel_checksum));
  } else {
    strncpy(h.kernel_checksum, kernel_checksum, sizeof(h.kernel_checksum));
  }
  if (getenv("KEMUFUZZER_TESTCASE_CHECKSUM")) {
    strncpy(h.testcase_checksum, getenv("KEMUFUZZER_TESTCASE_CHECKSUM"), sizeof(h.testcase_checksum));
  } else {
    strncpy(h.testcase_checksum, testcase_checksum, sizeof(h.testcase_checksum));
  }
  h.type = state_type;
  h.mem_size = vm_mem_size;
  h.cpusno = cpusno;
  h.ioports[0] = ioports[0];
  h.ioports[1] = ioports[1];
  r = fwrite(f, &h, sizeof(h));
  assert(r == sizeof(h));

  for (i = 0; i < cpusno; i++) {
    memset(&kregs, 0, sizeof(kregs));
    memset(&ksregs, 0, sizeof(ksregs));
    memset(&kfpu, 0, sizeof(kfpu));

    // Read VM state
    vcpus[i]->GetRegs(&kregs);
    vcpus[i]->GetSregs(&ksregs);
    vcpus[i]->GetFPU(&kfpu);

    // Fill registers state
    s.regs_state.rax = kregs.rax;
    s.regs_state.rbx = kregs.rbx;
    s.regs_state.rcx = kregs.rcx;
    s.regs_state.rdx = kregs.rdx;
    s.regs_state.rsi = kregs.rsi;
    s.regs_state.rdi = kregs.rdi;
    s.regs_state.rsp = kregs.rsp;
    s.regs_state.rbp = kregs.rbp;
    s.regs_state.rip = kregs.rip;
    s.regs_state.rflags = kregs.rflags;
    s.regs_state.r8 = kregs.r8;
    s.regs_state.r9 = kregs.r9;
    s.regs_state.r10 = kregs.r10;
    s.regs_state.r11 = kregs.r11;
    s.regs_state.r12 = kregs.r12;
    s.regs_state.r13 = kregs.r13;
    s.regs_state.r14 = kregs.r14;
    s.regs_state.r15 = kregs.r15;

    // Fill Sregisters state
    get_kvm_segment(s.sregs_state.cs, ksregs.cs);
    get_kvm_segment(s.sregs_state.ds, ksregs.ds);
    get_kvm_segment(s.sregs_state.es, ksregs.es);
    get_kvm_segment(s.sregs_state.fs, ksregs.fs);
    get_kvm_segment(s.sregs_state.gs, ksregs.gs);
    get_kvm_segment(s.sregs_state.ss, ksregs.ss);
    get_kvm_segment(s.sregs_state.tr, ksregs.tr);
    get_kvm_segment(s.sregs_state.ldt, ksregs.ldt);

    get_kvm_table(s.sregs_state.idtr, ksregs.idt);
    get_kvm_table(s.sregs_state.gdtr, ksregs.gdt);

    s.sregs_state.cr0 = ksregs.cr0;
    s.sregs_state.cr2 = ksregs.cr2;
    s.sregs_state.cr3 = ksregs.cr3;
    s.sregs_state.cr4 = ksregs.cr4;
    s.sregs_state.cr8 = ksregs.cr8;

    // Fill FPU
    memcpy(&s.fpu_state.st, &kfpu.fpr, sizeof(s.fpu_state.st));
    s.fpu_state.fcw = kfpu.fcw;
    s.fpu_state.fsw = kfpu.fsw;
    s.fpu_state.ftw = kfpu.ftwx;
    s.fpu_state.fop = kfpu.last_opcode;
    memcpy(&s.fpu_state.fpuip, &kfpu.last_ip, 8);
    memcpy(&s.fpu_state.fpudp, &kfpu.last_dp, 8);
    s.fpu_state.mxcsr = kfpu.mxcsr;
    memcpy(&s.fpu_state.xmm, &kfpu.xmm, sizeof(s.fpu_state.xmm));

    // Fill exception state
    s.exception_state.vector = vcpus[i]->exception;
    s.exception_state.error_code = 0;

    // Fill MSR state
    vcpus[i]->GetMSRs(msrs, (int *) &(s.msrs_state.n));
    for (r = 0; r < s.msrs_state.n; r++) {
      s.msrs_state.msr_regs[r].idx = msrs[r].index;
      s.msrs_state.msr_regs[r].val = msrs[r].data;
    }

    r = fwrite(f, &s, sizeof(s));
    assert(r == sizeof(s));
  }

  r = fwrite(f, vm_mem, vm_mem_size);
  assert(r == vm_mem_size);

  fclose(f);
}


void KVM::Print(FILE *f) {
  struct kvm_regs kregs;
  struct kvm_sregs ksregs;
  struct kvm_fpu kfpu;
  struct kvm_msr_entry msrs[MAX_MSRS];

  for (int i = 0; i < cpusno; i++) {
    vcpus[i]->GetRegs(&kregs);
    vcpus[i]->GetSregs(&ksregs);
    vcpus[i]->GetFPU(&kfpu);

    fprintf(f, "%s========================= CPU%d STATE =========================\n", i > 0 ? "\n" : "", i);
    fprintf(f, "RIP: %.16lx ", PAD64(kregs.rip));
    vcpus[i]->Disasm((void *) (kregs.rip + ksregs.cs.base), f);
    fprintf(f, "\n");
    fprintf(f, "RSP: %.16lx RBP: %.16lx\n", PAD64(kregs.rsp), PAD64(kregs.rbp));
    fprintf(f, "RAX: %.16lx RBX: %.16lx\n", PAD64(kregs.rax), PAD64(kregs.rbx));
    fprintf(f, "RCX: %.16lx RDX: %.16lx\n", PAD64(kregs.rcx), PAD64(kregs.rdx));
    fprintf(f, "RSI: %.16lx RDI: %.16lx\n", PAD64(kregs.rsi), PAD64(kregs.rdi));
    fprintf(f, "RFLAGS: %.16lx\n", PAD64(kregs.rflags));
    fprintf(f, "========================== SEGMENTS ==========================\n");
    fprintf(f, "CS:  %.16lx-%.16lx\n", PAD64(ksregs.cs.base), 
	    PAD64(ksregs.cs.base + ksregs.cs.limit));
    fprintf(f, "DS:  %.16lx-%.16lx\n", PAD64(ksregs.ds.base), 
	    PAD64(ksregs.ds.base + ksregs.ds.limit));
    fprintf(f, "========================== CONTROLS ==========================\n");
    fprintf(f, "CR0: %.16lx CR2: %.16lx\n", PAD64(ksregs.cr0), PAD64(ksregs.cr2));
    fprintf(f, "CR3: %.16lx CR4: %.16lx\n", PAD64(ksregs.cr3), PAD64(ksregs.cr4));
    fprintf(f, "==============================================================\n");
    
    fprintf(f, "============================ MSRS ============================\n");
    int n = sizeof(MSRs_to_save)/sizeof(int);
    for (int j = 0; j < n; j++) {
      msrs[j].index = MSRs_to_save[j];
    }
    vcpus[i]->GetMSRs(msrs, &n);
    for (int j = 0; j < n; j++) {
      fprintf(f, "#%.8x: %.16lx\n", msrs[j].index, (uint64_t) msrs[j].data);
    }
    fprintf(f, "==============================================================\n");

  }
}


#define GET32H(x) ((unsigned int) (((__u64) (x) >> 32) & 0xffffffff))
#define GET32L(x) ((unsigned int) ((__u64) (x) & 0xffffffff))

void dump_dummy_state(char *fname) {
  file f;
  cpu_state_t s;
  header_t h;
  int r;

  // Dump state to disk
  f = fopen(fname, "w");
  assert(f);

  memset(&s, 0, sizeof(s));

  // Fill header
  h.magic = EXPECTED_MAGIC;
  h.version = EXPECTED_VERSION;
  h.emulator = EMULATOR_KVM;
  if (getenv("KEMUFUZZER_KERNEL_VERSION")) {
    strncpy(h.kernel_version, getenv("KEMUFUZZER_KERNEL_VERSION"), sizeof(h.kernel_version));
  } else {
    strncpy(h.kernel_version, kernel_version, sizeof(h.kernel_version));
  }
  if (getenv("KEMUFUZZER_KERNEL_CHECKSUM")) {
    strncpy(h.kernel_checksum, getenv("KEMUFUZZER_KERNEL_CHECKSUM"), sizeof(h.kernel_checksum));
  } else {
    strncpy(h.kernel_checksum, kernel_checksum, sizeof(h.kernel_checksum));
  }
  if (getenv("KEMUFUZZER_TESTCASE_CHECKSUM")) {
    strncpy(h.testcase_checksum, getenv("KEMUFUZZER_TESTCASE_CHECKSUM"), sizeof(h.testcase_checksum));
  } else {
    strncpy(h.testcase_checksum, testcase_checksum, sizeof(h.testcase_checksum));
  }
  h.type = (type_t) (POST_TESTCASE | IO_TESTCASE);
  h.mem_size = 0;
  h.cpusno = 0;
  h.ioports[0] = 0;
  h.ioports[1] = 0;
  r = fwrite(f, &h, sizeof(h));
  assert(r == sizeof(h));
  fclose(f);
}

int main(int argc, char **argv) {
  KVM *vm;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  struct kvm_run *run;
  int r;
  uint8_t e[8];
  char tempfile[PATH_MAX];

  if (argc != 3 && argc != 2) {
    printf("Syntax: %s <input-dump> [<output-dump>]\n", argv[0]);
    return 0;
  }

  vm = new KVM(argv[1]);

  vm->Print(stdout);
  printf("\n\n");

  do {
    run = vm->Cpu()->Run();

    if (run->exit_reason == KVM_EXIT_IO && 
	run->io.direction == KVM_EXIT_IO_OUT && 
	(run->io.port == vm->GetIoPort(1))) {
      vm->Cpu()->GetRegs(&regs);
      vm->Cpu()->GetSregs(&sregs);
      vm->Cpu()->GetMem((void *) (sregs.cs.base + regs.rip - 2), 8, e);

      // Sanity check (out %al,$0xef or out %al,$0xee) 
      assert(e[0] == 0xe6 && e[1] == vm->GetIoPort(1));

      // Adjust the instruction pointer to point before the out
      regs.rip -= 2;
      vm->Cpu()->SetRegs(&regs);

      // The exception number is located 2 bytes after the out (a jump is used to
      // skip the code)
      vm->Cpu()->SetException(*((uint16_t *) (e + 4)));
      printf("Execution terminated: %x (exception %x)\n", run->io.port, 
	     *((uint16_t *) (e + 4)));

      if (argc == 3) {
	vm->SetStateType(POST_TESTCASE);
	strncpy(tempfile, "/tmp/kemufuzzer-kvm-XXXXXX", PATH_MAX - 1);
	mkstemp(tempfile);
	vm->Save(tempfile);
	rename(tempfile, argv[2]);
      }
      r = 0;
    } else if (run->exit_reason == KVM_EXIT_UNKNOWN) {
      uint32_t hw_exit;
      hw_exit = (uint32_t) (run->hw.hardware_exit_reason & 0xFFFF);

      switch(hw_exit) {
      case 13:
	// INVD
	printf("INVD, re-entering...\n");

	// Skip the faulty instruction
	vm->Cpu()->GetRegs(&regs);
	regs.rip += 2;
	vm->Cpu()->SetRegs(&regs);

	r = 1;
	break;
      default:
	// VMentry error
	printf("Failed to launch/resume VM -- error:%d "
	       "(see intel manual 3b - appendix i)\n", hw_exit);
	r = 0;
	break;
      }
    } else if (run->exit_reason == KVM_EXIT_IO ||
	       run->exit_reason == KVM_EXIT_MMIO) {
      printf("I/O, terminating execution\n");
      if (argc == 3) {
	strncpy(tempfile, "/tmp/kemufuzzer-kvm-XXXXXX", PATH_MAX - 1);
	mkstemp(tempfile);
	dump_dummy_state(tempfile);
	rename(tempfile, argv[2]);
      }
      r = 0;
      break;
    } else {
      printf("Unexpected exit (%d %d)\n", run->exit_reason, run->hw.hardware_exit_reason);
      r = 0;
    }
  } while (r);

  printf("\n\n");
  vm->Print(stdout);

  return(0);
}
