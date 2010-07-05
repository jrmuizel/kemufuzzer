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

#ifndef CPUSTATE_H
#define CPUSTATE_H

#include <stdint.h>
#include "x86.h"

#define KEMUFUZZER_HYPERCALL_START_TESTCASE  0x23
#define KEMUFUZZER_HYPERCALL_STOP_TESTCASE   0x45

#define EXPECTED_MAGIC    0xEFEF
#define EXPECTED_VERSION  0x0001

#define CPU_STATE_MAGIC          0xEFEF
#define CPU_STATE_VERSION        0x0001
#define MAX_MSRS                   0x20
#define HYPERCALL_LEN               0x2	// length of a "hypercall" instruction (in bytes)

static int MSRs_to_save[] = {
  X86_MSR_IA32_SYSENTER_CS,
  X86_MSR_IA32_SYSENTER_ESP,
  X86_MSR_IA32_SYSENTER_EIP,
  X86_MSR_IA32_APICBASE,
  X86_MSR_EFER,
  X86_MSR_STAR,
  X86_MSR_PAT,
  X86_MSR_VM_HSAVE_PA,
  X86_MSR_IA32_PERF_STATUS,  
};

typedef uint64_t reg64_t;
typedef uint32_t reg32_t;
typedef uint16_t reg16_t;

typedef struct __attribute__((__packed__)) {
  uint64_t mantissa;
  uint16_t expsign;
  uint8_t  reserved[6];
} fpust_t;

typedef struct __attribute__((__packed__)) {
  uint8_t data[16];
} fpuxmm_t;

typedef struct __attribute__((__packed__)) {
  uint16_t fcw;
  uint16_t fsw;
  uint8_t  ftw;
  uint8_t  unused;
  uint16_t fop;
  uint32_t fpuip;
  uint16_t cs;
  uint16_t reserved0;
  uint32_t fpudp;
  uint16_t ds;
  uint16_t reserved1;
  uint32_t mxcsr;
  uint32_t mxcsr_mask;

  fpust_t st[8];                // STx/MMx
  fpuxmm_t xmm[8];
  fpuxmm_t xmm_reserved[14];
} fpu_state_t;

typedef enum {
  EMULATOR_QEMU = 0,
  EMULATOR_BOCHS,
  EMULATOR_VIRTUALBOX,
  EMULATOR_VMWARE,
  EMULATOR_KVM
} emulator_t;

typedef enum {
  PRE_TESTCASE = 0,
  POST_TESTCASE = 1,
  CRASH_TESTCASE = 0x10,
  TIMEOUT_TESTCASE = 0x20,
  IO_TESTCASE = 0x40
} type_t;

typedef struct __attribute__ ((__packed__)) {
  uint16_t    magic;
  uint16_t    version;
  emulator_t  emulator;
  char        kernel_version[16];
  char        kernel_checksum[64];
  char        testcase_checksum[64];
  type_t      type;
  uint8_t     cpusno;
  uint32_t    mem_size;
  uint8_t     ioports[2];
} header_t;

typedef struct __attribute__ ((__packed__)) {
  reg64_t rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8, r9, r10;
  reg64_t r11, r12, r13, r14, r15, rip, rflags;
} regs_state_t;

typedef struct __attribute__ ((__packed__)) {
  uint64_t base;
  uint32_t limit;
  uint16_t selector;
  uint8_t type;
  uint8_t present, dpl, db, s, l, g, avl;
  uint8_t unusable;
} segment_reg_t;

typedef struct __attribute__ ((__packed__)) {
  uint64_t base;
  uint16_t limit;
} dtable_reg_t;

typedef struct __attribute__ ((__packed__)) {
  segment_reg_t cs, ds, es, fs, gs, ss;
  segment_reg_t tr, ldt;
  dtable_reg_t idtr, gdtr;
  uint64_t cr0, cr1, cr2, cr3, cr4, cr8;
  uint64_t dr0, dr1, dr2, dr3, dr6, dr7;
  uint64_t efer;
} sregs_state_t;

typedef struct __attribute__ ((__packed__)) {
  uint32_t idx;
  uint64_t val;
} msr_reg_t;

typedef struct __attribute__ ((__packed__)) {
  uint32_t n;
  msr_reg_t msr_regs[MAX_MSRS];
} msrs_state_t;

typedef struct __attribute__ ((__packed__)) {
  uint32_t vector;
  uint32_t error_code;
} exception_state_t;

typedef struct __attribute__ ((__packed__)) {
  // FPU state
  fpu_state_t fpu_state;

  // General purpose registers state
  regs_state_t regs_state;

  // Special registers state
  sregs_state_t sregs_state;

  // Exception state
  exception_state_t exception_state;

  // MSR registers state
  msrs_state_t msrs_state;
} cpu_state_t;

// HEADER + CPU[0] + CPU[1] + .... + MEM


#ifndef DONT_GZIP_STATE
#define file   gzFile
#define fwrite(a,b,c) gzwrite(a,b,c)
#define fread(a,b,c) gzread(a,b,c)
#define fclose(a) gzclose(a)
#define fopen(a,b) gzopen(a,b)
#else
#define file   FILE *
#define fwrite(a,b,c) (fwrite(b,c,1,a) * c)
#define fread(a,b,c)  (fread(b,c,1,a) * c)
#endif

#endif
