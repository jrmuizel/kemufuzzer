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

#ifndef _KEMU_X86
#define _KEMU_X86

#ifdef __LP64__
#define ADDR(x) ((uint64_t) (x))
#define PTR(x) ((uint64_t *) (x))
#define CPU_64_BIT
#define CPU_BITS 64
#else
#define ADDR(x) ((uint32_t) (x))
#define PTR(x) ((uint32_t *) (x))
#define CPU_32_BIT
#define CPU_BITS 32
#endif

#define PAD64(x) ((uint64_t) (x))

/* trap/fault mnemonics */
#define EXCEPTION_DIVIDE_ERROR      0
#define EXCEPTION_DEBUG             1
#define EXCEPTION_NMI               2
#define EXCEPTION_INT3              3
#define EXCEPTION_OVERFLOW          4
#define EXCEPTION_BOUNDS            5
#define EXCEPTION_INVALID_OP        6
#define EXCEPTION_NO_DEVICE         7
#define EXCEPTION_DOUBLE_FAULT      8
#define EXCEPTION_COPRO_SEG         9
#define EXCEPTION_INVALID_TSS      10
#define EXCEPTION_NO_SEGMENT       11
#define EXCEPTION_STACK_ERROR      12
#define EXCEPTION_GP_FAULT         13
#define EXCEPTION_PAGE_FAULT       14
#define EXCEPTION_SPURIOUS_INT     15
#define EXCEPTION_COPRO_ERROR      16
#define EXCEPTION_ALIGNMENT_CHECK  17
#define EXCEPTION_MACHINE_CHECK    18
#define EXCEPTION_SIMD_ERROR       19
#define EXCEPTION_DEFERRED_NMI     31
#define EXCEPTION_NONE             0xFFFF

/* cr0 bits */
#define CR0_PE         (1u << 0)
#define CR0_MP         (1u << 1)
#define CR0_EM         (1u << 2)
#define CR0_TS         (1u << 3)
#define CR0_ET         (1u << 4)
#define CR0_NE         (1u << 5)
#define CR0_WP         (1u << 16)
#define CR0_AM         (1u << 18)
#define CR0_NW         (1u << 29)
#define CR0_CD         (1u << 30)
#define CR0_PG         (1u << 31)

#define CR4_PAE        (1u << 5)

/* rflags */
#define RFLAGS_RESERVED_MASK    2

#define RFLAGS_TRAP    (1u << 8)

#define EFER_LME       (1u << 8)

#define PAGE_4K_MASK 0xfffff000
#define PAGE_4K_SIZE 0x1000

/* MSRs */
#define X86_MSR_IA32_SYSENTER_CS            0x174
#define X86_MSR_IA32_SYSENTER_ESP           0x175
#define X86_MSR_IA32_SYSENTER_EIP           0x176
#define X86_MSR_IA32_APICBASE               0x1b
#define X86_MSR_EFER                        0xc0000080
#define X86_MSR_STAR                        0xc0000081
#define X86_MSR_PAT                         0x277
#define X86_MSR_VM_HSAVE_PA                 0xc0010117
#define X86_MSR_IA32_PERF_STATUS            0x198

#endif /* _KEMU_X86 */
