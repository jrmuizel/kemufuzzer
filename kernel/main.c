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

#include <stdio.h>
#include <stdint.h>
#include <multiboot.h>
#include <sys/console.h>
#include <sys/mman.h>
#include <sys/interrupt.h>
#include <sys/tss.h>
#include <sys/asm.h>
#include <sys/fpu.h>

#include "kernel.h"
#include "interrupts.h"        /* for interrupt handlers */

#define MSR_SYSENTER_CS  0x174
#define MSR_SYSENTER_ESP 0x175
#define MSR_SYSENTER_EIP 0x176

/* EFLAGS masks */
#define CC_C   	0x0001
#define CC_P 	0x0004
#define CC_A	0x0010
#define CC_Z	0x0040
#define CC_S    0x0080
#define CC_O    0x0800
#define DF_MASK 		0x00000400

#define CHECK_FLAG(flags,bit)   ((flags) & (1 << (bit)))

extern uint32_t tc_ring0_base, tc_ring0_len, stack_r0;
extern uint32_t tc_ring1_base, tc_ring1_len;
extern uint32_t tc_ring2_base, tc_ring2_len;
extern uint32_t tc_ring3_base, tc_ring3_len;
extern uint32_t tc_ringvm_base, tc_ringvm_len, tcringvm;

seg_t gdt[GDT_ENTRY] __attribute__ ((aligned(4096)));
pde_t pd[1024] __attribute__ ((aligned(4096)));
pte_t pt[1024] __attribute__ ((aligned(4096)));
idte_t idt[INTERRUPTS] __attribute__ ((aligned(4096)));

tss_t tss0, tss1, tss2, tss3, tss4, tss5, tss6, tssVM;

/* FPU state -- 512 bytes */
static uint32_t fpustate[]  __attribute__ ((aligned (16))) = {
  0x0000037f,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00001f80,0x0000ffff,0x00000000,0x00000000,
  0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
  0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
  0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
  0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
  0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
  0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
  0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
  0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
  0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
  0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
  0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
  0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000
};

int divby(int,int);

void switch_to_testcase_task(void) __attribute__ ((noinline));

void init_memory(void);

inline void init_fpu(void);

void init_msr(void);

void halt(void);

void dump_state(void);

void invalidateTLB(void);

void kmain(int magic, multiboot_info_t *mbi)
{
/*   console_init(80,24); */
#ifdef DEBUG
  tssdesc_t *tssdesc;
#endif
  uint32_t esp0, esp1, esp2, esp3, espVM;

  if (magic != MULTIBOOT_BOOTLOADER_MAGIC)
    {
      kprintf ("Invalid magic number: 0x%x\n", (unsigned) magic);
      return;
    }

#ifdef VERBOSE
  /* Print out the flags. */
  kprintf ("flags = 0x%x\n", (unsigned) mbi->flags);

  /* Are mem_* valid? */
  if (CHECK_FLAG (mbi->flags, 0))
    kprintf ("mem_lower = %uKB, mem_upper = %uKB\n",
	    (unsigned) mbi->mem_lower, (unsigned) mbi->mem_upper);
     
  /* Is boot_device valid? */
  if (CHECK_FLAG (mbi->flags, 1))
    kprintf ("boot_device = 0x%x\n", (unsigned) mbi->boot_device);
     
  /* Is the command line passed? */
  if (CHECK_FLAG (mbi->flags, 2))
    kprintf ("cmdline = %s\n", (char *) mbi->cmdline);
     
  /* Are mods_* valid? */
  if (CHECK_FLAG (mbi->flags, 3))
    {
      module_t *mod;
      int i;
     
      kprintf ("mods_count = %d, mods_addr = 0x%x\n",
	      (int) mbi->mods_count, (int) mbi->mods_addr);
      for (i = 0, mod = (module_t *) mbi->mods_addr;
	   i < mbi->mods_count;
	   i++, mod++)
	kprintf (" mod_start = 0x%x, mod_end = 0x%x, string = %s\n",
		(unsigned) mod->mod_start,
		(unsigned) mod->mod_end,
		(char *) mod->string);
    }
     
  /* Bits 4 and 5 are mutually exclusive! */
  if (CHECK_FLAG (mbi->flags, 4) && CHECK_FLAG (mbi->flags, 5))
    {
      kprintf ("Both bits 4 and 5 are set.\n");
      return;
    }
     
  /* Is the symbol table of a.out valid? */
  if (CHECK_FLAG (mbi->flags, 4))
    {
      aout_symbol_table_t *aout_sym = &(mbi->u.aout_sym);
     
      kprintf ("aout_symbol_table: tabsize = 0x%0x, "
	      "strsize = 0x%x, addr = 0x%x\n",
	      (unsigned) aout_sym->tabsize,
	      (unsigned) aout_sym->strsize,
	      (unsigned) aout_sym->addr);
    }
     
  /* Is the section header table of ELF valid? */
  if (CHECK_FLAG (mbi->flags, 5))
    {
      elf_section_header_table_t *elf_sec = &(mbi->u.elf_sec);
     
      kprintf ("elf_sec: num = %u, size = 0x%x,"
	      " addr = 0x%x, shndx = 0x%x\n",
	      (unsigned) elf_sec->num, (unsigned) elf_sec->size,
	      (unsigned) elf_sec->addr, (unsigned) elf_sec->shndx);
    }
     
  /* Are mmap_* valid? */
  if (CHECK_FLAG (mbi->flags, 6))
    {
      memory_map_t *mmap;
     
      kprintf ("mmap_addr = 0x%x, mmap_length = 0x%x\n",
	      (unsigned) mbi->mmap_addr, (unsigned) mbi->mmap_length);
      for (mmap = (memory_map_t *) mbi->mmap_addr;
	   (unsigned long) mmap < mbi->mmap_addr + mbi->mmap_length;
	   mmap = (memory_map_t *) ((unsigned long) mmap
				    + mmap->size + sizeof (mmap->size)))
	kprintf (" size = 0x%x, base_addr = 0x%x%x,"
		" length = 0x%x%x, type = 0x%x\n",
		(unsigned) mmap->size,
		(unsigned) mmap->base_addr_high,
		(unsigned) mmap->base_addr_low,
		(unsigned) mmap->length_high,
		(unsigned) mmap->length_low,
		(unsigned) mmap->type);
    }
#endif

#ifdef DEBUG
  kprintf("kernel speaking with paging enabled :D\n");

  tssdesc = (tssdesc_t *)&gdt[4];
  kprintf("tss1 type after activation: %08x\n", tssdesc->type);
  tssdesc = (tssdesc_t *)&gdt[5];
  kprintf("tss0 type after activation of tss1: %08x\n", tssdesc->type);
#endif

  esp0 = tc_ring0_len / 2;
  esp1 = tc_ring1_len / 2;
  esp2 = tc_ring2_len / 2;
  esp3 = tc_ring3_len / 2;
#if 1
  /* 
     FIXME FIXME FIXME

     Questa l'ho messa perché altrimenti capita che VMware dia differenze in
     indirizzi di memoria interni al tss1. Non ho ben capito a cosa serve il
     task 1, visto che sembra non venir nemmeno inizializzato.
     Any idea?

     FIXME FIXME FIXME
   */

  set_tss(&tss1, 0, 0, get_eflags(), 
	  SEL_RPL(SEL_RING0_CS,0), SEL_RPL(SEL_RING0_DS,0), SEL_RPL(SEL_RING0_SS,0), get_cr3(), 
	  SEL_RPL(SEL_RING0_SS,0), SEL_RPL(SEL_RING1_SS,1), SEL_RPL(SEL_RING2_SS,2), esp0, esp1, esp2, 0xc8);
#endif

  /* Ring 0 */
  set_tss(&tss3, 0, esp0, get_eflags(), 
	  SEL_RPL(SEL_RING0_CS,0), SEL_RPL(SEL_RING0_DS,0), SEL_RPL(SEL_RING0_SS,0), get_cr3(), 
	  SEL_RPL(SEL_RING0_SS,0), SEL_RPL(SEL_RING1_SS,1), SEL_RPL(SEL_RING2_SS,2), esp0, esp1, esp2, 0xc8);

  /* Ring 1 */
  set_tss(&tss4, 0, esp1, get_eflags(), 
	  SEL_RPL(SEL_RING1_CS,1), SEL_RPL(SEL_RING1_DS,1), SEL_RPL(SEL_RING1_SS,1), get_cr3(), 
	  SEL_RPL(SEL_RING0_SS,0), SEL_RPL(SEL_RING1_SS,1), SEL_RPL(SEL_RING2_SS,2), esp0, esp1, esp2, 0xc8);

  /* Ring 2 */
  set_tss(&tss5, 0, esp2, get_eflags(), 
	  SEL_RPL(SEL_RING2_CS,2), SEL_RPL(SEL_RING2_DS,2), SEL_RPL(SEL_RING2_SS,2), get_cr3(), 
	  SEL_RPL(SEL_RING0_SS,0), SEL_RPL(SEL_RING1_SS,1), SEL_RPL(SEL_RING2_SS,2), esp0, esp1, esp2, 0xc8);

  /* Ring 3 */
  set_tss(&tss6, 0, esp3, get_eflags(), 
	  SEL_RPL(SEL_RING3_CS,3), SEL_RPL(SEL_RING3_DS,3), SEL_RPL(SEL_RING3_SS,3), get_cr3(), 
	  SEL_RPL(SEL_RING0_SS,0), SEL_RPL(SEL_RING1_SS,1), SEL_RPL(SEL_RING2_SS,2), esp0, esp1, esp2, 0xc8);

  /* Create new TSS - Task-State Segment  */
  /*    EFLAGS.VM[bit 17]= 1 */
  /*    eip= 0 */

  /* Segment selector TSS Descriptor */
  /* RPL[0:1 bit] => requested privilege level     = 3 */
  /* TI[2 bit]    => table indicator 0=GDT 1=LDT   = 0 */
  /* Index        => selector in the GDT           = X */
  
  /* TSS_VM Descriptor GDT_ENTRY= 26 */
  /* 0000000011010 | 0 | 11 = 0xD3 = 26/CPL3 */

  /* far call entry GDT (segment selector) */
  
  //set_tss(&tssVM, 0, 0x100, (get_eflags()|VM_BIT), 
/*   set_tss(&tssVM, 0, espVM, 0x20302,  */
/* 	  SEL_VM_CS, SEL_VM_DS, SEL_VM_SS, get_cr3(),  */
/* 	  SEL_RPL(SEL_RING0_SS,0), SEL_RPL(SEL_RING1_SS,1), SEL_RPL(SEL_RING2_SS,2), esp0, esp1, esp2, 0xc8); */

  set_tss(&tssVM, VM_EIP, VM_ESP, (get_eflags()|VM_BIT), 
	  SEL_VM_CS, SEL_VM_DS, SEL_VM_SS, get_cr3(), 
	  SEL_RPL(SEL_RING0_SS,0), SEL_RPL(SEL_RING1_SS,1), SEL_RPL(SEL_RING2_SS,2), esp0, esp1, esp2, 0xc8);

#if 1
  init_memory();
  init_fpu();
  init_msr();
#endif

#ifdef DEBUG
  __asm__ __volatile__ ("hlt;");
#endif

#ifdef CR0_WP
  __asm__ __volatile__(
	"push %eax;"
	"mov %cr0, %eax;"
	"orl $0x10000,%eax;"
	"mov %eax, %cr0;"
	"pop %eax;"
	);
#endif

    switch_to_testcase_task();
}

void invalidateTLB(void)
{
  __asm__ __volatile__("mov %cr3, %eax;"
		       "mov %eax, %cr3;");
}

void init_memory(void)
{
#define zeroregion(x,sz) {			\
    register unsigned char *p;			\
    register unsigned int i;			\
    p = (unsigned char*) (x);			\
    for (i=0; i<sz; i++)			\
      p[i] = '\0';				\
}
#define zeropage(x) zeroregion(x, 0x1000)
  /* Init memory */
  zeropage  (0x00100000);
  zeropage  (0x00102000);
  zeroregion(0x00110000, 0x1000*12);
  zeropage  (0x00167000);
  zeroregion(0x002f0000, 0x1000*16);
  zeropage  (0x003f0000);
  zeropage  (0x003f1000);
#undef zeropage
}

inline void init_fpu(void)
{
  /* Enable FPU (clear CR0 bits 2 and 3) */
  set_cr0(get_cr0() & ~(1 << 2 | 1 << 3));

  /* Enable FXSAVE & FXRSTOR (set bit 9 in CR4) */
  set_cr4(get_cr4() | (1 << 9));

  /* Initialize FPU */
  asm __volatile__ ("fxrstor %0;" : : "m" (*fpustate));
}

void init_msr(void)
{
  wrmsr(MSR_SYSENTER_CS,  0, SEL_RING0_CS);
  wrmsr(MSR_SYSENTER_ESP, 0, tc_ring0_len / 2);
  wrmsr(MSR_SYSENTER_EIP, 0, tc_ring0_base);
}

void halt(void)
{
  kprintf("system is halted ;)\n");
  __asm__ __volatile__ ("hlt;");
}

void  switch_to_testcase_task(void)
{
  // Dummy interrupt (iret) to touch the page containing interrupt handlers and to
  // prevent synthetic pagefaults in KVM (that might corrupt RF).
  // It doesn't work here! Inserted automatically as first instruction of a test-case
  //  __asm__ __volatile__ ("int $0x21");

  /* tcsel: (ring0) 0x20, (ring1) 0x29, (ring2) 0x32, (ring3) 0x3b (ringVM) 0xd3 */

  /* Store dr7 on the top of the stack */
  __asm__ __volatile__ (
			"push %eax;"
			"mov %dr7, %eax;"
			"xchg %eax, (%esp);"
			"pushf;"
			"popf;"
			);

#if 0
  /* Set RFLAGS */
  __asm__ __volatile__ (
			"or %%eax, %%eax;"
			"pushf;"
			"andl %0, (%%esp);"
			"popf;"
			: : "i" (~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C))
			);
#endif

  __asm__ __volatile__ (
			/* @QEMU: Keep CC_OP initialized */
			"xorl %eax, %eax;"

			/* Force the creation of a new BB */
			"jmp forward;"
			"forward:"

			/* Notify the beginning of the bb */
			"out %al, $0x23;"
			"testcase_start:"
			".byte 0xea;"
                        ".long 0x00;"
			"tcstartring:"
			".word 0x20;"
			);
  // "jmp $0x28, $0x0;"
}

int divby(int a, int b)
{
  int c;
  c = a / b;
  return c;
}
