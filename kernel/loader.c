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

#include <multiboot.h>
#include <stdint.h>
#include <sys/console.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/interrupt.h>
#include <sys/tss.h>
#include <sys/asm.h>

#include "kernel.h"
#include "interrupts.h"		/* for interrupt handlers */

// Task segment descriptor Virtual 8086 Mode gdt entry
#define TSS_VM 26

extern seg_t *gdt;
extern idte_t *idt;
extern pde_t *pd;
extern pte_t *pt;
extern uint32_t mem_offset;
extern tss_t tss0, tss1, tss2, tss3, tss4, tss5, tss6, tssVM;
extern uint32_t tc_ring0_base, tc_ring0_len;
extern uint32_t tc_ring1_base, tc_ring1_len;
extern uint32_t tc_ring2_base, tc_ring2_len;
extern uint32_t tc_ring3_base, tc_ring3_len;
extern uint32_t tc_ringvm_base, tc_ringvm_len;
extern uint32_t stack_ssfaultbase, stack_ssfault, stack_doublefaultbase, stack_doublefault, stack_r0;

static void io_wait(void);

static inline void outb(uint8_t port, uint8_t val)
{
  __asm__ __volatile__ ("outb %%al, %%dx;":: "a" (val), "d" (port));
}

static inline uint8_t inb(uint8_t port)
{
  uint8_t val;
  __asm__ __volatile__ ("inb %%dx, %%al;": "=a" (val) : "d" (port));
  return val;
}

void init_pic(void);

void kmain(int, multiboot_info_t *);

void halt(void);

void switch_to_main_task(int, multiboot_info_t *);

void set_gdt_entry(seg_t *, uint32_t, uint32_t, uint8_t, uint8_t);

void set_gdt_entry_tss(seg_t *, uint32_t, uint32_t,uint8_t, uint8_t, uint8_t, uint8_t, uint8_t);

void set_gdt(void);

void set_idt(void);

void enable_paging(void);

void set_gdt_entry(seg_t *seg, uint32_t base, uint32_t limit,
		   uint8_t access, uint8_t attr)
{
  seg->base_0_15 = base & 0xffff;
  seg->base_16_23 = (base >> 16)&0xff;
  seg->base_24_31 = (base >> 24)&0xff;
  seg->limit_0_15 = limit & 0xffff;
  seg->limit_16_19 = (limit >> 16)&0xff;
  seg->access = access;
  seg->attr = attr;
}

void set_gdt_entry_tss(seg_t *seg, uint32_t base, uint32_t limit,
		       uint8_t type, uint8_t dpl, uint8_t present,
		       uint8_t avl, uint8_t granularity)
{
  tssdesc_t *tss;
  tss = (tssdesc_t *) seg;
  tss->base_0_15 = base & 0xffff;
  tss->base_16_23 = (base >> 16)&0xff;
  tss->base_24_31 = (base >> 24)&0xff;
  tss->limit_0_15 = limit & 0xffff;
  tss->limit_16_19 = (limit >> 16)&0xff;
  tss->type = type;
  tss->dpl = dpl;
  tss->present = present;
  tss->avl = 0;
  tss->g = granularity;
  tss->zero = 0;
}

void set_gdt(void)
{
  seg_t *ph_gdt;
  gdtr_t gdtr;
#ifdef DEBUG
  tssdesc_t *tssdesc;
#endif
  ph_gdt = (seg_t *)((unsigned int)(&gdt) - mem_offset);

  set_gdt_entry(&ph_gdt[0], 0, 0, 0, 0);

  /* The "| 0x1" mask applied to code segment is needed to flag the segment as
     "accessed" (bit 0 of the "type" field). Otherwise, VMENTER checks fail. */

  set_gdt_entry_tss(&ph_gdt[1], (uint32_t) &tss0, sizeof(tss_t), 0x9, 0, 1, 0, 0);
  set_gdt_entry_tss(&ph_gdt[2], (uint32_t) &tss1, sizeof(tss_t), 0x9, 0, 1, 0, 0);
  set_gdt_entry_tss(&ph_gdt[3], (uint32_t) &tss2, sizeof(tss_t), 0x9, 0, 1, 0, 0);
  set_gdt_entry_tss(&ph_gdt[4], (uint32_t) &tss3, sizeof(tss_t), 0x9, 0, 1, 0, 0);
  set_gdt_entry_tss(&ph_gdt[5], (uint32_t) &tss4, sizeof(tss_t), 0x9, 1, 1, 0, 0);
  set_gdt_entry_tss(&ph_gdt[6], (uint32_t) &tss5, sizeof(tss_t), 0x9, 2, 1, 0, 0);
  set_gdt_entry_tss(&ph_gdt[7], (uint32_t) &tss6, sizeof(tss_t), 0x9, 3, 1, 0, 0);
  set_gdt_entry_tss(&ph_gdt[TSS_VM], (uint32_t) &tssVM, sizeof(tss_t), 0x9, 3, 1, 0, 0);

  set_gdt_entry(&ph_gdt[8],  0, 0xfffff, ACS_CODE  | 0x1,  0xc);
  set_gdt_entry(&ph_gdt[9],  0, 0xfffff, ACS_DATA,  0xc);
  set_gdt_entry(&ph_gdt[10], 0, 0xfffff, ACS_STACK, 0xc);
  set_gdt_entry(&ph_gdt[11], stack_ssfaultbase, stack_ssfault / 4096, ACS_STACK, 0xc);
  set_gdt_entry(&ph_gdt[12], stack_doublefaultbase, stack_doublefault / 4096, ACS_STACK, 0xc);

#define ACS_DPL(n) (((n)&0x3)<<5)
#define SEL_INDEX(n) ((n) >> 3)
  /* For SYSENTER/SYSEXIT to work, cs_ring3 = cs_ring0 + 16, while ss_ring3 = cs_ring0 + 24 */
  set_gdt_entry(&ph_gdt[SEL_INDEX(SEL_RING0_CS)], tc_ring0_base, tc_ring0_len/4096, ACS_CODE  | ACS_DPL(0) | 0x1, 0xc);
  set_gdt_entry(&ph_gdt[SEL_INDEX(SEL_RING0_DS)], tc_ring0_base, tc_ring0_len/4096, ACS_DATA  | ACS_DPL(0), 0xc);
  set_gdt_entry(&ph_gdt[SEL_INDEX(SEL_RING0_SS)], tc_ring0_base, tc_ring0_len/4096, ACS_STACK | ACS_DPL(0), 0xc);

  set_gdt_entry(&ph_gdt[SEL_INDEX(SEL_RING1_CS)], tc_ring1_base, tc_ring1_len/4096, ACS_CODE  | ACS_DPL(1) | 0x1, 0xc);
  set_gdt_entry(&ph_gdt[SEL_INDEX(SEL_RING1_DS)], tc_ring1_base, tc_ring1_len/4096, ACS_DATA  | ACS_DPL(1), 0xc);
  set_gdt_entry(&ph_gdt[SEL_INDEX(SEL_RING1_SS)], tc_ring1_base, tc_ring1_len/4096, ACS_STACK | ACS_DPL(1), 0xc);

  set_gdt_entry(&ph_gdt[SEL_INDEX(SEL_RING2_CS)], tc_ring2_base, tc_ring2_len/4096, ACS_CODE  | ACS_DPL(2) | 0x1, 0xc);
  set_gdt_entry(&ph_gdt[SEL_INDEX(SEL_RING2_DS)], tc_ring2_base, tc_ring2_len/4096, ACS_DATA  | ACS_DPL(2), 0xc);
  set_gdt_entry(&ph_gdt[SEL_INDEX(SEL_RING2_SS)], tc_ring2_base, tc_ring2_len/4096, ACS_STACK | ACS_DPL(2), 0xc);

  set_gdt_entry(&ph_gdt[SEL_INDEX(SEL_RING3_CS)], tc_ring3_base, tc_ring3_len/4096, ACS_CODE  | ACS_DPL(3) | 0x1, 0xc);
  set_gdt_entry(&ph_gdt[SEL_INDEX(SEL_RING3_DS)], tc_ring3_base, tc_ring3_len/4096, ACS_DATA  | ACS_DPL(3), 0xc);
  set_gdt_entry(&ph_gdt[SEL_INDEX(SEL_RING3_SS)], tc_ring3_base, tc_ring3_len/4096, ACS_STACK | ACS_DPL(3), 0xc);

#undef SEL_INDEX
#undef ACS_DPL

  /* LDTR */
  set_gdt_entry(&ph_gdt[25], 0, 0xffff, 0x2 | (1 << 7), 0);

  gdtr.base = (uint32_t) ph_gdt;
  gdtr.limit = sizeof(seg_t)*(GDT_ENTRY+1);

#ifdef DEBUG
  tssdesc = (tssdesc_t *)&ph_gdt[4];
  kprintf("tss type before activation: %08x\n", tssdesc->type);
#endif

  set_gdtr(&gdtr);
  set_ds(0x48);
  set_ss(0x50);
  set_es(0x48);
  set_fs(0x48);
  set_gs(0x48);
  set_cs(0x40);
  set_tr(0x10);
  set_ldtr(0xc8);
}

void enable_paging(void)
{
  uint32_t addr;
  int i;
  pde_t *p_dir;
  pte_t *p_tab;

  p_dir = (pde_t *)((unsigned int)(&pd) - mem_offset);
  p_tab = (pte_t *)((unsigned int)(&pt) - mem_offset);
  for(i=0;i<1024;i++) {
    p_dir[i].raw = 0;
    p_tab[i].raw = 0;
  }

  for(addr = 0; addr < 0x400000; addr += 0x1000) {
    /* 0x7: present, write allowed, user access allowed */
    p_dir[addr>>22].raw = ((uint32_t)p_tab) | 0x7;
    p_tab[(addr>>12)&0x3ff].raw = addr | 0x7;
  }

  set_cr3((get_cr3() & 0xfff) | (((uint32_t)(p_dir))&0xfffff000));
  set_cr0(get_cr0() | 0x80000000);
}

void set_idt(void)
{
  idtr_t idtr;
  idte_t *ph_idt;

  ph_idt = (idte_t *)((unsigned int)(&idt) - mem_offset);

  set_interrupt_handlers(ph_idt, 0x40);

  idtr.base = (uint32_t)ph_idt;
  idtr.limit = INTERRUPTS*8;

  set_idtr(&idtr);

  outb(0x70, inb(0x70) | 0x80);

  return;
}

int init(int magic, multiboot_info_t *mbi)
{
  init_pic();
  console_init(80,24);
  set_gdt();
  enable_paging();
  set_idt();
  enable_interrupts();
  switch_to_main_task(magic, mbi);
/*   kmain(magic, mbi); */
  return 0;
}

void switch_to_main_task(int magic, multiboot_info_t *mbi)
{
  uint32_t *sp;
  uint32_t esp;
  sp = (uint32_t *) stack_r0;

  *(--sp) = (uint32_t) mbi;
  *(--sp) = (uint32_t) magic;
  *(--sp) = (uint32_t) halt;
  esp = (uint32_t) sp;

  set_tss(&tss0, (uint32_t) kmain, esp, get_eflags(), 0x40, 0x48, 0x50, get_cr3(), 0x50, 0x50, 0x50, esp, esp, esp, 0xc8);
  __asm__ __volatile__ ("jmp $0x08, $0x0;");
}

void init_pic(void)
{
  outb(PIC1_COMMAND, ICW1_INIT+ICW1_ICW4);  // starts the initialization sequence
  io_wait();
  outb(PIC2_COMMAND, ICW1_INIT+ICW1_ICW4);
  io_wait();
  outb(PIC1_DATA, 0x20);                 // define the PIC vectors
  io_wait();
  outb(PIC2_DATA, 0x28);
  io_wait();
  outb(PIC1_DATA, 4);                       // continue initialization sequence
  io_wait();
  outb(PIC2_DATA, 2);
  io_wait();
  
  outb(PIC1_DATA, ICW4_8086);
  io_wait();
  outb(PIC2_DATA, ICW4_8086);
  io_wait();
  
  outb(PIC1_DATA, 0xff);   // restore saved masks.
  outb(PIC2_DATA, 0xff);

}

static void io_wait(void)
{
  outb(0x80, 0);
}
