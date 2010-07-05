#ifndef TSS_H
#define TSS_H

typedef struct
{
  uint16_t limit_0_15;
  uint16_t base_0_15;
  uint8_t base_16_23;
  uint8_t type:5;
  uint8_t dpl:2;
  uint8_t present:1;
  uint8_t limit_16_19:4;
  uint8_t avl:1;
  uint8_t zero:2;
  uint8_t g:1;
  uint8_t base_24_31;
} __attribute__ ((__packed__)) tssdesc_t;

typedef struct
{
  uint16_t prev;
  uint16_t res0;
  uint32_t esp0;
  uint16_t ss0;
  uint16_t res1;
  uint32_t esp1;
  uint16_t ss1;
  uint16_t res2;
  uint32_t esp2;
  uint16_t ss2;
  uint16_t res3;
  uint32_t cr3;
  uint32_t eip;
  uint32_t eflags;
  uint32_t eax;
  uint32_t ecx;
  uint32_t edx;
  uint32_t ebx;
  uint32_t esp;
  uint32_t ebp;
  uint32_t esi;
  uint32_t edi;
  uint16_t es;
  uint16_t res4;
  uint16_t cs;
  uint16_t res5;
  uint16_t ss;
  uint16_t res6;
  uint16_t ds;
  uint16_t res7;
  uint16_t fs;
  uint16_t res8;
  uint16_t gs;
  uint16_t res9;
  uint16_t ldt;
  uint16_t res10;
  uint16_t t:1;
  uint16_t res11:15;
  uint16_t iomap;
} __attribute__ ((__packed__)) tss_t;

void set_tss(tss_t *tss, uint32_t eip, uint32_t esp, uint32_t eflags,
	     uint16_t cs, uint16_t ds, uint16_t ss, uint32_t cr3,
	     uint16_t ss0, uint16_t ss1, uint16_t ss2,
	     uint32_t sp0, uint32_t sp1, uint32_t sp2,
	     uint16_t ldt);

#endif
