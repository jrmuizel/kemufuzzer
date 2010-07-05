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


#include <stdint.h>
#include <sys/asm.h>

#define xstr(s) str(s)
#define str(s) #s

#define GET_SELECTOR(n)						\
  uint16_t get_##n(void)					\
  {								\
    uint16_t s;							\
    asm __volatile__ ("mov %%" str(n) ", %0;" : "=m" (s));	\
    return s;							\
  }

GET_SELECTOR(cs)
GET_SELECTOR(ds)
GET_SELECTOR(ss)
GET_SELECTOR(fs)
GET_SELECTOR(gs)
GET_SELECTOR(es)

#undef GET_SELECTOR

void set_cs(uint16_t cs)
{
  switch(cs)
    {
    case 0x8:
      __asm__ __volatile__ ("jmp $0x8, $asd0x8;"
			    "asd0x8:"
			    "nop;"
			    );
      break;
    case 0x40:
      __asm__ __volatile__ ("jmp $0x40, $asd0x40;"
			    "asd0x40:"
			    "nop;"
			    );
      break;
    default:
      __asm__ __volatile__ ("hlt;");
    }
}

void set_ds(uint16_t ds)
{
  __asm__ __volatile__ ("mov %0, %%ds":: "r" (ds));
}

void set_ss(uint16_t ss)
{
  __asm__ __volatile__ ("mov %0, %%ss":: "r" (ss));
}

void set_es(uint16_t es)
{
  __asm__ __volatile__ ("mov %0, %%es":: "r" (es));
}

void set_fs(uint16_t fs)
{
  __asm__ __volatile__ ("mov %0, %%fs":: "r" (fs));
}

void set_gs(uint16_t gs)
{
  __asm__ __volatile__ ("mov %0, %%gs":: "r" (gs));
}

void set_cr3(uint32_t cr3)
{
  __asm__ __volatile__ ("mov %0, %%cr3":: "r" (cr3));
}

uint32_t get_cr3(void)
{
  uint32_t cr3;

  __asm__ __volatile__ ("mov %%cr3, %0":"=r" (cr3));

  return cr3;
}

void set_cr2(uint32_t cr2)
{
  __asm__ __volatile__ ("mov %0, %%cr2":: "r" (cr2));
}

uint32_t get_cr2(void)
{
  uint32_t cr2;

  __asm__ __volatile__ ("mov %%cr2, %0":"=r" (cr2));

  return cr2;
}

void set_cr0(uint32_t cr0)
{
  __asm__ __volatile__ ("mov %0, %%cr0":: "r" (cr0));
}

uint32_t get_cr0(void)
{
  uint32_t cr0;

  __asm__ __volatile__ ("mov %%cr0, %0": "=r" (cr0));

  return cr0;
}

void set_cr4(uint32_t cr4)
{
  __asm__ __volatile__ ("mov %0, %%cr4":: "r" (cr4));
}

uint32_t get_cr4(void)
{
  uint32_t cr4;

  __asm__ __volatile__ ("mov %%cr4, %0": "=r" (cr4));

  return cr4;
}

void set_gdtr(gdtr_t *gdtr)
{
  __asm__ __volatile__ ("lgdt %0":: "m" (*gdtr));
}

void get_gdtr(gdtr_t *gdtr)
{
  __asm__ __volatile__ ("sgdt %0":: "m" (*gdtr));
}

void set_idtr(idtr_t *idtr)
{
  __asm__ __volatile__ ("lidt %0":: "m" (*idtr));
}

void set_tr(uint16_t tr)
{
  __asm__ __volatile__ ("ltr %0":: "r" (tr));
}

void set_ldtr(uint16_t ldtr)
{
  __asm__ __volatile__ ("lldt %0":: "r" (ldtr));
}

void outport(uint8_t port, uint8_t val)
{
  __asm__ __volatile__ ("outb %%al, %%dx;":: "a" (val), "d" (port));
}

uint8_t inport(uint8_t port)
{
  uint8_t val;
  __asm__ __volatile__ ("inb %%dx, %%al;": "=a" (val) : "d" (port));
  return val;
}

void enable_interrupts(void)
{
  __asm__ __volatile__ ("sti;");
}

uint32_t get_eflags(void)
{
  uint32_t eflags;

  __asm__ __volatile__ ("pushf; pop %0;": "=r" (eflags));

  return eflags;
}

void set_eflags(uint32_t eflags)
{
  __asm__ __volatile__ ("mov %0, %%eax;"
			"push %%eax;"
			"popf;": : "m" (eflags));
}

void wrmsr(uint32_t n, uint32_t vhigh, uint32_t vlow)
{
  __asm__ __volatile__ (
			"push %%eax;"
			"push %%ecx;"
			"push %%edx;"
			"mov %0, %%edx;"
			"mov %1, %%eax;"
			"mov %2, %%ecx;"
			"wrmsr;"
			"pop %%edx;"
			"pop %%ecx;"
			"pop %%eax;"
			:: "m" (vhigh), "m" (vlow), "m" (n)
			);
}
