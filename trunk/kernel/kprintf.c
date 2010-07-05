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

#include <stdarg.h>
#include <sys/console.h>
#include <sys/asm.h>

#include "kernel.h"

uint32_t handler_stack_errcode, handler_stack_eip, handler_stack_cs, handler_stack_eflags, 
  handler_stack_esp, handler_stack_ss, original_esp;

static void printchar(char **str, int c)
{
  if (str) {
    **str = c;
    ++(*str);
  }
  else console_putc(c);
}

#define PAD_RIGHT 1
#define PAD_ZERO 2

static int prints(char **out, const char *string, int width, int pad)
{
  register int pc = 0, padchar = ' ';

  if (width > 0) {
    register int len = 0;
    register const char *ptr;
    for (ptr = string; *ptr; ++ptr) ++len;
    if (len >= width) width = 0;
    else width -= len;
    if (pad & PAD_ZERO) padchar = '0';
  }
  if (!(pad & PAD_RIGHT)) {
    for ( ; width > 0; --width) {
      printchar (out, padchar);
      ++pc;
    }
  }
  for ( ; *string ; ++string) {
    printchar (out, *string);
    ++pc;
  }
  for ( ; width > 0; --width) {
    printchar (out, padchar);
    ++pc;
  }

  return pc;
}

/* the following should be enough for 32 bit int */
#define PRINT_BUF_LEN 12

static int printi(char **out, int i, int b, int sg, int width, int pad, int letbase)
{
  char print_buf[PRINT_BUF_LEN];
  register char *s;
  register int t, neg = 0, pc = 0;
  register unsigned int u = i;

  if (i == 0) {
    print_buf[0] = '0';
    print_buf[1] = '\0';
    return prints (out, print_buf, width, pad);
  }

  if (sg && b == 10 && i < 0) {
    neg = 1;
    u = -i;
  }

  s = print_buf + PRINT_BUF_LEN-1;
  *s = '\0';

  while (u) {
    t = u % b;
    if( t >= 10 )
      t += letbase - '0' - 10;
    *--s = t + '0';
    u /= b;
  }

  if (neg) {
    if( width && (pad & PAD_ZERO) ) {
      printchar (out, '-');
      ++pc;
      --width;
    }
    else {
      *--s = '-';
    }
  }

  return pc + prints (out, s, width, pad);
}

static int print(char **out, const char *format, va_list args )
{
  register int width, pad;
  register int pc = 0;
  char scr[2];

  for (; *format != 0; ++format) {
    if (*format == '%') {
      ++format;
      width = pad = 0;
      if (*format == '\0') break;
      if (*format == '%') goto out;
      if (*format == '-') {
	++format;
	pad = PAD_RIGHT;
      }
      while (*format == '0') {
	++format;
	pad |= PAD_ZERO;
      }
      for ( ; *format >= '0' && *format <= '9'; ++format) {
	width *= 10;
	width += *format - '0';
      }
      if( *format == 's' ) {
	register char *s = (char *)va_arg( args, int );
	pc += prints (out, s?s:"(null)", width, pad);
	continue;
      }
      if( *format == 'd' ) {
	pc += printi (out, va_arg( args, int ), 10, 1, width, pad, 'a');
	continue;
      }
      if( *format == 'x' ) {
	pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'a');
	continue;
      }
      if( *format == 'X' ) {
	pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'A');
	continue;
      }
      if( *format == 'u' ) {
	pc += printi (out, va_arg( args, int ), 10, 0, width, pad, 'a');
	continue;
      }
      if( *format == 'c' ) {
	/* char are converted to int then pushed on the stack */
	scr[0] = (char)va_arg( args, int );
	scr[1] = '\0';
	pc += prints (out, scr, width, pad);
	continue;
      }
    }
    else {
    out:
      printchar (out, *format);
      ++pc;
    }
  }
  if (out) **out = '\0';
  va_end( args );
  return pc;
}

int kprintf(const char *format, ...)
{
  va_list args;
        
  va_start( args, format );
  return print( 0, format, args );
}

int ksprintf(char *out, const char *format, ...)
{
  va_list args;
        
  va_start( args, format );
  return print( &out, format, args );
}

static void dump_gdt_entry(seg_t *e, int i)
{
  uint32_t base;
  uint32_t limit;

  base  = e->base_0_15 | (e->base_16_23 << 16) | (e->base_24_31 << 24);
  limit = e->limit_0_15 | (e->limit_16_19 << 16);

  kprintf("gdt[%02d]: bas=%08x lim=%08x typ=%02x s=%d dpl=%d p=%d avl=%d l=%d d_b=%d g=%d\n", 
	  i, base, limit, e->type, e->s, e->dpl, e->p, e->avl, e->l, e->d_b, e->g);
}

void dump_state(uint32_t exc)
{
  uint32_t r1,r2,r3,r4, eflags, *p;  
  seg_t *gdt;
  gdtr_t gdtr;

  /* Save RFLAGS */
  asm __volatile__ ("push %%eax;"
		    "pushf;"
		    "pop %%eax;"
		    "mov %%eax, %0;"
		    "pop %%eax;" : "=m" (eflags));

  /* Dump general-purpose registers */
  asm __volatile__ ("mov %%eax, %0" : "=m" (r1));
  asm __volatile__ ("mov %%ebx, %0" : "=m" (r2));
  asm __volatile__ ("mov %%ecx, %0" : "=m" (r3));
  asm __volatile__ ("mov %%edx, %0" : "=m" (r4));
  kprintf("eax: %08x ebx: %08x ecx: %08x edx: %08x\n", r1, r2, r3, r4);

  asm __volatile__ ("mov %%esi, %0" : "=m" (r1));
  asm __volatile__ ("mov %%edi, %0" : "=m" (r2));
  asm __volatile__ ("mov %%ebp, %0" : "=m" (r4));
  kprintf("esi: %08x edi: %08x esp: %08x ebp: %08x eflags: %08x\n", r1, r2, original_esp, r4, eflags);

  /* Dump control registers */
  kprintf("cr0: %08x cr2: %08x cr3: %08x cr4: %08x\n", get_cr0(), get_cr2(), get_cr3(), get_cr4());

  /* Dump segment selectors */
  kprintf("cs: %02x ss: %02x ds: %02x es: %02x fs: %02x gs: %02x\n", 
	  get_cs(), get_ss(), get_ds(), get_es(), get_fs(), get_gs());
  kprintf("\n");

  /* Dump GDT entries */
  get_gdtr(&gdtr);
  gdt = (seg_t*) gdtr.base;

#define SEL_INDEX(n) ((n) >> 3)
  /* Ring0 */
  dump_gdt_entry(&gdt[SEL_INDEX(SEL_RING0_CS)], SEL_INDEX(SEL_RING0_CS));
  dump_gdt_entry(&gdt[SEL_INDEX(SEL_RING0_DS)], SEL_INDEX(SEL_RING0_DS));
  dump_gdt_entry(&gdt[SEL_INDEX(SEL_RING0_SS)], SEL_INDEX(SEL_RING0_SS));
  kprintf("\n");

  /* Ring1 */
  dump_gdt_entry(&gdt[SEL_INDEX(SEL_RING1_CS)], SEL_INDEX(SEL_RING1_CS));
  dump_gdt_entry(&gdt[SEL_INDEX(SEL_RING1_DS)], SEL_INDEX(SEL_RING1_DS));
  dump_gdt_entry(&gdt[SEL_INDEX(SEL_RING1_SS)], SEL_INDEX(SEL_RING1_SS));
  kprintf("\n");

  /* Ring2 */
  dump_gdt_entry(&gdt[SEL_INDEX(SEL_RING2_CS)], SEL_INDEX(SEL_RING2_CS));
  dump_gdt_entry(&gdt[SEL_INDEX(SEL_RING2_DS)], SEL_INDEX(SEL_RING2_DS));
  dump_gdt_entry(&gdt[SEL_INDEX(SEL_RING2_SS)], SEL_INDEX(SEL_RING2_SS));
  kprintf("\n");

  /* Ring3 */
  dump_gdt_entry(&gdt[SEL_INDEX(SEL_RING3_CS)], SEL_INDEX(SEL_RING3_CS));
  dump_gdt_entry(&gdt[SEL_INDEX(SEL_RING3_DS)], SEL_INDEX(SEL_RING3_DS));
  dump_gdt_entry(&gdt[SEL_INDEX(SEL_RING3_SS)], SEL_INDEX(SEL_RING3_SS));
  kprintf("\n");
#undef SEL_INDEX

  /* Dump the exception handler's stack */
  kprintf("handler's stack: ");
  kprintf("errcode: %08x eip: %08x cs: %08x eflags: %08x\n", 
	  handler_stack_errcode, handler_stack_eip, handler_stack_cs, handler_stack_eflags);

  kprintf("interrupt handler %d speaking\n", exc);

#if 1
  /* Dump the first entries of the PT */
  p = (uint32_t*) PAGE_ALIGN((uint32_t*) get_cr3());
  kprintf("pd[0]: %08x pd[1]: %08x || ", p[0], p[1]);
  p = (uint32_t*) ((((pde_t*) p)[0].basehigh << 16) | (((pde_t*) p)[0].baselow << 12));
  kprintf("pt[0]: %08x pt[1]: %08x\n", p[0], p[1]);
#endif

}
