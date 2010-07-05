#ifndef ASM_H
#define ASM_H

#include <stdint.h>
#include <sys/mman.h>
#include <sys/interrupt.h>

void set_cs(uint16_t);
void set_ds(uint16_t);
void set_ss(uint16_t);
void set_fs(uint16_t);
void set_gs(uint16_t);
void set_es(uint16_t);

uint16_t get_cs(void);
uint16_t get_ds(void);
uint16_t get_ss(void);
uint16_t get_fs(void);
uint16_t get_gs(void);
uint16_t get_es(void);

uint32_t get_cr0(void);
uint32_t get_cr2(void);
uint32_t get_cr3(void);
uint32_t get_cr4(void);

void set_cr0(uint32_t);
void set_cr2(uint32_t);
void set_cr3(uint32_t);
void set_cr4(uint32_t);

void set_gdtr(gdtr_t*);
void get_gdtr(gdtr_t*);
void set_tr(uint16_t);
void set_ldtr(uint16_t);

void outport(uint8_t, uint8_t);
uint8_t inport(uint8_t);

void set_idtr(idtr_t*);

void enable_interrupts(void);

uint32_t get_eflags(void);
void set_eflags(uint32_t);

void wrmsr(uint32_t, uint32_t, uint32_t);

#endif
