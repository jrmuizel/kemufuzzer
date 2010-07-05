#ifndef INTERRUPT_H
#define INTERRUPT_H

#define PIC1 0x20
#define PIC2 0xA0
#define PIC1_COMMAND PIC1
#define PIC1_DATA (PIC1+1)
#define PIC2_COMMAND PIC2
#define PIC2_DATA PIC2+1
#define PIC_EOI 0x20

#define ICW1_ICW4       0x01 /* ICW4 (not) needed */
#define ICW1_SINGLE     0x02 /* Single (cascade) mode */
#define ICW1_INTERVAL4  0x04 /* Call address interval 4 (8) */
#define ICW1_LEVEL      0x08 /* Level triggered (edge) mode */
#define ICW1_INIT       0x10 /* Initialization - required! */

#define ICW4_8086       0x01 /* 8086/88 (MCS-80/85) mode */
#define ICW4_AUTO       0x02 /* Auto (normal) EOI */
#define ICW4_BUF_SLAVE  0x08 /* Buffered mode/slave */
#define ICW4_BUF_MASTER 0x0C /* Buffered mode/master */
#define ICW4_SFNM       0x10 /* Special fully nested (not) */

#ifndef INTERRUPTS
#define INTERRUPTS 64
#endif

typedef struct 
{
  uint16_t limit;
  uint32_t base;
} __attribute__ ((__packed__)) idtr_t;

typedef struct
{
  uint16_t off_0_15;
  uint16_t seg;
  uint8_t reserved:5;
  uint8_t zero:3;
  uint8_t type:5;
  uint8_t dpl:2;
  uint8_t present:1;
  uint16_t off_16_31;
} __attribute__ ((__packed__)) idte_t;

#endif
