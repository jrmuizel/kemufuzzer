#ifndef MMAN_H
#define MMAN_H

#define ACS_PRESENT     0x80
#define ACS_CSEG        0x18
#define ACS_DSEG        0x10
#define ACS_CONFORM     0x04
#define ACS_READ        0x02
#define ACS_WRITE       0x02
#define ACS_IDT         ACS_DSEG
#define ACS_INT_GATE    0x0E
#define ACS_INT         (ACS_PRESENT | ACS_INT_GATE)
#define ACS_TSS_GATE    0x09
#define ACS_TSS         (ACS_PRESENT | ACS_TSS_GATE)

#define ACS_CODE        (ACS_PRESENT | ACS_CSEG | ACS_READ)
#define ACS_DATA        (ACS_PRESENT | ACS_DSEG | ACS_WRITE)
#define ACS_STACK       (ACS_PRESENT | ACS_DSEG | ACS_WRITE)


typedef struct {
  uint16_t limit;
  uint32_t base;
} __attribute__ ((__packed__)) gdtr_t;

typedef struct{
  uint16_t limit_0_15;
  uint16_t base_0_15;
  uint8_t base_16_23;
  union {
    struct {
      uint8_t type:4;
      uint8_t s:1;
      uint8_t dpl:2;
      uint8_t p:1;
    };
    uint8_t access;
  };
  union {
    struct {
      uint8_t limit_16_19:4;
      uint8_t avl:1;
      uint8_t l:1;
      uint8_t d_b:1;
      uint8_t g:1;
    };
    struct {
      uint8_t asd:4;
      uint8_t attr:4;
    };
  };
  uint8_t base_24_31;
} __attribute__ ((__packed__)) seg_t;

typedef union{
  struct{
    uint8_t p:1;
    uint8_t r_w:1;
    uint8_t u_s:1;
    uint8_t pwt:1;
    uint8_t pcd:1;
    uint8_t a:1;
    uint8_t zero:1;
    uint8_t ps:1;
    uint8_t g:1;
    uint8_t avail:3;
    uint8_t baselow:4;
    uint16_t basehigh;
  } __attribute__ ((__packed__));
  uint32_t raw;
} __attribute__ ((__packed__)) pde_t;

typedef union{
  struct{
    uint8_t p:1;
    uint8_t r_w:1;
    uint8_t u_s:1;
    uint8_t pwt:1;
    uint8_t pcd:1;
    uint8_t a:1;
    uint8_t d:1;
    uint8_t pat:1;
    uint8_t g:1;
    uint8_t avail:3;
    uint8_t baselow:4;
    uint16_t basehigh;
  } __attribute__ ((__packed__));
  uint32_t raw;
} __attribute__ ((__packed__)) pte_t;

void set_gdt_entry(seg_t *, uint32_t, uint32_t, uint8_t, uint8_t);

#endif
