#ifndef _FPU_H
#define _FPU_H

#include <stdint.h>

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

#endif /* _FPU_H */
