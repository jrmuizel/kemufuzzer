#ifndef STDIO_H
#define STDIO_H

#define EOF (-1)

#ifndef _SIZE_T
#define _SIZE_T
typedef unsigned int size_t;
#endif

#include <stdarg.h>

int
kprintf(char const *, ...);

int
kvprintf(const char *, va_list);

#endif
