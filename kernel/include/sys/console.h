#ifndef CONSOLE_H
#define CONSOLE_H

#define VIDMEM ((char *)0xb8000)

void console_cls(void);

void console_init(int, int);

void console_putc(char);

int console_print(char *, int);

#endif
