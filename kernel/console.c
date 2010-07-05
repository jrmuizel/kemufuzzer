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

#include <sys/types.h>
#include <sys/console.h>

static struct
{
  int width;
  int height;
  struct
  {
    int x;
    int y;
  }cursor;
} console;

#define _X_ (console.cursor.x)
#define _Y_ (console.cursor.y)
#define HEIGHT (console.height)
#define WIDTH (console.width)
#define ATTRIBUTE 7

void console_init(int w, int h)
{
  console.width = w;
  console.height = h;
  console.cursor.x = 0;
  console.cursor.y = 0;
  console_cls();
}

void console_cls(void)
{
  int i;
  for(i=0;i<WIDTH*HEIGHT*2;i++)
    {
      *(VIDMEM + i) = 0;
    }
}

void console_putc(char c)
{
  if (c == '\n' || c == '\r')
    {
    newline:
      _X_ = 0;
      _Y_ ++;
      if (_Y_ >= HEIGHT)
	_Y_ = 0;
      return;
    }
     
  *(VIDMEM + (_X_ + _Y_ * WIDTH) * 2) = c & 0xFF;
  *(VIDMEM + (_X_ + _Y_ * WIDTH) * 2 + 1) = ATTRIBUTE;
     
  _X_++;
  if (_X_ >= WIDTH)
    goto newline;
}

int console_print(char *s, int n)
{
  int count;
  char *p;

  count = 0;

  p = s;
  while(*p && count < n)
    {
      console_putc(*p);
      p++;
      count ++;
    }
  return 0;
}
