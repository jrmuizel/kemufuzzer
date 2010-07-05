objs = decode.o input.o itab.o syn-att.o syn.o syn-intel.o udis86.o

all: libudis86.a

libudis86.a: $(objs)
	ar -r $@ $(objs)

%.o: %.c
	gcc -c $<

clean:
	rm -f *.o

distclean:
	rm -f libudis86.a

.PHONY: all clean distclean
