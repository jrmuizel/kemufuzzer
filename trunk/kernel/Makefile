CFLAGS += -Wall -m32 -O2 -nostdlib -nostdinc -nostartfiles -I./include/
LDFLAGS=-Wl,--script=kernel.ld,--build-id=none
OBJS=boot.o loader.o kprintf.o console.o main.o interrupts.o asm.o int_wrappers.o tss.o
DEST=kernel

all: $(DEST) 

$(DEST): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o:	%.c
	$(CC) $(CFLAGS) -c -o $@ $<

boot.o: boot.S
	$(CC) $(CFLAGS) -c -o $@ $<

int_wrappers.o: int_wrappers.S
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	-rm -f $(DEST) $(OBJS) floppy.img interrupts.c interrupts.h int_wrappers.S 

floppy.img: $(DEST)
	dd if=/dev/zero of=floppy.img bs=1024 count=1440
	/sbin/mkdosfs floppy.img
	mmd -i floppy.img boot
	mmd -i floppy.img boot/grub
	mcopy -i floppy.img grub_stuff/boot/grub/* ::boot/grub
	mcopy -i floppy.img kernel ::
	grub --batch --device-map=/dev/null < grub_stuff/grub.cfg

disk: floppy.img 

int_wrappers.c interrupts.c interrupts.h: gen_ints_asm.py
	# use port 69 to notify interrupts & exceptions
	python gen_ints_asm.py 69

# dependencies
loader.o: interrupts.h
