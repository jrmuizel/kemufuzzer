OUTPUT_FORMAT("elf32-i386")
ENTRY(_start)
virt = 0x200000; /* 2 meg */
phys = 0x200000; /* 2 meg */
SECTIONS
{   .multiboot 0x100000 : AT(0x100000)
    {
	LONG(0x1BADB002)
	LONG(0x00000003)
	LONG(-(0x1BADB002 + 0x00000003))
    }
    .loader :
    {
	loaderlow = .;
	KEEP (*boot.o(.text))
	KEEP (*loader.o(.text))
	KEEP (*boot.o(.data))
	KEEP (*loader.o(.data))
	KEEP (*boot.o(.bss))
	KEEP (*loader.o(.bss))
	KEEP (*boot.o(COMMON))
	KEEP (*loader.o(COMMON))
	loaderhigh = .;
    }
    .text virt : AT(phys)
    {   code = .;
        *(.text)
        . = ALIGN(4096); 
    }
    .data :  AT(phys + (data - code))
    {   data = .;
    	tc_ring0_base = .;
	LONG(tcring0)
	tc_ring0_len = .;
	LONG(tcring0end - tcring0)
    	tc_ring1_base = .;
	LONG(tcring1)
	tc_ring1_len = .;
	LONG(tcring1end - tcring1)
    	tc_ring2_base = .;
	LONG(tcring2)
	tc_ring2_len = .;
	LONG(tcring2end - tcring2)
     	tc_ring3_base = .;
	LONG(tcring3)
	tc_ring3_len = .;
	LONG(tcring3end - tcring3)
     	tc_ringvm_base = .;
	LONG(tcringvm)
	tc_ringvm_len = .;
	LONG(tcringvmend - tcringvm)
	stack_r0 = .;
	LONG(ring0stacktop);
	stack_ssfaultbase = .;
	LONG(ssfaultstack);
	stack_ssfault = .;
	LONG(ssfaultstacktop - ssfaultstack);
	stack_doublefaultbase = .;
	LONG(doublefaultstack);
	stack_doublefault = .;
	LONG(doublefaultstacktop - doublefaultstack);
	*(.data)
	mem_offset = .;
	LONG(virt - phys)
        . = ALIGN(4096); 
    }
    .bss :  AT(phys + (bss - code))
    {   bss = .;
        *(.bss)
        *(COMMON)
        . = ALIGN(4096); 
    }
    .ring0stack :  AT(phys + (ring0stack - code))
    {   ring0stack = .;
    	LONG(0x00000000);
        . = ALIGN(4096); 
    	ring0stacktop = .;
    } = 0x0000
    .ssfaultstack :  AT(phys + (ssfaultstack - code))
    {   ssfaultstack = .;
    	LONG(0x00000000);
        . = ALIGN(4096); 
    	ssfaultstacktop = .;
    } = 0x0000
    .doublefaultstack :  AT(phys + (doublefaultstack - code))
    {   doublefaultstack = .;
    	LONG(0x00000000);
        . = ALIGN(4096); 
    	doublefaultstacktop = .;
    } = 0x0000
    .tcring0 : AT(phys + (tcring0 - code))
    {   tcring0 = .;
    	LONG(0x41414141);
	. = ALIGN(4096);
	tcring0end = .;
    } = 0x41414141
    .tcring1 : AT(phys + (tcring1 - code))
    {   tcring1 = .;
    	LONG(0x42424242);
	. = ALIGN(4096);
	tcring1end = .;
    } = 0x42424242
    .tcring2 : AT(phys + (tcring2 - code))
    {   tcring2 = .;
    	LONG(0x43434343);
	. = ALIGN(4096);
	tcring2end = .;
    } = 0x43434343
    .tcring3 : AT(phys + (tcring3 - code))
    {   tcring3 = .;
    	LONG(0x44444444);
	. = ALIGN(4096);
	tcring3end = .;
    } = 0x44444444
    .tcringvm : AT(phys + (tcringvm - code))
    {   tcringvm = .;
    	LONG(0xF4F4F4F4);
	. = ALIGN(4096);
	tcringvmend = .;
    } = 0xF4F4F4F4
    end = .;
}
