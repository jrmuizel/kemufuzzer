KEmuFuzzer is protocol-specific fuzzer for system virtual machines. KEmuFuzzer generates floppy images to boot a virtual machine and to execute a specific test-case. The same test-case is executed also in an oracle, based on hardware-assisted virtualization. The states obtained are compared to detect defects in the virtual machine. Test-cases are generated using a special compiler that applies certain mutations before compiling.

![http://kemufuzzer.googlecode.com/svn/wiki/kemufuzzer.png](http://kemufuzzer.googlecode.com/svn/wiki/kemufuzzer.png)

KEmuFuzzer currently supports:

  * [BOCHS](http://bochs.sourceforge.net/)
  * [QEMU](http://www.qemu.org/)
  * [VMware](http://www.vmware.com/)
  * [VirtualBox](http://www.virtualbox.org/)

The release include:

  * KEmuFuzzer source code (including compiler and kernel)
  * Patches for:
    * BOCHS 2.4.1
    * BOCHS 2.4.5
    * QEMU 0.11.0
    * QEMU 0.12.4
    * QEMU 0.13.5
    * VirtualBox OSE 3.0.8 (Ubuntu)
  * Gdb backend to interact with VMware's builtin debugger
  * Sample test-cases

We are not releasing the oracle. Use vanilla KVM instead (we recommend the latest development release and a CPU with EPT support).