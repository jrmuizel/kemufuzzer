We just extended KEmuFuzzer to support the testing of VM86 mode.

# CVE-2009-2267 #

Last year Tavis Ormandy and Julien Tinnes found a nasty bug in VMware that allows a local attacker to escalate privileges. The bug manifests when a page fault occurs in VM86 mode. The VMM always saves the exception code in the stack with the U/S (user/supervisor) bit cleared.

Now that KEmuFuzzer supports testing the CPU of the VMM in VM86 mode we can try to reproduce the VMware bug and, hopefully, find new ones.

# Reproducing the bug with KEmuFuzzer #

We wrote a very simple test-case to reproduce the scenario described by Tavis and Julien.
A brief demo follows.

  * Run the test case in VMware and got in output the CPU states before and after the execution of the testcase:

```
$ ./kemufuzzer emu:VMWARE kerneldir:$./kernel kernel:./kernel/kernel floppy:./kernel/floppy.img testcase:../test-cases/vm_CVE-2009-2267.0000.testcase outdir:./states/vmware/
...
...
[*] Flushing state '/tmp/kemufuzzer-pre-t_7OVZ' -> './states/vmware/vm_CVE-2009-2267.0000.pre'
[*] Flushing state '/tmp/kemufuzzer-post-kpDlBH' -> './states/vmware/vm_CVE-2009-2267.0000.post'
```

  * Run the same test-case in the KVM-based oracle (starting from the same initial state):

```
$ ./kemufuzzer emu:KVM kerneldir:$./kernel kernel:./kernel/kernel floppy:./kernel/floppy.img testcase:../test-cases/vm_CVE-2009-2267.0000.testcase pre:./states/vmware/vm_CVE-2009-2267.0000.pre post:./states/kvm/vmware/vm_CVE-2009-2267.0000.post
...
...
[*] Flushing state '/tmp/kemufuzzer-post-zE813H' -> './states/kvm/vm_CVE-2009-2267.0000.post'
```

  * Compare the states of the end of the execution:

```
$ ./x86_cpustate_diff ./states/vmware/vm_CVE-2009-2267.0000.post ./states/kvm/vm_CVE-2009-2267.0000.post
                                                      Oracle          VMware
--------------------------------------------------------------------------------
cpu[0].exception_state.error_code                       6                2
```