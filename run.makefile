TESTCASE_COMPILE       = tc_template
KEMUFUZZER             = kemufuzzer
KERNEL                 = kernels/kernel
FLOPPY                 = kernels/floppy.img
KEMUFUZZER_OPTS        = kerneldir:kernels kernel:$(KERNEL) floppy:$(FLOPPY)

TESTCASES_TEMPLATE     = $(wildcard test-cases/*.template)
TESTCASES_TESTCASE     = $(subst .template,.0000.testcase,$(TESTCASES_TEMPLATE))

QEMU_POST_STATES       = $(addprefix qemu/,$(subst .testcase,.post,$(notdir $(wildcard test-cases/*.testcase))))
BOCHS_POST_STATES      = $(addprefix bochs/,$(subst .testcase,.post,$(notdir $(wildcard test-cases/*.testcase))))
VBOX_POST_STATES       = $(addprefix vbox/,$(subst .testcase,.post,$(notdir $(wildcard test-cases/*.testcase))))
VMWARE_POST_STATES     = $(addprefix vmware/,$(subst .testcase,.post,$(notdir $(wildcard test-cases/*.testcase))))

KVM_QEMU_POST_STATES   = $(addprefix kvm/qemu/,$(subst .testcase,.post,$(notdir $(wildcard test-cases/*.testcase))))
KVM_BOCHS_POST_STATES  = $(addprefix kvm/bochs/,$(subst .testcase,.post,$(notdir $(wildcard test-cases/*.testcase))))
KVM_VBOX_POST_STATES   = $(addprefix kvm/vbox/,$(subst .testcase,.post,$(notdir $(wildcard test-cases/*.testcase))))
KVM_VMWARE_POST_STATES = $(addprefix kvm/vmware/,$(subst .testcase,.post,$(notdir $(wildcard test-cases/*.testcase))))
KVM_QEMU_PRE_STATES    = $(addprefix kvm/,$(subst .pre,.post,$(wildcard qemu/*.pre)))
KVM_BOCHS_PRE_STATES   = $(addprefix kvm/,$(subst .pre,.post,$(wildcard bochs/*.pre)))
KVM_VBOX_PRE_STATES    = $(addprefix kvm/,$(subst .pre,.post,$(wildcard vbox/*.pre)))
KVM_VMWARE_PRE_STATES  = $(addprefix kvm/,$(subst .pre,.post,$(wildcard vmware/*.pre)))

LOCK       = true
UNLOCK     = true

# KVM_RECURSE = 0

# This is necessary to prevent make to consider some .post files as
# intermediate (and to delete them at the end of the build)
.SECONDARY: 

# Compile test-cases (this is a dirty hack because I don't know how to ignore
# the numeric part of the filename)
%.0000.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0001.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0002.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0003.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0004.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0005.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0006.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0007.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0008.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0009.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0010.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0011.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0012.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0013.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0014.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0015.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0016.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0017.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0018.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0019.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0020.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0021.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0022.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0023.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0024.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0025.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0026.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0027.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0028.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0029.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0030.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0031.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)
%.0032.testcase: %.template
	@$(LOCK) $(subst .testcase,.lock,$<)
	@$(TESTCASE_COMPILE) $<
	@$(UNLOCK) $(subst .testcase,.lock,$<)

test-cases: $(TESTCASES_TESTCASE)

# Qemu
qemu/%.post: $(KERNEL) $(FLOPPY) test-cases/%.testcase
	@echo QEMU: $(filter %.testcase,$^) $@
	@$(LOCK) $(subst .post,.lock,$@)
	@$(KEMUFUZZER) $(KEMUFUZZER_OPTS) emu:QEMU testcase:$(filter %.testcase,$^) outdir:qemu > $(subst .post,.log,$@) 2>&1
	@$(UNLOCK) $(subst .post,.lock,$@)

qemu: test-cases $(QEMU_POST_STATES)

# Bochs
bochs/%.post: $(KERNEL) $(FLOPPY) test-cases/%.testcase
	@echo BOCHS: $(filter %.testcase,$^) $@
	@$(LOCK) $(subst .post,.lock,$@)
	@$(KEMUFUZZER) $(KEMUFUZZER_OPTS) emu:BOCHS testcase:$(filter %.testcase,$^) outdir:bochs > $(subst .post,.log,$@) 2>&1
	@$(UNLOCK) $(subst .post,.lock,$@)

bochs: test-cases $(BOCHS_POST_STATES)

# VBox
vbox/%.post: $(KERNEL) $(FLOPPY) test-cases/%.testcase
	@echo VBOX: $(filter test-cases/%.testcase,$^) $@
	@$(LOCK) $(subst .post,.lock,$@)
	@$(KEMUFUZZER) $(KEMUFUZZER_OPTS) emu:VBOX testcase:$(filter test-cases/%.testcase,$^) outdir:vbox > $(subst .post,.log,$@) 2>&1
	@$(UNLOCK) $(subst .post,.lock,$@)

vbox: test-cases $(VBOX_POST_STATES)

# VMware
vmware/%.post: $(KERNEL) $(FLOPPY) test-cases/%.testcase
	@echo VMWARE: $(filter %.testcase,$^) $@
	@$(LOCK) $(subst .post,.lock,$@)
	@$(KEMUFUZZER) $(KEMUFUZZER_OPTS) emu:VMWARE testcase:$(filter %.testcase,$^) outdir:vmware > $(subst .post,.log,$@) 2>&1
	@$(UNLOCK) $(subst .post,.lock,$@)

vmware: test-cases $(VMWARE_POST_STATES)

# KVM
ifdef KVM_RECURSE

kvm/%.post: %.post
	@echo KVM: $< $@;
	@$(LOCK) $(subst .post,.lock,$@)
	@$(KEMUFUZZER) $(KEMUFUZZER_OPTS) emu:KVM pre:$(subst .post,.pre,$<) post:$@ > $(subst .post,.log,$@) 2>&1
	@$(UNLOCK) $(subst .post,.lock,$@)
kvm-qemu:   test-cases $(KVM_QEMU_POST_STATES)
kvm-bochs:  test-cases $(KVM_BOCHS_POST_STATES)
kvm-vbox:   test-cases $(KVM_VBOX_POST_STATES)
kvm-vmware: test-cases $(KVM_VMWARE_POST_STATES)
kvm:        kvm-qemu kvm-bochs kvm-vbox kvm-vmware

else # !KVM_RECURSE

kvm/%.post: %.pre
	@echo KVM: $< $@;
	@$(LOCK) $(subst .post,.lock,$@)
	@$(KEMUFUZZER) $(KEMUFUZZER_OPTS) emu:KVM pre:$< post:$@ > $(subst .post,.log,$@) 2>&1
	@$(UNLOCK) $(subst .post,.lock,$@)

kvm-qemu:   test-cases $(KVM_QEMU_PRE_STATES)
kvm-bochs:  test-cases $(KVM_BOCHS_PRE_STATES)
kvm-vbox:   test-cases $(KVM_VBOX_PRE_STATES)
kvm-vmware: test-cases $(KVM_VMWARE_PRE_STATES)
kvm:        kvm-qemu kvm-bochs kvm-vbox kvm-vmware

endif # !KVM_RECURSE

diff-bochs:
	@for p in kvm/bochs/*.post; \
	do \
		t=$$(basename $$p .post); \
		difftime=0; \
		if [ -f diffs/bochs/$$t.diff ]; \
		then \
			difftime=$$(stat -c "%Y" diffs/bochs/$$t.diff); \
		fi; \
		if [ $$difftime -lt $$(stat -c "%Y" bochs/$$t.post) -o \
			$$difftime -lt $$(stat -c "%Y" kvm/bochs/$$t.post) ]; \
		then \
			tmp=$$(mktemp); \
			echo "DIFF: " bochs/$$t.post kvm/bochs/$$t.post; \
			x86_cpustate_diff bochs/$$t.post kvm/bochs/$$t.post update_guest:1 fix_bugs:1 2>&1 > $$tmp; \
			if [ $$? -eq 0 ]; \
			then \
				echo -n "" > diffs/bochs/$$t.diff; \
				rm $$tmp; \
			else \
				mv $$tmp diffs/bochs/$$t.diff; \
			fi; \
		fi; \
	done

diff-qemu:
	@for p in kvm/qemu/*.post; \
	do \
		t=$$(basename $$p .post); \
		difftime=0; \
		if [ -f diffs/qemu/$$t.diff ]; \
		then \
			difftime=$$(stat -c "%Y" diffs/qemu/$$t.diff); \
		fi; \
		if [ $$difftime -lt $$(stat -c "%Y" qemu/$$t.post) -o \
			$$difftime -lt $$(stat -c "%Y" kvm/qemu/$$t.post) ]; \
		then \
			tmp=$$(mktemp); \
			echo "DIFF: " qemu/$$t.post kvm/qemu/$$t.post; \
			x86_cpustate_diff qemu/$$t.post kvm/qemu/$$t.post update_guest:1 fix_bugs:1 2>&1 > $$tmp; \
			if [ $$? -eq 0 ]; \
			then \
				echo -n "" > diffs/qemu/$$t.diff; \
				rm $$tmp; \
			else \
				mv $$tmp diffs/qemu/$$t.diff; \
			fi; \
		fi; \
	done

diff-vbox:
	@for p in kvm/vbox/*.post; \
	do \
		t=$$(basename $$p .post); \
		difftime=0; \
		if [ -f diffs/vbox/$$t.diff ]; \
		then \
			difftime=$$(stat -c "%Y" diffs/vbox/$$t.diff); \
		fi; \
		if [ $$difftime -lt $$(stat -c "%Y" vbox/$$t.post) -o \
			$$difftime -lt $$(stat -c "%Y" kvm/vbox/$$t.post) ]; \
		then \
			tmp=$$(mktemp); \
			echo "DIFF: " vbox/$$t.post kvm/vbox/$$t.post; \
			x86_cpustate_diff vbox/$$t.post kvm/vbox/$$t.post update_guest:1 fix_bugs:1 2>&1 > $$tmp; \
			if [ $$? -eq 0 ]; \
			then \
				echo -n "" > diffs/vbox/$$t.diff; \
				rm $$tmp; \
			else \
				mv $$tmp diffs/vbox/$$t.diff; \
			fi; \
		fi; \
	done

diff-vmware:
	@for p in kvm/vmware/*.post; \
	do \
		t=$$(basename $$p .post); \
		difftime=0; \
		if [ -f diffs/vmware/$$t.diff ]; \
		then \
			difftime=$$(stat -c "%Y" diffs/vmware/$$t.diff); \
		fi; \
		if [ $$difftime -lt $$(stat -c "%Y" vmware/$$t.post) -o \
			$$difftime -lt $$(stat -c "%Y" kvm/vmware/$$t.post) ]; \
		then \
			tmp=$$(mktemp); \
			echo "DIFF: " vmware/$$t.post kvm/vmware/$$t.post; \
			x86_cpustate_diff vmware/$$t.post kvm/vmware/$$t.post update_guest:1 fix_bugs:1 2>&1 > $$tmp; \
			if [ $$? -eq 0 ]; \
			then \
				echo -n "" > diffs/vmware/$$t.diff; \
				rm $$tmp; \
			else \
				mv $$tmp diffs/vmware/$$t.diff; \
			fi; \
		fi; \
	done

diff: diff-bochs diff-qemu diff-vbox diff-vmware

# Kernel
kernel: $(KERNEL)
	$(MAKE) -s -C $(dir $(KERNEL)) disk

# Cleanup
clean-test-cases:
	@rm -f test-cases/*.testcase

clean-qemu:
	@rm -f qemu/*.pre qemu/*.post qemu/*.log

clean-bochs:
	@rm -f bochs/*.pre bochs/*.post bochs/*.log

clean-vbox:
	@rm -f vbox/*.pre vbox/*.post vbox/*.log

clean-vmware:
	@rm -f vmware/*.pre vmware/*.post vmware/*.log

clean-kvm-qemu:
	@rm -f kvm/qemu/*.post kvm/qemu/*.log

clean-kvm-bochs:
	@rm -f kvm/bochs/*.post  kvm/bochs/*.log

clean-kvm-vbox:
	@rm -f kvm/vbox/*.post  kvm/vbox/*.log

clean-kvm-vmware:
	@rm -f kvm/vmware/*.post  kvm/vmware/*.log

clean-kvm: clean-kvm-bochs clean-kvm-qemu clean-kvm-vbox clean-kvm-vmware

.PHONY: kvm bochs qemu vmware vbox diff test-cases kvm-qemu kvm-bochs kvm-vbox kvm-vmware
