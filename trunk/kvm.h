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

#ifndef KVM_H
#define KVM_H

#include <stdint.h>
#include <x86.h>

#define EXPECTED_KVM_API_VERSION 12
#define MAXCPUS 4

#include <linux/kvm.h>

#if KVM_API_VERSION != EXPECTED_KVM_API_VERSION
#error "Wrong API version"
#endif

#include "x86_cpustate.h"

class KVM;

class VCPU {
private:
  int slot;
  int cpu_fd;
  int exception;
  KVM *kvm;
  struct kvm_run *run;

  friend class KVM;

public:
  VCPU(KVM *, int);
  ~VCPU();

  void SetRegs(struct kvm_regs *);
  void GetRegs(struct kvm_regs *);
  void SetSregs(struct kvm_sregs *);
  void GetSregs(struct kvm_sregs *);
  void SetFPU(struct kvm_fpu *);
  void GetFPU(struct kvm_fpu *);
  void SetMSRs(struct kvm_msr_entry *msrs, int n);
  void GetMSRs(struct kvm_msr_entry *msrs, int *n);
  struct kvm_run *Run();
  int Bits();
  int GetMem(void *, unsigned int, uint8_t *);
  int SetMem(void *, unsigned int, uint8_t *);
  void Disasm(void *, FILE *);
  void DumpMem(void *, int, FILE *, bool = false);
  void SetException(int);
};

class KVM {
private:
  void *vm_mem;
  unsigned int vm_mem_size;
  VCPU *vcpus[MAXCPUS];
  int cpusno;
  type_t state_type;
  uint8_t ioports[2];

  friend class VCPU;

  void Init(int, unsigned int);

protected:
  int fd; 
  int vm_fd;

public:
  KVM(int, unsigned int);
  KVM(const char *);
  ~KVM();

  VCPU *Cpu(int = 0);
  void *Mem();
  void Load(const char *);
  void Save(const char *);
  void Print(FILE *);

  void SetIoPort(int, uint8_t);
  uint8_t GetIoPort(int);
  void SetStateType(type_t);
  type_t GetStateType();
};


#endif
