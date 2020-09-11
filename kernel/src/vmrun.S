/*
 * This file contains the assembly code for running a VM with a given VMCB.
 */

    .text
LC0:
.globl run_vcpu_asm
run_vcpu_asm:
    // store all host general purpose registers
    pushq       %rbx
    pushq       %r12
    pushq       %r13
    pushq       %r14
    pushq       %r15
    pushq       %rbp
    pushq       %rdx
    clgi

    pushq       %rsi // argument 2: phys_addr_host_vmcb
    movq        %rsi, %rax
    vmsave      %rax

    movq        %rdi, %rax

    // load the guest general purpose registers: argument 3: saved_regs of guest
    movq       0(%rdx), %rbx 
    movq       8(%rdx), %rcx
    movq       24(%rdx), %rdi
    movq       32(%rdx), %rsi
    movq       40(%rdx), %r8
    movq       48(%rdx), %r9
    movq       56(%rdx), %r10
    movq       64(%rdx), %r11
    movq       72(%rdx), %r12
    movq       80(%rdx), %r13
    movq       88(%rdx), %r14
    movq       96(%rdx), %r15
    movq       104(%rdx), %rbp
    movq       16(%rdx), %rdx

    // the vmrun instruction takes the physical address of the VMCB as argument
    vmload 	%rax
    vmrun 	%rax
    vmsave  	%rax

    // restore the host state which has not been recovered by #VMEXIT
    popq       %rax // argument 2: phys_addr_host_vmcb
    vmload     %rax
    
    popq       %rax // argument 3: saved_regs of guest
    
    // Copy the guest registers to the VCPU struct
    movq	%rbx, 0(%rax)
    movq	%rcx, 8(%rax)
    movq	%rdx, 16(%rax)
    movq	%rdi, 24(%rax)
    movq	%rsi, 32(%rax)
    movq	%r8,  40(%rax)
    movq	%r9,  48(%rax)
    movq	%r10, 56(%rax)
    movq	%r11, 64(%rax)
    movq	%r12, 72(%rax)
    movq	%r13, 80(%rax)
    movq	%r14, 88(%rax)
    movq	%r15, 96(%rax)
    movq	%rbp, 104(%rax)

    // restore the host general purpose registers
    popq       %rbp
    popq       %r15
    popq       %r14
    popq       %r13
    popq       %r12
    popq       %rbx

    ret
