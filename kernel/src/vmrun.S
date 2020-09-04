/*
 * This file contains the assembly code for running a VM with a given VMCB.
 */

    .text
LC0:
.globl run_vcpu_asm
run_vcpu_asm:
    // store all host general purpose registers
    pushq       %rax
    pushq       %rbx
    pushq       %rcx
    pushq       %rdx
    pushq       %rdi
    pushq       %rsi
    pushq       %r8
    pushq       %r9
    pushq       %r10
    pushq       %r11
    pushq       %r12
    pushq       %r13
    pushq       %r14
    pushq       %r15
    pushq       %rbp
    pushq       %rcx
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
    
    popq       %rax // argument 4: current executed VCPU
    
    /*
    // Save all general-purpose registers on the stack.
    // We need to store the registers manually since they are not covered by the VMCB.
    pushq      %rbx
    pushq      %rcx
    pushq      %rdx
    pushq      %rdi
    pushq      %rsi
    pushq      %r8
    pushq      %r9
    pushq      %r10
    pushq      %r11
    pushq      %r12
    pushq      %r13
    pushq      %r14
    pushq      %r15
    pushq      %rbp

    movq       %rsp, %rdi
    addq       $0x68, %rdi
    
    movq       %rax, %rsi

    call       handle_vmexit

    addq       $0x70, %rsp*/
    
    // Copy the guest registers to the VCPU struct
    movq	40(%rax), %rax
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
    popq       %r11
    popq       %r10
    popq       %r9
    popq       %r8
    popq       %rsi
    popq       %rdi
    popq       %rdx
    popq       %rcx
    popq       %rbx
    popq       %rax

    ret
