    .text
LC0:
.globl vmx_vmptrst
vmx_vmptrst:
    vmptrst rdi
    ret

.globl vmx_vmptrld
vmx_vmptrld:
    vmptrld rdi
    ret

.globl vmx_vmclear
vmx_vmclear:
    vmclear rdi
    ret

.globl vmx_vmresume
vmx_vmresume:
    vmresume
    ret

.gobl vmx_vmlaunch
vmx_vmlaunch:
    vmlaunch
    ret

.globl vmx_vmxon
vmx_vmxon:
    ret

.globl vmx_vmread
vmx_vmread:
    vmread rax, rdi
    ret

.globl vmx_vmwrite
vmx_vmwrite:
    vmwrite rdi, rsi
    ret