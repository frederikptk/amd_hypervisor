# MAH: Mini AMD Hypervisor

A small AMD SVM (AMD Secure Virtual Machine) Hypervisor for Linux systems. It provides a clear interface for creating guests, setting registers and donating memory to the guest. MAH is intended to be a minimal hypervisor without capabilities such as complex device emulation.
It is primarily **supposed to show how AMD SVM is used and how a hypervisor, such as KVM, works under the hood**. Therefore, booting of complex systems, such as Linux or Windows, is not supported. In order to be still a comprehensive und easily understandable, MAH is intended to have a small codebase.

I am happy about any suggestions in order to improve this project! And if you find a bug, please report it. There still might be a few in here, since the project is still in development.

## Features
The features MAH provides are:
 - Donating userspace memory to the guest
 - Setting registers
 - Set when a VM should be intercepted
 - Getting the VM interception information

## Example API usage
A small example for using MAH:
```c
#define TEST_IOCTL_RET(x) if (x) return EXIT_FAILURE;

...

TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_CREATE_GUEST))
	
// Create a VCPU for the guest
TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_CREATE_VCPU))
	
// Donate the page to the guest
guest_page = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, ctl_fd, 0);
memset(guest_page, 0xf4, getpagesize());
	
// Get the registers and set EBX and ECX
TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_GET_REGISTERS, &regs))
regs.rbx = 4;
regs.rcx = 5;
TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_SET_REGISTERS, &regs))
	
// Run the VCPU
TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_VCPU_RUN, &exit))
	
printf("Exit reason: 0x%lx\n", exit.exitcode);
printf("Exit info 1: 0x%lx\n", exit.exitinfo1);
printf("Exit info 2: 0x%lx\n", exit.exitinfo2);

...

```
The above example creates a guest and executes a `HLT` instruction, which exits the guest and will be intercepted by the hypervisor.
A more complete example can be found in the `user` folder. Userland code should include `mah_defs.h` in the `include` folder. This header file is shared by both user- and kernelspace.
Currently, the following self-explaining IOCTLs are provided:
```c
MAH_IOCTL_CREATE_GUEST
MAH_IOCTL_CREATE_VCPU
MAH_IOCTL_SET_REGISTERS
MAH_IOCTL_GET_REGISTERS
MAH_IOCTL_VCPU_RUN
MAH_IOCTL_DESTROY_GUEST
MAH_SET_INTERCEPT_REASONS
```

## Building: Ubuntu
Install the dependencies via:
```
sudo apt install gcc make linux-headers-$(uname -r)
```
In order to build MAH, clone the repository and execute:
```
./build.sh
```

## TODO
 - Support for multiple VCPUs and vAPIC support
 - Log of all accessed pages
 - Check if number of VCPUs is within number of phyiscal cores
 - IO permissions
 - All exitcodes and instruction intercept definitions
 - Event injection
 - CPU reset: enter realmode instead of protected mode, move code to userland
 - Add automated tests
