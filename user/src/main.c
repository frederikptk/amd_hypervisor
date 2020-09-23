#include <stdint.h>
#include <mah_defs.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

/*
 Contains the following code:
	add eax, 0x4
	mov ebx, 0x3
	mov ecx, ebx
	sub ecx, 0x1
	hlt
*/

char* example_code = "\x83\xc0\x04\xbb\x03\x00\x00\x00\x89\xd9\x83\xe9\x01\xf4";

#define TEST_IOCTL_RET(x) if (x) return EXIT_FAILURE;

int main() {
	int				ctl_fd;
	void*				guest_page;
	user_arg_registers		regs;
	user_vcpu_run			run_data;
	
	printf("Running example...\n");
	
	ctl_fd = open(MAH_PROC_PATH, O_RDWR);
	if (ctl_fd == -1) {
		printf("Could not open " MAH_PROC_PATH "\n");
		return EXIT_FAILURE;
	}
	
	// Create a guest
	printf("Create guest\n");
	TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_CREATE_GUEST))
	
	// Create a VCPU for the guest
	printf("Create vcpu\n");
	TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_CREATE_VCPU))
	
	// Donate the page to the guest
	printf("Donate memory\n");
	guest_page = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, ctl_fd, 0);
	if (guest_page == NULL) {
		printf("Could not allocate guest page\n");
		return EXIT_FAILURE;
	}
	memset(guest_page, 0xf4, getpagesize());
	memcpy(guest_page, example_code, 14);
	
	// Get the registers and set EBX and ECX
	printf("Set registers\n");
	TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_GET_REGISTERS, &regs))
	
	TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_SET_REGISTERS, &regs))
	
	// Run the VCPU
	printf("Run vcpu\n");
	TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_VCPU_RUN, &run_data))
	
	// Test the result
	printf("Get registers\n");
	TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_GET_REGISTERS, &regs))
	printf("Result rip: 0x%lx\n\n", regs.rip);
	
	printf("Result rax: 0x%lx\n", regs.rax);
	printf("Result rbx: 0x%lx\n", regs.rbx);
	printf("Result rcx: 0x%lx\n", regs.rcx);
	printf("Result rdx: 0x%lx\n", regs.rdx);
	printf("Result rdi: 0x%lx\n", regs.rdi);
	printf("Result rsi: 0x%lx\n", regs.rsi);
	printf("Result r9:  0x%lx\n", regs.r8);
	printf("Result r9:  0x%lx\n", regs.r9);
	printf("Result r10: 0x%lx\n", regs.r10);
	printf("Result r11: 0x%lx\n", regs.r11);
	printf("Result r12: 0x%lx\n", regs.r12);
	printf("Result r13: 0x%lx\n", regs.r13);
	printf("Result r14: 0x%lx\n", regs.r14);
	printf("Result r15: 0x%lx\n", regs.r15);
	
	// Destroy a guest
	printf("Destroy guest\n");
	TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_DESTROY_GUEST))
	
	close(ctl_fd);
	
	return EXIT_SUCCESS;
}
