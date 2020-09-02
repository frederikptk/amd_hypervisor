#include <stdint.h>
#include <mah.h>
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

#define TEST_IOCTL_RET(x) if (x) return EXIT_FAILURE;

int main() {
	int				ctl_fd;
	void*				guest_page;
	user_arg_registers		regs;
	user_vcpu_exit			exit;
	
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
	
	// Get the registers and set EBX and ECX
	printf("Set registers\n");
	TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_GET_REGISTERS, &regs))
	regs.rbx = 4;
	regs.rcx = 5;
	
	
	TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_SET_REGISTERS, &regs))
	
	// Run the VCPU
	printf("Run vcpu\n");
	TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_VCPU_RUN, &exit))
	
	printf("Exit reason: 0x%lx\n", exit.exitcode);
	printf("Exit info 1: 0x%lx\n", exit.exitinfo1);
	printf("Exit info 2: 0x%lx\n", exit.exitinfo2);
	
	/*
	// Test the result
	printf("Get registers\n");
	TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_GET_REGISTERS, &regs))
	printf("Result rdx: 0x%lx\n", regs.rdx);
	
	// Destroy a guest
	printf("Destroy guest\n");
	TEST_IOCTL_RET(ioctl(ctl_fd, MAH_IOCTL_DESTROY_GUEST))
	*/
	
	close(ctl_fd);
	
	return EXIT_SUCCESS;
}
