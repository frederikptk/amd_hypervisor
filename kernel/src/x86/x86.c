#include <x86/x86.h>

void (*x86_io_port_handlers[MAX_NUM_IO_PORTS])(int, uint32_t, uint16_t, uint32_t*); // TODO: change void* to handler function type

int x86_handle_io(int in, uint32_t op_size, uint16_t port, uint32_t* eax) {

    // Check if we have registered a IO port handler first
    if (x86_io_port_handlers[port] == NULL) {
        printk(DBG "IO port handler for 0x%x not registered!\n", port);
        return -EINVAL;
    } else {
        x86_io_port_handlers[port](in, op_size, port, eax);
    }
    return 0;
}