#include <svm/svm.h>
#include <svm/svm_ops.h>
#include <ioctl.h>
#include <stddef.h>

#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

int hyperkraken_initialized = 0;

static int __init hyperkraken_init(void) {
	printk(DBG "Loaded HYPERKRAKEN kernel module\n");

    // Detect on which platform HYPERKRAKEN is running on.
    //if (svm_check_support()) // TODO: remove comment
        init_svm_hyperkraken_ops();

    // If we are on no supported platform, unload the module
    if (hyperkraken_initialized == 0) {
        printk(DBG "No supported platform detected!\n");
        return -1;
    }

	init_ctl_interface();
	return 0;
}

static void __exit hyperkraken_exit(void) {
	printk(DBG "Unloaded HYPERKRAKEN kernel module\n");
	finit_ctl_interface();
}

module_init(hyperkraken_init);
module_exit(hyperkraken_exit);