#include <svm/svm.h>
#include <svm/svm_ops.h>
#include <ioctl.h>
#include <stddef.h>

#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

int mah_initialized = 0;

static int __init mah_init(void) {
	printk(DBG "Loaded MAH kernel module\n");

    // Detect on which platform MAH is running on.
    //if (svm_check_support()) // TODO: remove comment
        init_svm_mah_ops();

    // If we are on no supported platform, unload the module
    if (mah_initialized == 0) {
        printk(DBG "No supported platform detected!\n");
        return -1;
    }

	init_ctl_interface();
	return 0;
}

static void __exit mah_exit(void) {
	printk(DBG "Unloaded MAH kernel module\n");
	finit_ctl_interface();
}

module_init(mah_init);
module_exit(mah_exit);