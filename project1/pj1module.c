

#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <linux/uaccess.h>          // Required for the copy to user function
#include "project1.h"
#define  DEVICE_NAME "ebbchar"    ///< The device will appear at /dev/ebbchar using this value
#define  CLASS_NAME  "ebb"        ///< The device class -- this is a character device driver
 
MODULE_LICENSE("GPL");            ///< The license type -- this affects available functionality
MODULE_AUTHOR("Richard Liu");    ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("Loadable module for debug syscall");  ///< The description -- see modinfo
MODULE_VERSION("0.1");            ///< A version number to inform users

int project1_sys_func(int pid, char *result);

int project1_sys_func(int pid, char *result)
{
    int ret;
    printk("[%s] pid:%d addr:%p \n", __FUNCTION__, pid , result);

    return ret;
}


static int __init project1_init(void){
    project1_hook = project1_sys_func;
    project1_hook_ready = 1;

    return 0;
}
static void __exit project1_exit(void){
    project1_hook_ready = 0;
    project1_hook = NULL;

}

module_init(project1_init);
module_exit(project1_exit);
