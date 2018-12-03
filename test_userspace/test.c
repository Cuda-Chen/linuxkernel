
#include <stdio.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>

// 64bit 323 / 324 (helloworld)
// 32bit 359 / 360

int main()
{  
#if 0
    long int ret_status = syscall(359); // 323 is the syscall number
    printf("Invoking 'listProcessInfo' system call");
         
         
    if(ret_status == 0) 
         printf("System call 'listProcessInfo' executed correctly. Use dmesg to check processInfo\n");
    
    else 
         printf("System call 'listProcessInfo' did not execute as expected\n");
#endif 
          
    long int ret_status = syscall(360, 111, 0xFFFF0000); // 323 is the syscall number
     return 0;
}
