
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched.h>
#include<linux/syscalls.h>
#include "project1.h"

int (*project1_hook)(int pid, char *result) = NULL;
int project1_hook_ready = 0 ; 


asmlinkage long sys_linux_survey_TT(int pid, char *buf) {
	printk("[%s] pid: %d : buf:%p \n", __FUNCTION__, pid, buf);
	if(1 == project1_hook_ready){
		project1_hook(pid, buf);
	}
return 0;
}
asmlinkage long sys_listProcessInfo(void) {
    struct task_struct *proces;
 
    for_each_process(proces) {
 
    printk(
      "Process: %s\n \
       PID_Number: %ld\n \
       Process State: %ld\n \
       Priority: %ld\n \
       RT_Priority: %ld\n \
       Static Priority: %ld\n \
       Normal Priority: %ld\n", \
       proces->comm, \
       (long)task_pid_nr(proces), \
       (long)proces->state, \
       (long)proces->prio, \
       (long)proces->rt_priority, \
       (long)proces->static_prio, \
       (long)proces->normal_prio \
    );
  
  
   if(proces->parent) 
      printk(
        "Parent process: %s, \
         PID_Number: %ld", \ 
         proces->parent->comm, \
         (long)task_pid_nr(proces->parent) \
      );
  
   printk("\n\n");
  
  }
  
  return 0;
}

EXPORT_SYMBOL(project1_hook);
EXPORT_SYMBOL(project1_hook_ready);
