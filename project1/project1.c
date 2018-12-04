
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched.h>
#include<linux/syscalls.h>
#include "project1.h"

int (*project1_hook)(int pid, char *result) = NULL;
int project1_hook_ready = 0 ; 


asmlinkage long sys_linux_survey_TT(int pid, char *buf) {
	printk("[%s] pid: %d : buf:%p \n", __FUNCTION__, pid, buf);
	//if(1 == project1_hook_ready){
	//	project1_hook(pid, buf);
	//}

  printk("hi");
  struct task_struct *task;
  struct mm_struct *mm;
  void *cr3_virt;
  unsigned long cr3_phys;

  task = pid_task(find_vpid(pid), PIDTYPE_PID);

  if (task == NULL)
    return 0; // pid has no task_struct

  mm = task->mm;

  // mm can be NULL in some rare cases (e.g. kthreads)
  // when this happens, we should check active_mm
  if (mm == NULL) {
    mm = task->active_mm;
  }

  if (mm == NULL)
    return 0; // this shouldn't happen, but just in case

  struct vm_area_struct *vma = mm->mmap;
  while (vma != NULL){
      printk("PID: %d virtual: %08lx-%08lx\n", pid, vma->vm_start, vma->vm_end);
      printk("PID: %d physical: %08lx-%08lx\n", pid, virt_to_phys(vma->vm_start), virt_to_phys(vma->vm_end));
    if ((virt_to_phys(vma->vm_start) != NULL) && (virt_to_phys(vma->vm_end) != NULL)) {
      printk("virtual: %08lx-%08lx has corresponding physical\n", vma->vm_start, vma->vm_end);
    } 
    vma = vma->vm_next;
  }

	if(1 == project1_hook_ready){
		project1_hook(pid, buf);
	}

return 0;
}

asmlinkage long sys_linux_survey_VV(char *buf) {
	printk("VV hi\n");
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *taskpid;

	//taskpid = find_get_pid();
	taskpid = task_pid_nr(current);
	task = pid_task(taskpid, PIDTYPE_PID );
	if(task == NULL) {
		printk("cannot find task: pid: %d \n", curpid);
		return 0;
	}

  mm = task->mm;

  // mm can be NULL in some rare cases (e.g. kthreads)
  // when this happens, we should check active_mm
  if (mm == NULL) {
    mm = task->active_mm;
  }

  if (mm == NULL)
    return 0; // this shouldn't happen, but just in case

  struct vm_area_struct *vma = mm->mmap;
  while (vma != NULL){
      printk("PID: %d virtual: %08lx-%08lx\n", taskpid, vma->vm_start, vma->vm_end);
      printk("PID: %d physical: %08lx-%08lx\n", taskpid, virt_to_phys(vma->vm_start), virt_to_phys(vma->vm_end));
    if ((virt_to_phys(vma->vm_start) != NULL) && (virt_to_phys(vma->vm_end) != NULL)) {
      printk("virtual: %08lx-%08lx has corresponding physical\n", vma->vm_start, vma->vm_end);
    } 
    vma = vma->vm_next;
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
