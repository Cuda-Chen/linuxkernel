
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched.h>
#include<linux/syscalls.h>
//#include <unistd.h>
//#include <sys/syscall.h>
//#include <sys/types.h>
//#include <pthread.h>
#include "project1.h"

int (*project1_hook)(int pid, char *result) = NULL;
int project1_hook_ready = 0 ; 

#define PTRS_PER_PGD	4
#define PTRS_PER_PUD	1
#define PTRS_PER_PMD	512
#define PTRS_PER_PTE	512
#define PGDIR_SHIFT	30
#define PTRS_PER_PGD	4
#define PMD_SHIFT	21
#define PTRS_PER_PMD	512
#define PTRS_PER_PTE	512
#define PAGE_SHIFT	12
#define PAGE_MASK       (~(PAGE_SIZE-1))
#define __va(x)		((void *)((unsigned long)(x)+PAGE_OFFSET))
#define _pgd_offset(mm, addr)           (mm->pgd + (((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1)))
#define _pud_offset(pgd, addr)          (pgd) //skip pud on x86 with PAE
#define _pmd_offset(pud, addr)          ((pmd_t *)(unsigned long)__va((pud->pgd.pgd) & PTE_PFN_MASK) + ((addr >> PMD_SHIFT) & (PTRS_PER_PMD - 1)))
#define _pte_offset_kernel(pmd, addr)   ((pte_t *)(unsigned long)__va(pmd->pmd & PTE_PFN_MASK) + ((addr >> PAGE_SHIFT) & (PTRS_PER_PTE - 1)))
unsigned long _virt_to_phys(struct mm_struct *mm, unsigned long virt_addr);

unsigned long _virt_to_phys(struct mm_struct *mm, unsigned long virt_addr){
  pgd_t *pgd;
  pud_t *pud;
  pmd_t *pmd;
  pte_t *pte;
  unsigned long paddr = 0;
  unsigned long page_addr = 0;
  unsigned long page_offset = 0;
  pgd = _pgd_offset(mm, virt_addr);
  printk("pgd: %08lx\n", *pgd);
  if (pgd_none(*pgd) || pgd_bad(*pgd))
    return 0;
  pud = _pud_offset(pgd, virt_addr);
  //printk("pud: %08lx\n", *pud);
  if (pud_none(*pud) || pud_bad(*pud))
    return 0;
  pmd = _pmd_offset(pud, virt_addr);
  //printk("pmd: %08lx\n", *pmd);
  if (pmd_none(*pmd) || pmd_bad(*pmd))
    return 0;
  
  pte = _pte_offset_kernel(pmd, virt_addr);
  if (pte_none(*pte) || !pte_present(*pte))
    return 0;
  //printk("pte: %08lx\n", *pte);
  
  page_addr = pte_val(*pte) & PAGE_MASK;
  page_offset = virt_addr & ~PAGE_MASK;
  paddr = page_addr | page_offset;
  
  //printk("paddr: %08lx\n", paddr);
  return paddr;
}

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
      printk("PID: %d physical: %08lx-%08lx\n", pid, _virt_to_phys(mm, vma->vm_start), _virt_to_phys(mm, vma->vm_end));
    //if ((virt_to_phys(vma->vm_start) != NULL) && (virt_to_phys(vma->vm_end) != NULL)) {
    //  printk("virtual: %08lx-%08lx has corresponding physical\n", vma->vm_start, vma->vm_end);
    //} 
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

	//int curpid = task_pid_nr(current->pid);
	//int curpid = syscall(SYS_gettid);
	//int curpid = pthread_self();
	taskpid = find_get_pid(current->pid);
	task = pid_task(taskpid, PIDTYPE_PID );
	if(task == NULL) {
		printk("cannot find task: pid: %d \n", taskpid);
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
      printk("PID: %d physical: %08lx-%08lx\n", taskpid, _virt_to_phys(mm, vma->vm_start), _virt_to_phys(mm, vma->vm_end));
    //if ((virt_to_phys(vma->vm_start) != NULL) && (virt_to_phys(vma->vm_end) != NULL)) {
    //  printk("virtual: %08lx-%08lx has corresponding physical\n", vma->vm_start, vma->vm_end);
    //} 
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
