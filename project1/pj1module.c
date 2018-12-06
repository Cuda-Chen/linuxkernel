#include <linux/mm.h>
#include <linux/sched.h>
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

long project1_sys_func(int pid, char *result);

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

long project1_sys_func(int pid, char *result)
{
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
    //printk("PID: %d physical: %08lx-%08lx\n", pid, virt_to_phys(vma->vm_start), virt_to_phys(vma->vm_end));
    printk("PID: %d physical: %08lx-%08lx\n", pid, _virt_to_phys(mm, vma->vm_start), _virt_to_phys(mm, vma->vm_end));
    vma = vma->vm_next;
  }

  return 0;
}

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


static int __init project1_init(void){
    project1_hook = project1_sys_func;
    project1_hook_ready = 1;
    project1_sys_func(3219, NULL);
    return 0;
}
static void __exit project1_exit(void){
    project1_hook_ready = 0;
    project1_hook = NULL;

}

module_init(project1_init);
module_exit(project1_exit);
