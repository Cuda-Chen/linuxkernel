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
#define pmd_table(pmd)		((pmd_val(pmd) & PMD_TYPE_MASK) ==  PMD_TYPE_TABLE)


static int bad_address(void *p)
{
	unsigned long dummy;

	return probe_kernel_address((unsigned long *)p, dummy);
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
  //printk("pgd: %08lx\n", *pgd);
  if (bad_address(pgd) || pgd_none(*pgd) || pgd_bad(*pgd) || !pgd_present(*pgd)){
    return 0;
  }
  pud = _pud_offset(pgd, virt_addr);
  //printk("pud: %08lx\n", *pud);
  if (bad_address(pud) || pud_none(*pud) || pud_bad(*pud) || !pud_present(*pud)){
    return 0;
  }
  if(pud_large(*pud)){
    printk("pud_large!\n");
    page_addr = pud_val(*pud) & PUD_MASK;
    page_offset = virt_addr & ~PUD_MASK;
    paddr = page_addr | page_offset;
    return paddr;
  }
  pmd = _pmd_offset(pud, virt_addr);
  //printk("pmd: %08lx flags:%08lx\n", *pmd, pmd_flags(*pmd));
  if (bad_address(pmd) || pmd_none(*pmd) || pmd_bad(*pmd) || ! pmd_present(*pmd)){
    return 0;
  }
  if(pmd_trans_huge(*pmd)){
    printk("pmd_trans_huge!\n");    
  }
  if(pmd_large(*pmd)){
    //printk("pmd_large!\n");
    page_addr = pmd_val(*pmd) & PMD_MASK;
    page_offset = virt_addr & ~PMD_MASK;
    paddr = page_addr | page_offset;
    return paddr;
  }  
  pte = _pte_offset_kernel(pmd, virt_addr);
  if (bad_address(pte) || pte_none(*pte) || !pte_present(*pte)){
    return 0;
  }
  //printk("pte: %08lx\n", *pte);
  
  page_addr = pte_val(*pte) & PAGE_MASK;
  page_offset = virt_addr & ~PAGE_MASK;
  paddr = page_addr | page_offset;
  
  //printk("paddr: %08lx\n", paddr);
  return paddr;
}


void ptdump_walk_pgd(void){
  struct task_struct *proc;
  unsigned long lowest_paddr = 0xFFFFFFFF;
  unsigned long highest_paddr = 0x00000000;
  uint8_t mem_usage[0x100000] = {0};
  unsigned long mem_total = 0;
  for_each_process(proc){
    printk("PID: %d state: %08lx flags:%08lx\n", proc->pid, proc->state, proc->flags);
    struct mm_struct *mm = proc->mm;
    if(mm==NULL){
      mm = proc->active_mm;
    }
    if(mm==NULL){
      continue;
    }
    struct vm_area_struct *vma = mm->mmap;
    while(vma != NULL){
      if(!!(vma->vm_flags & VM_HUGETLB)){
	printk("hugetlb!\n");
	continue;
      }
      unsigned long vaddr;
      for(vaddr = vma->vm_start; vaddr < vma->vm_end; vaddr += 0x07){
	unsigned long paddr = _virt_to_phys(mm, vaddr);
	if(paddr != 0){
	  lowest_paddr = paddr < lowest_paddr ? paddr : lowest_paddr;
	  highest_paddr = paddr > highest_paddr ? paddr : highest_paddr;
	  mem_total++;
	}
      }
      break;
      vma = vma->vm_next;
    }
  }
  printk("low: %08lx high: %08lx count: %08lx\n", lowest_paddr, highest_paddr, mem_total);
  printk("totalram_pages: %08lx\n", totalram_pages);
  printk("totalram: %08lx\n", totalram_pages * 4096);
}

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

  //printk("mm flag: %08lx\n", mm->flags);

  struct vm_area_struct *vma = mm->mmap;
  while (vma != NULL){
    printk("PID: %d vma flag: %08lx\n", pid, vma->vm_flags);
    printk("PID: %d virtual: %08lx-%08lx\n", pid, vma->vm_start, vma->vm_end);
    //printk("PID: %d physical: %08lx-%08lx\n", pid, virt_to_phys(vma->vm_start), virt_to_phys(vma->vm_end));
    printk("PID: %d physical: %08lx-%08lx\n", pid, _virt_to_phys(mm, vma->vm_start), _virt_to_phys(mm, vma->vm_end));
    vma = vma->vm_next;
  }

  return 0;
}

long project1b_sys_func(char *result)
{
	printk("VV HI");
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *taskpid;

	taskpid = find_get_pid(current->pid);
	task = pid_task(taskpid, PIDTYPE_PID);
	if(task == NULL) {
		printk("cannot find task: pid: %d \n", taskpid);
		return 0;
	}

	mm = task->mm;

	if(mm == NULL) {
		mm = task->active_mm;
	}

	if(mm == NULL)
		return 0;

	//printk("mm flag: %08lx\n", mm->flags);

	struct vm_area_struct *vma = mm->mmap;
	while(vma != NULL) {
		printk("PID: %d vma flag: %08lx\n", taskpid, vma->vm_flags);
		printk("PID: %d virtual: %08lx-%08lx\n", taskpid, vma->vm_start, vma->vm_end);
		printk("PID: %d physical: %08lx-%08lx\n", taskpid, _virt_to_phys(mm, vma->vm_start), _virt_to_phys(mm, vma->vm_end));

		vma = vma->vm_next;
	}

	return 0;
}

static int __init project1_init(void){
    project1_hook = project1_sys_func;
    project1_hook_ready = 1;
    project1_sys_func(1290, NULL);
    ptdump_walk_pgd();
    return 0;
}
static void __exit project1_exit(void){
    project1_hook_ready = 0;
    project1_hook = NULL;

}

module_init(project1_init);
module_exit(project1_exit);
