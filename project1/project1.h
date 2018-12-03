#ifndef _PROJECT1_H_
#define _PROJECT1_H_
asmlinkage long sys_listProcessInfo(void);
asmlinkage long sys_linux_survey_TT(int pid, char *buf);

extern int project1_hook_ready;
extern int (*project1_hook)(int pid, char *result);

#endif
