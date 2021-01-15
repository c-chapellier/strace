#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h> /* for ptrace() */
#include <sys/user.h> /* for struct user_regs_struct */
/* This program runs the 2nd argument argv[1] in a child process 
 * and count the number of system calls made by the child process.
 */
int main ( int argc, char * argv[] )
{
 int status; 
 pid_t pid;
 struct user_regs_struct regs;
 int counter = 0;
 int in_call =0;
 
 switch(pid = fork()){
   case -1: 
     perror("fork");
     exit(1);
   case 0: /* in the child process */
     ptrace(PTRACE_TRACEME, 0, NULL, NULL);
     execvp(argv[1], argv+1);
   default: /* in the parent process */
     wait(&status);
     while(status == 1407){
       ptrace(PTRACE_GETREGS, pid, NULL, &regs);
       if(!in_call){
         printf("SystemCall %ld called with %ld, %ld,     %ld\n",regs.orig_rax, regs.rbx, regs.rcx, regs.rdx);
         in_call=1;
         counter ++;
       }
       else
         in_call = 0; 
     ptrace(PTRACE_SYSCALL, pid, NULL, NULL); 
     wait(&status); 
     }
   }
   printf("Total Number of System Calls=%d\n", counter);
   return 0; 
}
