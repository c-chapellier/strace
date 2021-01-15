#include "strace.h"

// long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
// pid_t wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage);

void check_wstatus(int wstatus)
{
    printf("wstatus: ");
    if (WIFEXITED(wstatus))
    {
        printf("exited: %d", WEXITSTATUS(wstatus));
    }

    if (WIFSIGNALED(wstatus))
    {
        printf("signaled: %d: ", WTERMSIG(wstatus));
        if (WCOREDUMP(wstatus))
        {
            printf("core dump");
        }
        else
        {
            printf("no core dump");
        }
    }

    if (WIFSTOPPED(wstatus))
    {
        printf("stopped: %d", WSTOPSIG(wstatus));
    }

    if (WIFCONTINUED(wstatus))
    {
        printf("continued: ");
    }
    printf("\n");
}

char *syscall_str(int syscall)
{
	switch (syscall)
	{
		case 0:
			return ("read");
		case 1:
			return ("write");
		case 2:
			return ("open");
		case 3:
			return ("close");
		case 4:
			return ("stat");
		case 5:
			return ("fstat");
		case 6:
			return ("lstat");
		case 7:
			return ("poll");
		case 8:
			return ("lseek");
		case 9:
			return ("mmap");
		case 10:
			return ("mprotect");
		case 11:
			return ("munmap");
		case 12:
			return ("brk");
		default:
			return ("Unknow");
	}
}

int main(int argc, char *argv[], char *env[])
{
	pid_t   child_pid;
	int     wstatus;

	struct user_regs_struct regs;
 	int counter = 0;
 	int in_call =0;

    child_pid = fork();
    if (child_pid == -1)
    {
        perror("fork");
        exit(-1);
    }
    else if (child_pid == 0)
    {
		errno = 0;
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        if (errno)
        {
            perror("child: ptrace");
            exit(-1);
        }
        // printf("child: before execve\n");
        execve(argv[1], &argv[1], env);
        printf("child: return\n");
    }
    else
    {
		errno = 0;
		wait(&wstatus);
		if (errno)
        {
            perror("parent: wait4");
            exit(-1);
        }
        check_wstatus(wstatus);
		while (wstatus == 1407)
		{
			ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
			if (!in_call)
			{
				printf("Syscall %s:\n", syscall_str(regs.orig_rax));
				printf("\trax: %ld\n", regs.rbx);
				printf("\trbx: %ld\n", regs.rcx);
				printf("\trdx: %ld\n", regs.rdx);
				in_call = 1;
				++counter;
			}
			else
			{
				in_call = 0;
			}
			ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL); 
			wait(&wstatus); 
		}
        errno = 0;
		printf("Syscalls number = %d\n", counter);
    }
    return (0);
}
