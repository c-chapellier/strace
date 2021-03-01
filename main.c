#include "strace.h"
#include "pthread.h"

// long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
// pid_t wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage);

#ifdef __x86_64__
#define SC_NUMBER  (8 * ORIG_RAX)
#define SC_RETCODE (8 * RAX)
#else
#define SC_NUMBER  (4 * ORIG_EAX)
#define SC_RETCODE (4 * EAX)
#endif

void parent(pid_t child_pid)
{
	long sc_number, sc_retcode;
    int                         wstatus;
	struct user_regs_struct     regs;
	struct ptrace_syscall_info  syscall_info;
 	int                         in_call = 0;
	int							is_in_execve = 0;

	ptrace(PTRACE_SEIZE, child_pid, 0,	PTRACE_O_TRACESYSGOOD |
										PTRACE_O_TRACEEXEC |
										PTRACE_O_TRACEEXIT
	);
	wait(&wstatus);
    while (WIFSTOPPED(wstatus))
    {
		if (wstatus >> 8  == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) // exit
		{
			unsigned long exit_value;
			ptrace(PTRACE_GETEVENTMSG, child_pid, NULL, &exit_value);
			printf(") = ?\n+++ exited with %lu +++\n", exit_value);
			break;
		}

		//printf("[%d]\n", WSTOPSIG(wstatus));

		if (WSTOPSIG(wstatus) == 133)	// PTRACE_EVENT_STOP
		{
        	ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

			if (regs.rax == -ENOSYS && regs.orig_rax == 59)	// if execve is called
			{
				is_in_execve = 1;
			}

			if (is_in_execve)	// display only syscalls of called program (after execve)
			{
				if (regs.rax == -ENOSYS)	// in a syscall
				{
					print_syscall(child_pid, regs);
				}
				else
				{
					print_rax(regs.rax);
				}
			}
		}

		ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL); 
		wait(&wstatus); 
    }
}

void child(char *argv[])
{
	raise(SIGSTOP);
    execve(argv[1], &argv[1], environ);
	//system(argv[1]);
	perror("execve");
	exit(-1);
}

int main(int argc, char *argv[])
{
	pid_t   child_pid;

	if (argc < 2)
	{
		printf("usage: PROG [ARGS]\n");
		return (-1);
	}
    child_pid = fork();
    if (child_pid == -1)
    {
        perror("fork: ");
        exit(-1);
    }
    else if (child_pid == 0)
    {
		child(argv);
    }
    else
    {
		parent(child_pid);
    }
    return (0);
}

