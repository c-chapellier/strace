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

void	print_str_from_child_addr(pid_t child_pid, unsigned long addr)
{
	char word = '1';
	
	while (word != '\0')
	{
		word = ptrace(PTRACE_PEEKTEXT, child_pid, addr, NULL);
		++addr;
		printf("%c", word);
	}
}

void print_regs(pid_t child_pid, struct user_regs_struct regs)
{
    printf("%s(", syscall_table[regs.orig_rax].name);
    if (regs.orig_rax == 6)
    {
        print_str_from_child_addr(child_pid, regs.rdi);
    }
    else
        printf("%ld", regs.rdi);
    printf(", %ld", regs.rsi);
    printf(", %ld", regs.rdx);
    printf(")");
}

void parent(pid_t child_pid)
{
    int                     wstatus;
	struct user_regs_struct regs;
 	int                     counter = 0;
 	int                     in_call = 0;

    errno = 0;
    wait(&wstatus);
    if (errno)
    {
        perror("parent: wait: ");
        exit(-1);
    }
    check_wstatus(wstatus);
    while (wstatus == 1407)
    {
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        if (!in_call)
        {
            print_regs(child_pid, regs);
			in_call = 1;
			++counter;
		}
		else
		{
			printf(" = %ld\n", regs.orig_rax);
			in_call = 0;
        }
        ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL); 
        wait(&wstatus); 
    }
    errno = 0;
    printf("nbr of syscalls = %d\n", counter);
}

void child(char *argv[], char *env[])
{
    errno = 0;
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (errno)
    {
        perror("child: ptrace");
        exit(-1);
    }
    execve(argv[1], &argv[1], env);
    printf("child: return\n");
}

int main(int argc, char *argv[], char *env[])
{
	pid_t   child_pid;

    child_pid = fork();
    if (child_pid == -1)
    {
        perror("fork: ");
        exit(-1);
    }
    else if (child_pid == 0)
    {
		child(argv, env);
    }
    else
    {
		parent(child_pid);
    }
    return (0);
}
