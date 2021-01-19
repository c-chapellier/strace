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

char	*get_str_from_child_addr(pid_t child_pid, unsigned long addr)
{
	char str[100];
	int	i = 0;
	
	if (addr == 0)
	{
		return (NULL);
	}
	str[0] = ptrace(PTRACE_PEEKTEXT, child_pid, addr, NULL);
	while (str[i] != '\0')
	{
		++addr;
		++i;
		str[i] = ptrace(PTRACE_PEEKTEXT, child_pid, addr, NULL);
	}
	return (strdup(str));
}

void print_str(const char *str)
{
	if (str == NULL)
	{
		printf("(null)");
	}
	else
	{
		printf("\"%s\"", str);
	}
}

void print_ptr(void *ptr)
{
	if (ptr == NULL)
	{
		printf("NULL");
	}
	else
	{
		printf("%p", ptr);
	}
}

void	print_str_tab_from_child_addr(pid_t child_pid, unsigned long addr)
{
	char	*str_tab[100];
	char	**tmp = (char **)addr;
	int	i = 0;
	
	if (addr == 0)
	{
		printf("\"(null)\"");
		return ;
	}
	str_tab[0] = get_str_from_child_addr(child_pid, (unsigned long)tmp[0]);
	while (str_tab[i] != NULL)
	{
		++i;
		str_tab[i] = get_str_from_child_addr(child_pid, (unsigned long)tmp[i]);
	}

	if (i > 10)
	{
		print_ptr((void *)addr);
		printf(" /* %d vars */", i);
	}
	else
	{
		i = 0;
		printf("[");
		while (str_tab[i] != NULL)
		{
			if (i != 0)
			{
				printf(", ");
			}
			print_str(str_tab[i]);
			++i;
		}
		printf("]");
	}
}

void print_reg(pid_t child_pid, unsigned long reg, unsigned int type)
{
	if (type == PTR)
	{
		print_ptr((void *)reg);
	}
	else if (type == STRING)
	{
		char *str = get_str_from_child_addr(child_pid, reg);
		print_str(str);
		free(str);
	}
	else if (type == STRING_TAB)
	{
		print_str_tab_from_child_addr(child_pid, reg);
	}
	else
	{
		printf("%ld", reg);
	}
}

void print_know_syscall(pid_t child_pid, struct user_regs_struct regs)
{
    printf("%s(", syscall_table[regs.orig_rax].name);
	if (syscall_table[regs.orig_rax].rdi != NONE)
	{
   		print_reg(child_pid, regs.rdi, syscall_table[regs.orig_rax].rdi);
	}
	if (syscall_table[regs.orig_rax].rsi != NONE)
	{
		printf(", ");
		print_reg(child_pid, regs.rsi, syscall_table[regs.orig_rax].rsi);
	}
	if (syscall_table[regs.orig_rax].rdx != NONE)
	{
		printf(", ");
		print_reg(child_pid, regs.rdx, syscall_table[regs.orig_rax].rdx);
	}
	//printf(")");
	printf(") = %ld\n", regs.rax);
}

void print_unknow_syscall(pid_t child_pid, struct user_regs_struct regs)
{
    printf("unknow(");
   	print_reg(child_pid, regs.rdi, NUMBER);
	printf(", ");
	print_reg(child_pid, regs.rsi, NUMBER);
	printf(", ");
	print_reg(child_pid, regs.rdx, NUMBER);
	//printf(")");
	printf(") = %ld\n", regs.rax);
}

void print_syscall(pid_t child_pid, struct user_regs_struct regs)
{
	if (regs.orig_rax > MAX_SYSCALL)
	{
		print_unknow_syscall(child_pid, regs);
	}
	else
	{
		print_know_syscall(child_pid, regs);
	}
}

void print_syscall_info(struct ptrace_syscall_info syscall_info)
{
	int i = 0;

	printf("---------  Syscall_info  ----------\n");
	printf("op = %d\n", syscall_info.op);
	printf("arch = %d\n", syscall_info.arch);
	printf("inst_ptr = %lld\n", syscall_info.instruction_pointer);
	printf("stack_ptr = %lld\n", syscall_info.stack_pointer);
	
	if (syscall_info.op == PTRACE_SYSCALL_INFO_ENTRY)
	{
		printf("\tnr = %lld\n", syscall_info.entry.nr);
		while (i < 6)
		{
			printf("\targs[%d] = %lld\n", i, syscall_info.entry.args[i]);
			++i;
		}
	}
	if (syscall_info.op == PTRACE_SYSCALL_INFO_EXIT)
	{
		printf("\trval = %lld\n", syscall_info.exit.rval);
		printf("\tis_error = %d\n", i, syscall_info.exit.is_error);
	}
	if (syscall_info.op == PTRACE_SYSCALL_INFO_SECCOMP)
	{
		printf("\tnr = %lld\n", syscall_info.seccomp.nr);
		while (i < 6)
		{
			printf("\targs[%d] = %lld\n", i, syscall_info.seccomp.args[i]);
			++i;
		}
		printf("\tret_data = %d\n", syscall_info.seccomp.ret_data);
	}
	printf("--------------------------------------\n");
}

void parent(pid_t child_pid)
{
    int                     wstatus;
	struct user_regs_struct regs;
	struct ptrace_syscall_info syscall_info;
 	int                     in_call = 0;
;
    wait(&wstatus);
	ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT);
	ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
	wait(&wstatus);
    while (WIFSTOPPED(wstatus))
    {
		//errno = 0;
		//long ret = ptrace(PTRACE_GET_SYSCALL_INFO, child_pid, sizeof(struct ptrace_syscall_info), &syscall_info);
		//if (errno)
		//{
		//	perror("ICI: ");
		//}
		//printf("ret = %ld\n", ret);
		//print_syscall_info(syscall_info);
		siginfo_t sig;
		
		ptrace(PTRACE_GETSIGINFO, child_pid, NULL, &sig);
		if (sig.si_code & 0x80)
		{
			//printf("in a syscall\n");
		}
		else
		{
			//printf("not in a syscall\n");
		}

        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        if (!in_call)
        {
            print_syscall(child_pid, regs);
			in_call = 1;
		}
		else
		{
			//printf(" = %ld\n", regs.rax);
			in_call = 0;
        }
		if (wstatus >> 8  == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) // exit
		{
			unsigned long exit_value;
			ptrace(PTRACE_GETEVENTMSG, child_pid, NULL, &exit_value);
			printf("+++ exited with %lu +++\n", exit_value);
		}
        ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL); 
        wait(&wstatus); 
    }
    errno = 0;
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
	raise(SIGSTOP);
    execve(argv[1], &argv[1], env);
	//system(argv[1]);
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

