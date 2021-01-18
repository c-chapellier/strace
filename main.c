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

char *syscall_str(syscall_table_t syscall_table, int syscall_number)
{
	int	i = 0;

	while (i < syscall_table.size)
	{
		if (syscall_table.value[i] == syscall_number)
			return (syscall_table.str[i]);
		++i;
	}
	return ("Unknow");
}

int	alloc_syscall_table(syscall_table_t *syscall_table, const char *filename)
{
	FILE	*fp;
    char	*line = NULL;
    size_t	len = 0;
	int		i = 0;

    if ((fp = fopen(filename, "r")) == NULL)
		return (-1);

    while (getline(&line, &len, fp) != -1)
	{
		++i;
    }
	syscall_table->size = i;

    fclose(fp);
    if (line)
        free(line);

	if ((syscall_table->str = malloc(syscall_table->size * sizeof(char *))) == NULL)
		return (-1);
	if ((syscall_table->value = malloc(syscall_table->size * sizeof(int))) == NULL)
	{
		free(syscall_table->str);
		return (-1);
	}
	return (0);
}

int	get_syscall_table(syscall_table_t *syscall_table, const char *filename)
{
	FILE	*fp;
    char	*line = NULL;
    size_t	len = 0;
	int		i = 0;
	char	**split;

	if (alloc_syscall_table(syscall_table, filename) == -1)
		return (-1);
    if ((fp = fopen(filename, "r")) == NULL)
		return (-1);
    while (getline(&line, &len, fp) != -1)
	{
		strtok(line, " \t");
   		syscall_table->str[i] = strdup(strtok(NULL, " \t"));
		//printf("str = %s\n", syscall_table->str[i]); 
		syscall_table->value[i] = atoi(strtok(NULL, " \t"));
		//printf("value = %d\n", syscall_table->value[i]);
		++i;
    }
	syscall_table->size = i;
    fclose(fp);
    if (line)
        free(line);
	return (0);
}

void free_syscall_table(syscall_table_t syscall_table)
{
	int i = 0;

	while (i < syscall_table.size)
	{
		free(syscall_table.str[i]);
		++i;
	}
	free(syscall_table.str);
	free(syscall_table.value);
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

int main(int argc, char *argv[], char *env[])
{
	pid_t   child_pid;
	syscall_table_t	syscall_table;
	int     wstatus;

	struct user_regs_struct regs;
 	int counter = 0;
 	int in_call = 0;

	if (get_syscall_table(&syscall_table, "./syscall.h") == -1)
		return (-1);

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
				printf("%s(", syscall_str(syscall_table, regs.orig_rax));
				if (regs.orig_rax == 6)
				{
					print_str_from_child_addr(child_pid, regs.rdi);
				}
				else
					printf("%ld", regs.rdi);
				printf(", %ld", regs.rsi);
				printf(", %ld", regs.rdx);
				printf(")");
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
		printf("Syscalls number = %d\n", counter);
    }
	free_syscall_table(syscall_table);
    return (0);
}
