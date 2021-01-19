#include "strace.h"

static char *get_str_from_child(pid_t child_pid, unsigned long addr)
{
	char *str;
	int	i = 0, size = 100;
	
	if (addr == 0)
	{
		return (NULL);
	}
	if ((str = malloc(size * sizeof(char))) == NULL)
	{
		printf("malloc error");
		return (NULL);
	}
	str[0] = ptrace(PTRACE_PEEKTEXT, child_pid, addr, NULL);
	while (str[i] != '\0' && i < size - 1)
	{
		++addr;
		++i;
		str[i] = ptrace(PTRACE_PEEKTEXT, child_pid, addr, NULL);
	}
	str[i] = '\0';
	return (str);
}

static void print_str(const char *str)
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

static void print_ptr(void *ptr)
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

static void	get_str_tab_from_child(pid_t child_pid, unsigned long addr) // maybe just try with str_from_child
{
	char	**str_tab;
	char	**tmp = (char **)addr;
	int	i = 0, size = 100;
	
	if (addr == 0)
	{
		printf("\"(null)\"");
		return ;
	}
	if ((str_tab = malloc(size * sizeof(char *))) == NULL)
	{
		printf("malloc error");
		return (NULL);
	}
	str_tab[0] = get_str_from_child_addr(child_pid, (unsigned long)tmp[0]);
	while (str_tab[i] != NULL && i < size - 1)
	{
		++i;
		str_tab[i] = get_str_from_child_addr(child_pid, (unsigned long)tmp[i]);
	}
	str_tab[i] = NULL;
	return (str_tab);
}

static void	print_str_tab(char **str_tab, unsigned long addr)
{
	int i = 0;

	while (str_tab[i] != NULL)
	{
		++i;
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

static void free_2d(void **array)
{
	int i = 0;

	while (array[i] != NULL)
	{
		free(array[i]);
		++i;
	}
	free(array);
}

static void print_str_from_child(pid_t child_pid, unsigned long reg)
{
	char *str;
	
	str = get_str_from_child(child_pid, reg);
	print_str(str);
	free(str);
}

static void print_reg(pid_t child_pid, unsigned long reg, unsigned int type)
{
	if (type == PTR)
	{
		print_ptr((void *)reg);
	}
	else if (type == STRING)
	{
		print_str_from_child(child_pid, reg);
	}
	else if (type == STRING_TAB)
	{
		print_str_tab_from_child(child_pid, reg);
	}
	else
	{
		printf("%ld", reg);
	}
}

static void print_know_syscall(pid_t child_pid, struct user_regs_struct regs)
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

static void print_unknow_syscall(pid_t child_pid, struct user_regs_struct regs)
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

void    print_syscall(pid_t child_pid, struct user_regs_struct regs)
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