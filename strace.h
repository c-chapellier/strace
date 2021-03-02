#ifndef STRACE_H
#define STRACE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <signal.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/reg.h>

#define PTR			0
#define STRING		1
#define STRING_TAB	2
#define NUMBER		3
#define NONE		4

#define MAX_SYSCALL_32 384
#define MAX_SYSCALL_64 328

#define RED 0
#define GREEN 1
#define BROWN 2
#define BLUE 3
#define PURPLE 4
#define CYAN 5
#define RESET "\033[0m"

typedef struct	s_syscall
{
	char		*name;
	uint16_t	orig_rax;
	uint8_t		rdi;
	uint8_t		rsi;
	uint8_t		rdx;
	uint8_t		r10;
	uint8_t		r8;
	uint8_t		r9;
}				syscall_t;

typedef struct	s_ft_errno
{
	char		*name;
	int			value;
	char		*interpretation;
}				ft_errno_t;

extern char				**environ;
extern const syscall_t	syscall_table_64[330];
extern const syscall_t	syscall_table_32[386];
extern const char		*color_table[7];
extern const ft_errno_t	errno_table[127];

void	print_rax(unsigned long rax);
void	print_syscall(pid_t child_pid, struct user_regs_struct regs, int is_32bits);

char    *ft_strerror(int errnum);
void    ft_perror(const char *s);
char	*ft_errno_name(int errnum);

#endif
