#ifndef STRACE_H
#define STRACE_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
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

#define MAX_SYSCALL 328

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

void	print_rax(unsigned long rax);
void	print_syscall(pid_t child_pid, struct user_regs_struct regs);

extern char				**environ;
extern const syscall_t	syscall_table[330];

#endif
