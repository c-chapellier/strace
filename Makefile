SRCS =	main.c \
		print_syscall.c \
		ft_errno.c \
		data/syscall_table_32.c \
		data/syscall_table_64.c \
		data/color_table.c \
		data/errno_table.c

OBJS = ${SRCS:.c=.o}

NAME = ft_strace

CFLAGS		= -Wall -Wextra -Werror

all :		${NAME}

${NAME} :	${OBJS}
			gcc -o ${NAME} ${OBJS}

clean :
			rm -f ${OBJS}

fclean :	clean
			rm -f ${NAME}

re :		fclean all
