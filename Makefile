SRCS =	main.c \
		syscall_table.c \
		syscall_table_32bits.c \
		print_syscall.c \
		color_table.c \
		ft_errno.c

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
