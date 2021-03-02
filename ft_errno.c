#include "strace.h"

char    *ft_strerror(int errnum)
{
    if (errnum < 0)
    {
        return (strdup(errno_table[0].interpretation));
    }
    return (strdup(errno_table[errnum + 1].interpretation));
}

void    ft_perror(const char *s)
{
    char    *msg = ft_strerror(errno);
    if (s != NULL)
    {
        printf("%s: ", s);
    }
    printf("%s\n", msg);
    free(msg);
}

char	*ft_errno_name(int errnum)
{
	if (errnum < 0)
	{
		return (strdup(errno_table[0].name));
	}
	return (strdup(errno_table[errnum + 1].name));
}
