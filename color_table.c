#include "strace.h"

#define RED 0
#define GREEN 1
#define BROWN 2
#define BLUE 3
#define PURPLE 4
#define CYAN 5
#define RESET "\033[0m"

const char	*color_table[] =
{
 	"\e[0;31m",
 	"\e[0;32m",
 	"\e[0;33m",
 	"\e[0;34m",
 	"\e[0;35m",
 	"\e[0;36m",
	NULL
};
