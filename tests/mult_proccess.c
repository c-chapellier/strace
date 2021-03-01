#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>

int main()
{
	int pid = fork();

	if (pid == 0)
	{
		write(1, "child\n", 6);
	}
	else
	{
		wait(NULL);
		write(1, "\t\tpar  \f\v ent\nok\n\r", 70);
	}
	return (0);
}
