#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

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
		write(1, "parent\n", 7);
	}
	return (0);
}
