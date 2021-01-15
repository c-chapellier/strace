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

int main(int argc, char *argv[], char *env[])
{
    char    *command[] = {"./pause", NULL};
    pid_t   child_pid;
    int     wstatus;

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
        execve(command[0], command, env);
        printf("child: return\n");
    }
    else
    {
        errno = 0;
        wait4(child_pid, &wstatus, WUNTRACED, NULL);
        if (errno)
        {
            perror("parent: wait4");
            exit(-1);
        }
        check_wstatus(wstatus);
        errno = 0;
        // printf("parent: before ptrace\n");
        ptrace(PTRACE_ATTACH, child_pid, 0, 0);
        if (errno)
        {
            perror("parent: ptrace");
            exit(-1);
        }
        printf("parent: return\n");
    }
    return (0);
}
