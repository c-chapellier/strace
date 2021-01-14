#include "strace.h"

// int ptrace(int request, pid_t pid, caddr_t addr, int data);
// pid_t wait4(pid_t pid, int *stat_loc, int options, struct rusage *rusage);

void check_status(int status)
{
    printf("status: ");
    if (WIFEXITED(status))
    {
        printf("exited: %d", WEXITSTATUS(status));
    }

    if (WIFSIGNALED(status))
    {
        printf("signaled: %d: ", WTERMSIG(status));
        if (WCOREDUMP(status))
        {
            printf("core dump");
        }
        else
        {
            printf("no core dump");
        }
    }

    if (WIFSTOPPED(status))
    {
        printf("stopped: %d", WSTOPSIG(status));
    }
    printf("\n");
}

#define ERR( msg, pid ) do { \
                          fprintf( stderr, "%s: %s (errno = %d)\n", \
                            msg, strerror( errno ), errno ); \
                          waitpid( pid, NULL, 0 ); \
                          return 1; \
                        } while( 0 );

int main(int argc, char *argv[], char *env[])
{
    char    *command[] = {"./pause", NULL};
    pid_t   child_pid;
    int     status;

    child_pid = fork();
    if (child_pid == -1)
    {
        perror("fork");
        exit(-1);
    }
    else if (child_pid == 0)
    {
        errno = 0;
        ptrace(PT_TRACE_ME, 0, 0, 0);
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
        wait4(child_pid, &status, WUNTRACED, NULL);
        if (errno)
        {
            perror("parent: wait4");
            exit(-1);
        }
        check_status(status);
        errno = 0;
        // printf("parent: before ptrace\n");
        ptrace(PT_ATTACHEXC, child_pid, 0, 0);
        if (errno)
        {
            perror("parent: ptrace");
            exit(-1);
        }
        printf("parent: return\n");
    }
    return (0);
}
