#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/ptrace.h>

char *syscall_str(long long rax){
	switch(rax){
		case 0:
			return "read";
		case 1:
			return "write";
		case 2:
			return "open";
		case 3:
			return "close";
		case 4:
			return "stat";
		case 5:
			return "fstat";
		case 6:
			return "lstat";
		case 7:
			return "poll";
		case 8:
			return "lseek";
		case 9:
			return "mmap";
		case 10:
			return "mprotect";
		case 11:
			return "munmap";
		case 12:
			return "brk";
		case 13:
			return "rt_sigaction";
		case 14:
			return "rt_sigprocmask";
		case 15:
			return "rt_sigreturn";
		case 16:
			return "ioctl";
		case 17:
			return "pread64";
		case 18:
			return "pwrite64";
		case 19:
			return "readv";
		case 20:
			return "writev";
		case 21:
			return "access";
		case 22:
			return "pipe";
		case 23:
			return "select";
		case 24:
			return "sched_yield";
		case 25:
			return "mremap";
		case 26:
			return "msync";
		case 27:
			return "mincore";
		case 28:
			return "madvise";
		case 29:
			return "shmget";
		case 30:
			return "shmat";
		case 31:
			return "shmctl";
		case 32:
			return "dup";
		case 33:
			return "dup2";
		case 34:
			return "pause";
		case 35:
			return "nanosleep";
		case 36:
			return "getitimer";
		case 37:
			return "alarm";
		case 38:
			return "setitimer";
		case 39:
			return "getpid";
		case 40:
			return "sendfile";
		case 41:
			return "socket";
		case 42:
			return "connect";
		case 43:
			return "accept";
		case 44:
			return "sendto";
		case 45:
			return "recvfrom";
		case 46:
			return "sendmsg";
		case 47:
			return "recvmsg";
		case 48:
			return "shutdown";
		case 49:
			return "bind";
		case 50:
			return "listen";
		case 51:
			return "getsockname";
		case 52:
			return "getpeername";
		case 53:
			return "socketpair";
		case 54:
			return "setsockopt";
		case 55:
			return "getsockopt";
		case 56:
			return "clone";
		case 57:
			return "fork";
		case 58:
			return "vfork";
		case 59:
			return "execve";
		case 60:
			return "exit";
		case 61:
			return "wait4";
		case 62:
			return "kill";
		case 63:
			return "uname";
		case 64:
			return "semget";
		case 65:
			return "semop";
		case 66:
			return "semctl";
		case 67:
			return "shmdt";
		case 68:
			return "msgget";
		case 69:
			return "msgsnd";
		case 70:
			return "msgrcv";
		case 71:
			return "msgctl";
		case 72:
			return "fcntl";
		case 73:
			return "flock";
		case 74:
			return "fsync";
		case 75:
			return "fdatasync";
		case 76:
			return "truncate";
		case 77:
			return "ftruncate";
		case 78:
			return "getdents";
		case 79:
			return "getcwd";
		case 80:
			return "chdir";
		case 81:
			return "fchdir";
		case 82:
			return "rename";
		case 83:
			return "mkdir";
		case 84:
			return "rmdir";
		case 85:
			return "creat";
		case 86:
			return "link";
		case 87:
			return "unlink";
		case 88:
			return "symlink";
		case 89:
			return "readlink";
		case 90:
			return "chmod";
		case 91:
			return "fchmod";
		case 92:
			return "chown";
		case 93:
			return "fchown";
		case 94:
			return "lchown";
		case 95:
			return "umask";
		case 96:
			return "gettimeofday";
		case 97:
			return "getrlimit";
		case 98:
			return "getrusage";
		case 99:
			return "sysinfo";
		case 100:
			return "times";
		default:
			return "unknown";
	}
}

pid_t spawn_proc(char *az, char **argv){
	pid_t pid = -1;
	pid = fork();
	if(!pid){
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execvp(az, argv);
	}
	if(pid < 0){
		printf("Failed to spawn process: %s\n", strerror(errno));
		return -1;
	}
	printf("Spawned Process %d (%s)\n", pid, az);
	return pid;
}

pid_t attach_proc(pid_t pid){
	printf("Attaching...\n");
	return 0;
}

void usage(char *az){
	printf("Usage:\n %s <Executable> [args...]\n", az);
	printf(" %s -p <PID>\n", az);
	return;
}

int main(int argc, char **argv){
	struct user_regs_struct regs;
	int x = 0;
	int p_namelen = 0;
	char **p_args = {NULL};
	char *p_name = NULL;
	pid_t pid = -1;
	char attached = 0;
	int status = 0;
	char entry = 0;

	if(argc < 2){
		usage(argv[0]);
		return 0;
	}
	for(;x < argc; x++){
		if( (argv[x][0] == '-') && (strlen(argv[x]) > 1) ){
			if((x+1) < argc){
				if(argv[x][1] == 'p'){
					pid = atoi(argv[x+1]);
					if(pid == 0){
						printf("%s is not a valid PID >:(\n", argv[x+1]);
						return 1;
					}
					break;
				}
			}else{
				printf("Need a PID!!!\n");
				return 0;
			}
		}
	}
	// if -p was not given to us then assume 
	// cmdline args specify an executable
	if(pid < 0){
		p_namelen = strlen(argv[1]);
		p_name = (char *)malloc(p_namelen+1);
		if(!p_name){
			printf("Failed to allocate %d bytes: %s\n", p_namelen, strerror(errno));
			return 1;
		}
		memset(p_name, 0, p_namelen+1);
		strncpy(p_name, argv[1], p_namelen);
		if(argc > 2) p_args = &argv[3];
		pid = spawn_proc(p_name, p_args);
	}
	else{
		attach_proc(pid);
		attached = 1;
	}

	if(waitpid(pid, NULL, 0) < 0){
		printf("waitpid(): %s\n", strerror(errno));
		goto XTRACE_END;
	}
	ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD);
	ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	for(;;){
		if(waitpid(pid, &status, 0) < 0){
			printf("waitpid(): %s\n", strerror(errno));
			continue;
		}
		if(WIFEXITED(status)){
			printf("Exited: %d\n", WIFEXITED(status));
			break;
		}
		else if(WIFSTOPPED(status) && (WSTOPSIG(status)&0x80)){
			if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) != -1){
				if(!entry)printf("%s(rdi: %llu, rsi: %llu, rdx: %llu, r10: %llu, r8: %llu, r9: %llu) = ", syscall_str((long long)regs.orig_rax), regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
				if((long)regs.rax == -38){
					entry = 1;
				}else{
					printf(" 0x%llx (%llu)\n", regs.rax, regs.rax);
					entry = 0;
				}
			}
		}
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	}
XTRACE_END:
	if(!attached && (pid > 1)){
		kill(pid, SIGKILL);
		kill(pid, SIGCHLD);
	}
	if(p_name) free(p_name);
	return 0;
}
