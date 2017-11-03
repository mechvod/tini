/* See LICENSE file for copyright and license details. */
#define _GNU_SOURCE
#define SIGNAL_TIMEOUT_SEC 5
#define SIGNAL_TIMEOUT_NSEC 0

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include "tiniConfig.h"
#include "tiniLicense.h"

// The following are needed for work with /proc
#include <malloc.h>
#include <sys/vfs.h>
#include <sys/mount.h>
#include <dirent.h>

#if TINI_MINIMAL
#define PRINT_FATAL(...)                         fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");
#define PRINT_WARNING(...)  if (verbosity > 0) { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#define PRINT_INFO(...)     if (verbosity > 1) { fprintf(stdout, __VA_ARGS__); fprintf(stdout, "\n"); }
#define PRINT_DEBUG(...)    if (verbosity > 2) { fprintf(stdout, __VA_ARGS__); fprintf(stdout, "\n"); }
#define PRINT_TRACE(...)    if (verbosity > 3) { fprintf(stdout, __VA_ARGS__); fprintf(stdout, "\n"); }
#define DEFAULT_VERBOSITY 0
#else
#define PRINT_FATAL(...)                         fprintf(stderr, "[FATAL tini (%i)] ", getpid()); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");
#define PRINT_WARNING(...)  if (verbosity > 0) { fprintf(stderr, "[WARN  tini (%i)] ", getpid()); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#define PRINT_INFO(...)     if (verbosity > 1) { fprintf(stdout, "[INFO  tini (%i)] ", getpid()); fprintf(stdout, __VA_ARGS__); fprintf(stdout, "\n"); }
#define PRINT_DEBUG(...)    if (verbosity > 2) { fprintf(stdout, "[DEBUG tini (%i)] ", getpid()); fprintf(stdout, __VA_ARGS__); fprintf(stdout, "\n"); }
#define PRINT_TRACE(...)    if (verbosity > 3) { fprintf(stdout, "[TRACE tini (%i)] ", getpid()); fprintf(stdout, __VA_ARGS__); fprintf(stdout, "\n"); }
#define DEFAULT_VERBOSITY 1
#endif

#define ARRAY_LEN(x)  (sizeof(x) / sizeof(x[0]))

typedef struct {
   sigset_t* const sigmask_ptr;
   struct sigaction* const sigttin_action_ptr;
   struct sigaction* const sigttou_action_ptr;
} signal_configuration_t;

static unsigned int verbosity = DEFAULT_VERBOSITY;

#ifdef PR_SET_CHILD_SUBREAPER
#define HAS_SUBREAPER 1
#define OPT_STRING "hsvgl"
#define SUBREAPER_ENV_VAR "TINI_SUBREAPER"
#else
#define HAS_SUBREAPER 0
#define OPT_STRING "hvgl"
#endif

#define VERBOSITY_ENV_VAR "TINI_VERBOSITY"

#define TINI_VERSION_STRING "tini version " TINI_VERSION TINI_GIT


#if HAS_SUBREAPER
static unsigned int subreaper = 0;
#endif
static unsigned int kill_process_group = 0;

static struct timespec ts = { .tv_sec = SIGNAL_TIMEOUT_SEC, .tv_nsec = SIGNAL_TIMEOUT_NSEC };

static const char reaper_warning[] = "Tini is not running as PID 1 "
#if HAS_SUBREAPER
       "and isn't registered as a child subreaper"
#endif
".\n\
Zombie processes will not be re-parented to Tini, so zombie reaping won't work.\n\
To fix the problem, "
#if HAS_SUBREAPER
#ifndef TINI_MINIMAL
"use the -s option "
#endif
"or set the environment variable " SUBREAPER_ENV_VAR " to register Tini as a child subreaper, or "
#endif
"run Tini as PID 1.";

pid_t (*parse_pid)(char*);
//this will point to atoi,atol or atoll depending on size of pid_t


int restore_signals(const signal_configuration_t* const sigconf_ptr) {
	if (sigprocmask(SIG_SETMASK, sigconf_ptr->sigmask_ptr, NULL)) {
		PRINT_FATAL("Restoring child signal mask failed: '%s'", strerror(errno));
		return 1;
	}

	if (sigaction(SIGTTIN, sigconf_ptr->sigttin_action_ptr, NULL)) {
		PRINT_FATAL("Restoring SIGTTIN handler failed: '%s'", strerror((errno)));
		return 1;
	}

	if (sigaction(SIGTTOU, sigconf_ptr->sigttou_action_ptr, NULL)) {
		PRINT_FATAL("Restoring SIGTTOU handler failed: '%s'", strerror((errno)));
		return 1;
	}

	return 0;
}

int isolate_child() {
	// Put the child into a new process group.
	if (setpgid(0, 0) < 0) {
		PRINT_FATAL("setpgid failed: %s", strerror(errno));
		return 1;
	}

	// If there is a tty, allocate it to this new process group. We
	// can do this in the child process because we're blocking
	// SIGTTIN / SIGTTOU.

	// Doing it in the child process avoids a race condition scenario
	// if Tini is calling Tini (in which case the grandparent may make the
	// parent the foreground process group, and the actual child ends up...
	// in the background!)
	if (tcsetpgrp(STDIN_FILENO, getpgrp())) {
		if (errno == ENOTTY) {
			PRINT_DEBUG("tcsetpgrp failed: no tty (ok to proceed)");
		} else if (errno == ENXIO) {
			// can occur on lx-branded zones
			PRINT_DEBUG("tcsetpgrp failed: no such device (ok to proceed)");
		} else {
			PRINT_FATAL("tcsetpgrp failed: %s", strerror(errno));
			return 1;
		}
	}

	return 0;
}


//int spawn(const signal_configuration_t* const sigconf_ptr, char* const argv[], int* const child_pid_ptr) {
int spawn(const signal_configuration_t* const sigconf_ptr, char* const argv[], pid_t* const child_pid_ptr) {
	pid_t pid;

	// TODO: check if tini was a foreground process to begin with (it's not OK to "steal" the foreground!")

	pid = fork();
	if (pid < 0) {
		PRINT_FATAL("fork failed: %s", strerror(errno));
		return 1;
	} else if (pid == 0) {

		// Put the child in a process group and make it the foreground process if there is a tty.
		if (isolate_child()) {
			return 1;
		}

		// Restore all signal handlers to the way they were before we touched them.
		if (restore_signals(sigconf_ptr)) {
			return 1;
		}

		execvp(argv[0], argv);

		// execvp will only return on an error so make sure that we check the errno
		// and exit with the correct return status for the error that we encountered
		// See: http://www.tldp.org/LDP/abs/html/exitcodes.html#EXITCODESREF
		int status = 1;
		switch (errno) {
			case ENOENT:
				status = 127;
				break;
			case EACCES:
				status = 126;
				break;
		}
		PRINT_FATAL("exec %s failed: %s", argv[0], strerror(errno));
		return status;
	} else {
		// Parent
		PRINT_INFO("Spawned child process '%s' with pid '%i'", argv[0], pid);
		*child_pid_ptr = pid;
		return 0;
	}
}

void print_usage(char* const name, FILE* const file) {
	fprintf(file, "%s (%s)\n", basename(name), TINI_VERSION_STRING);

#if TINI_MINIMAL
	fprintf(file, "Usage: %s PROGRAM [ARGS] | --version\n\n", basename(name));
#else
	fprintf(file, "Usage: %s [OPTIONS] PROGRAM -- [ARGS] | --version\n\n", basename(name));
#endif
	fprintf(file, "Execute a program under the supervision of a valid init process (%s)\n\n", basename(name));

	fprintf(file, "Command line options:\n\n");

	fprintf(file, "  --version: Show version and exit.\n");

#if TINI_MINIMAL
#else
	fprintf(file, "  -h: Show this help message and exit.\n");
#if HAS_SUBREAPER
	fprintf(file, "  -s: Register as a process subreaper (requires Linux >= 3.4).\n");
#endif
	fprintf(file, "  -v: Generate more verbose output. Repeat up to 3 times.\n");
	fprintf(file, "  -g: Send signals to the child's process group.\n");
	fprintf(file, "  -l: Show license and exit.\n");
#endif

	fprintf(file, "\n");

	fprintf(file, "Environment variables:\n\n");
#if HAS_SUBREAPER
	fprintf(file, "  %s: Register as a process subreaper (requires Linux >= 3.4)\n", SUBREAPER_ENV_VAR);
#endif
	fprintf(file, "  %s: Set the verbosity level (default: %d)\n", VERBOSITY_ENV_VAR, DEFAULT_VERBOSITY);

	fprintf(file, "\n");
}

void print_license(FILE* const file) {
    if(LICENSE_len > fwrite(LICENSE, sizeof(char), LICENSE_len, file)) {
        // Don't handle this error for now, since parse_args won't care
        // about the return value. We do need to check it to compile with
        // older glibc, though.
        // See: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=25509
        // See: http://sourceware.org/bugzilla/show_bug.cgi?id=11959
    }
}

int parse_args(const int argc, char* const argv[], char* (**child_args_ptr_ptr)[], int* const parse_fail_exitcode_ptr) {
	char* name = argv[0];

	// We handle --version if it's the *only* argument provided.
	if (argc == 2 && strcmp("--version", argv[1]) == 0) {
		*parse_fail_exitcode_ptr = 0;
		fprintf(stdout, "%s\n", TINI_VERSION_STRING);
		return 1;
	}

#ifndef TINI_MINIMAL
	int c;
	while ((c = getopt(argc, argv, OPT_STRING)) != -1) {
		switch (c) {
			case 'h':
				print_usage(name, stdout);
				*parse_fail_exitcode_ptr = 0;
				return 1;
#if HAS_SUBREAPER
			case 's':
				subreaper++;
				break;
#endif
			case 'v':
				verbosity++;
				break;

			case 'g':
				kill_process_group++;
				break;

			case 'l':
				print_license(stdout);
				*parse_fail_exitcode_ptr = 0;
				return 1;

			case '?':
				print_usage(name, stderr);
				return 1;
			default:
				/* Should never happen */
				return 1;
		}
	}
#endif

	*child_args_ptr_ptr = calloc(argc-optind+1, sizeof(char*));
	if (*child_args_ptr_ptr == NULL) {
		PRINT_FATAL("Failed to allocate memory for child args: '%s'", strerror(errno));
		return 1;
	}

	int i;
	for (i = 0; i < argc - optind; i++) {
		(**child_args_ptr_ptr)[i] = argv[optind+i];
	}
	(**child_args_ptr_ptr)[i] = NULL;

	if (i == 0) {
		/* User forgot to provide args! */
		print_usage(name, stderr);
		return 1;
	}

	return 0;
}

int parse_env() {
#if HAS_SUBREAPER
	if (getenv(SUBREAPER_ENV_VAR) != NULL) {
		subreaper++;
	}
#endif

	char* env_verbosity = getenv(VERBOSITY_ENV_VAR);
	if (env_verbosity != NULL) {
		verbosity = atoi(env_verbosity);
	}

	return 0;
}


#if HAS_SUBREAPER
int register_subreaper () {
	if (subreaper > 0) {
		if (prctl(PR_SET_CHILD_SUBREAPER, 1)) {
			if (errno == EINVAL) {
				PRINT_FATAL("PR_SET_CHILD_SUBREAPER is unavailable on this platform. Are you using Linux >= 3.4?")
			} else {
				PRINT_FATAL("Failed to register as child subreaper: %s", strerror(errno))
			}
			return 1;
		} else {
			PRINT_TRACE("Registered as child subreaper");
		}
	}
	return 0;
}
#endif


void reaper_check () {
	/* Check that we can properly reap zombies */
#if HAS_SUBREAPER
	int bit = 0;
#endif

	if (getpid() == 1) {
		return;
	}

#if HAS_SUBREAPER
	if (prctl(PR_GET_CHILD_SUBREAPER, &bit)) {
		PRINT_DEBUG("Failed to read child subreaper attribute: %s", strerror(errno));
	} else if (bit == 1) {
		return;
	}
#endif

	PRINT_WARNING(reaper_warning);
}


int configure_signals(sigset_t* const parent_sigset_ptr, const signal_configuration_t* const sigconf_ptr) {
	/* Block all signals that are meant to be collected by the main loop */
	if (sigfillset(parent_sigset_ptr)) {
		PRINT_FATAL("sigfillset failed: '%s'", strerror(errno));
		return 1;
	}

	// These ones shouldn't be collected by the main loop
	uint i;
	int signals_for_tini[] = {SIGFPE, SIGILL, SIGSEGV, SIGBUS, SIGABRT, SIGTRAP, SIGSYS, SIGTTIN, SIGTTOU};
	for (i = 0; i < ARRAY_LEN(signals_for_tini); i++) {
		if (sigdelset(parent_sigset_ptr, signals_for_tini[i])) {
			PRINT_FATAL("sigdelset failed: '%i'", signals_for_tini[i]);
			return 1;
		}
	}

	if (sigprocmask(SIG_SETMASK, parent_sigset_ptr, sigconf_ptr->sigmask_ptr)) {
		PRINT_FATAL("sigprocmask failed: '%s'", strerror(errno));
		return 1;
	}

	// Handle SIGTTIN and SIGTTOU separately. Since Tini makes the child process group
	// the foreground process group, there's a chance Tini can end up not controlling the tty.
	// If TOSTOP is set on the tty, this could block Tini on writing debug messages. We don't
	// want that. Ignore those signals.
	struct sigaction ign_action;
	memset(&ign_action, 0, sizeof ign_action);

	ign_action.sa_handler = SIG_IGN;
	sigemptyset(&ign_action.sa_mask);

	if (sigaction(SIGTTIN, &ign_action, sigconf_ptr->sigttin_action_ptr)) {
		PRINT_FATAL("Failed to ignore SIGTTIN");
		return 1;
	}

	if (sigaction(SIGTTOU, &ign_action, sigconf_ptr->sigttou_action_ptr)) {
		PRINT_FATAL("Failed to ignore SIGTTOU");
		return 1;
	}

	return 0;
}


//int reap_zombies(const pid_t child_pid, int* const child_exitcode_ptr) {
int reap_zombies(int* const child_exitcode_ptr) {
	pid_t current_pid;
	int current_status=1; // current_status not only used to keep info
	                      // about exited process, but also to indicate
	                      // if we expect a zombie to exist.

	while (current_status) {
		current_pid = waitpid(-1, &current_status, WNOHANG);

		switch (current_pid) {

			case -1:
				if (errno == ECHILD) {
					PRINT_TRACE("No child to wait");
					current_status=0;
					break;
				}
				PRINT_FATAL("Error while waiting for pids: '%s'", strerror(errno));
				return 1;

			case 0:
				PRINT_TRACE("No child to reap");
				current_status=0;
				break;

			default:
				/* A child was reaped. Check whether it's the
				 * main one. If it is, then set the exit_code,
				 * which will cause us to exit once we've reaped
				 * everyone else.
				 */
				PRINT_DEBUG("Reaped child with pid: '%i'", current_pid);
//				if (current_pid == child_pid) {
					if (WIFEXITED(current_status)) {
						/* Our process exited normally. */
						PRINT_INFO("Child %d exited normally (with status '%i')", current_pid, WEXITSTATUS(current_status));
						*child_exitcode_ptr = WEXITSTATUS(current_status);
					} else if (WIFSIGNALED(current_status)) {
						/* Our process was terminated. Emulate what sh / bash
						 * would do, which is to return 128 + signal number.
						 */
						PRINT_INFO("Child %d exited (with signal '%s')", current_pid, strsignal(WTERMSIG(current_status)));
						*child_exitcode_ptr = 128 + WTERMSIG(current_status);
					} else {
						PRINT_FATAL("Child %d exited for unknown reason", current_pid);
						return 1;
					}
//				}
				// Check if other childs have been reaped.
				current_status=1;
				continue;
		}

		/* If we make it here, that's because we did not continue in the switch case. */
		break;
	}

	return 0;
}

int check_pid(char* dirent_name, pid_t* parent) {
// If caller wants not only check if this entry in /proc na s valid PID,
// but also to find its parent's PID, then parent must be non-null value
// pointing to area allocated in advance.
	int result=1;
	int count=0;
	int commlgt=0;
	char procdatafname[24]="/proc/";
	// "/proc/"(6 chars) + PID(max. 7 digits) + "/cmdline"(8 chars) + NULL
	// + some contingencies ;)
	char buffer_string[32];
	// PID (max. 7 digits) + space + ( + comm (max. 16 chars) + ) + space
	// + NULL + some contingencies
	char onechar;
	FILE *procdatafile;
	///PRINT_DEBUG("Started check_pid for /proc/%s",dirent_name);
	while( result!=0 && dirent_name[count]!=0) {
		///PRINT_TRACE("checking %d char '%c'(%d)",count,dirent_name[count],dirent_name[count]);
		// Hope, this is cheaper than atoi - we only check, not parse.
		if(dirent_name[count]<48 || dirent_name[count]>57) {
			///PRINT_TRACE("Non-numeric char %d at position %d - not a PID",dirent_name[count],count);
			result=0;
		} else {
			procdatafname[6+count]=dirent_name[count];
			count++;
			procdatafname[6+count]=0; // Keep this inside loop in order to
			                          // have valid null-terminated string
			                          // for diagnostic printing.
			///PRINT_TRACE("Building PID directory, chars parsed: %d, dirname: '%s'.",count+1,procdatafname);
		}
	} // "while" loop over chars in dirent_name
	if (result==1) {
		strcpy(procdatafname+6+count,"/cmdline");
		///PRINT_TRACE("Going to check if command line in '%s' is non-empty.",procdatafname);
		procdatafile=fopen(procdatafname,"r");
		if (procdatafile==NULL) {
			///PRINT_DEBUG("Failed to open '%s'",procdatafname);
			result=0;
		} else {
			onechar=fgetc(procdatafile);
			if (feof(procdatafile)) {
				///PRINT_TRACE("%s is empty",procdatafname);
				fclose(procdatafile);
				result=0;
			} else {
				//while (!feof(procdatafile) && onechar!='\n') {
				//	PRINT_TRACE("Read from %s: %c",procdatafname,onechar);
				//	onechar=fgetc(procdatafile);
				//}
				fclose(procdatafile);
				// cmdline is not empty, now check that state in
				// /proc/PID/stat is neither "zombie" nor "dead".
				// To do that we first obtain command from /proc/PID/comm.
				// Together with PID it gives a string that precedes
				// the state character in /proc/PID/stat. Having built
				// the string, we will traverse stat file char-by-char,
				// to find the state char.
				strcpy(procdatafname+6+count,"/comm");
				///PRINT_DEBUG("Going to read command from '%s'",procdatafname);
				procdatafile=fopen(procdatafname,"r");
				if (procdatafile==NULL) {
					///PRINT_DEBUG("failed open %s",procdatafname);
					result=0;
				} else {
					// going to build the string that should
					// preceed "State" field in /proc/PID/stat
					strcpy(buffer_string,dirent_name);
					buffer_string[count]=32;
					buffer_string[count+1]='(';
					commlgt=count+2;
					onechar=fgetc(procdatafile);
					while (!feof(procdatafile) && onechar!='\n') {
						buffer_string[commlgt]=onechar;
						onechar=fgetc(procdatafile);
						commlgt++;
						buffer_string[commlgt]=0;
						///PRINT_TRACE("Chars read: %d; buffer_string='%s'",commlgt+1,buffer_string);
					}
					buffer_string[commlgt]=')';
					commlgt++;
					buffer_string[commlgt]=' ';
					commlgt++;
					buffer_string[commlgt]=0;
					///PRINT_DEBUG("Resulting buffer_string='%s', length=%d",buffer_string,commlgt);
					strcpy(procdatafname+6+count,"/stat");
					///PRINT_DEBUG("Going to read stat file '%s'",procdatafname);
					procdatafile=fopen(procdatafname,"r");
					if(procdatafile==NULL){
						///PRINT_DEBUG("Failed to open '%s'",procdatafname);
						result=0;
					} else {
						onechar=fgetc(procdatafile);
						count=0;
						///PRINT_TRACE("start scanning %s",procdatafname);
						while ( count<commlgt && result==1) {
							if(onechar!=buffer_string[count] || feof(procdatafile)){
								///PRINT_DEBUG("Unexpected EOF or unmatched char at position %d: expected '%c', found '%c'",count,buffer_string[count],onechar);
								result=0;
							} else {
								///PRINT_TRACE("Read char '%c' - ok",onechar);
								onechar=fgetc(procdatafile);
								count++;
							}
						} // loop over chars in buffer_string
						// Our Holy Grail
						///PRINT_DEBUG("Process state char: '%c'",onechar);
						if (onechar=='Z' || onechar=='X' || onechar=='x' ) {
							///PRINT_DEBUG("Process '%s' is zombie or dead",dirent_name);
							result=0;
						} else {
							PRINT_INFO("Found alive process: '%s'",dirent_name);
							if (parent!=NULL) {
								onechar=fgetc(procdatafile); // space
								onechar=fgetc(procdatafile); // first digit of PPID
								count=0;
								while (onechar!=' ') {
									buffer_string[count]=onechar;
									onechar=fgetc(procdatafile);
									count++;
								}
								buffer_string[count]=0;
								PRINT_DEBUG("For child '%s' parent PID string: '%s'",dirent_name,buffer_string);
								*parent=parse_pid(buffer_string);
								PRINT_DEBUG("Parsed to number: '%d'",*parent);
							} // if we need PPID
						} // if neither zombie nor dead
					} // if pointer to stat file is not NULL
				} // if pointer to comm file is not NULL
			} // if cmdline file is not empty
		} // if pointer to cmdline file is not NULL
	} // if dirent_name consists of digits only
	return result;
}


int main(int argc, char *argv[]) {
	pid_t child_pid, parent_pid, my_pid=getpid();
	siginfo_t signal_info;

	// Those are passed to functions to get an exitcode back.
	int child_exitcode = -1;  // This isn't a valid exitcode, and lets us tell whether the child has exited.
	int parse_exitcode = 1;   // By default, we exit with 1 if parsing fails.

	int alive_posterity;
	DIR *procdir;
	struct dirent *diritem;

	if (sizeof(pid_t)==sizeof(int)) {
		parse_pid=(pid_t(*)(char*))atoi;
	} else if (sizeof(pid_t)==sizeof(long)) {
		parse_pid=(pid_t(*)(char*))atol;
	}else if (sizeof(pid_t)==sizeof(long long)) {
		parse_pid=(pid_t(*)(char*))atoll;
	} else {
		PRINT_FATAL("Don't know how to parse PID strings\n");
		return 1;
	}

	// Check if /proc is mounted, try to mount if it is not.
	struct statfs *fsdata=(struct statfs *)malloc(sizeof(struct statfs));
	if (statfs("/proc", fsdata)!=0) {
		PRINT_FATAL("Could not check if /proc is mounted");
		return 1;
	}
	if (fsdata->f_type!=0x9fa0) {
		PRINT_INFO("/proc is not of type 0x9fa0 - trying to mount");
		if (mount ("proc","/proc","proc",0,"")!=0){
			PRINT_FATAL("Mount /proc failed");
			return 1;
		}
	}
	free(fsdata);
	procdir=opendir("/proc");
	if (procdir==NULL){
		PRINT_FATAL("Failed to open /proc");
		return 1;
	}

	/* Parse command line arguments */
	char* (*child_args_ptr)[];
	int parse_args_ret = parse_args(argc, argv, &child_args_ptr, &parse_exitcode);
	if (parse_args_ret) {
		return parse_exitcode;
	}

	/* Parse environment */
	if (parse_env()) {
		return 1;
	}

	/* Configure signals */
	sigset_t parent_sigset, child_sigset;
	struct sigaction sigttin_action, sigttou_action;
	memset(&sigttin_action, 0, sizeof sigttin_action);
	memset(&sigttou_action, 0, sizeof sigttou_action);

	signal_configuration_t child_sigconf = {
		.sigmask_ptr = &child_sigset,
		.sigttin_action_ptr = &sigttin_action,
		.sigttou_action_ptr = &sigttou_action,
	};

	if (configure_signals(&parent_sigset, &child_sigconf)) {
		return 1;
	}

#if HAS_SUBREAPER
	/* If available and requested, register as a subreaper */
	if (register_subreaper()) {
		return 1;
	};
#endif

	/* Are we going to reap zombies properly? If not, warn. */
	reaper_check();

	/* Go on */
	int spawn_ret = spawn(&child_sigconf, *child_args_ptr, &child_pid);
	if (spawn_ret) {
		return spawn_ret;
	}
	PRINT_DEBUG("Spawned child '%s' PID=%d",(*child_args_ptr)[0],child_pid);
	free(child_args_ptr);

	while (1) {
		/* Wait for one signal, and forward it */
		if (sigtimedwait(&parent_sigset, &signal_info, &ts) == -1) {
			if (errno!=EAGAIN && errno!=EINTR) {
				PRINT_FATAL("Unexpected error in sigtimedwait: '%s'", strerror(errno));
				return 1;
			}
		} else {
			if (signal_info.si_signo!=SIGCHLD) {
				PRINT_INFO("Received signal %s(%d)",strsignal(signal_info.si_signo),signal_info.si_signo);
				rewinddir(procdir);
				errno=0;
				diritem=readdir(procdir);
				while (diritem!=NULL) {
					if(diritem->d_type==DT_DIR) {
						///PRINT_DEBUG("Checking /proc/%s\n",diritem->d_name);
						if (check_pid(diritem->d_name,&parent_pid)) {
							///PRINT_DEBUG("Found alive process PID=%s, PPID=%d",diritem->d_name,parent_pid);
							if (parent_pid==my_pid) {
								// This is our direct child,
								// send the signal to it
								PRINT_DEBUG("Passing signal '%s' to proc %s", strsignal(signal_info.si_signo),diritem->d_name);
								child_pid=parse_pid(diritem->d_name);
								PRINT_DEBUG("Going to send signal %s(%d) to PID %d, group=%d",strsignal(signal_info.si_signo),signal_info.si_signo,child_pid,kill_process_group);
								if (kill(kill_process_group ? -child_pid : child_pid, signal_info.si_signo)) {
									if (errno == ESRCH) {
										PRINT_WARNING("Child was dead when forwarding signal");
									} else {
										PRINT_FATAL("Unexpected error when forwarding signal: '%s'", strerror(errno));
										return 1;
									}
								}
							}
						} //if check_pid returns non-zero
					} // if item is a dir
					diritem=readdir(procdir);
				} // while(diritem!=NULL)
				if (errno!=0){
					// something wrong occured
					PRINT_DEBUG("Error '%s' occured while scanning /proc - ignoring",strerror(errno));
					errno=0;
				}
			} else {
			PRINT_DEBUG("Received SIGCHLD");
			}
	}
		/* Now, reap zombies */
		child_exitcode=-1;
		if (reap_zombies(&child_exitcode)) {
			return 1;
		}
		if (child_exitcode != -1) {
			// If child_exitcode was assigned to WEXITSTATUS or WTERMSIG,
			// i.e. if at least one child was reaped successfully
			// Here we look into /proc for forked processes and check
			// if they are zombies or not
			alive_posterity=0;
			child_pid=0; // 0 is kernel but we don't care ;)
			rewinddir(procdir);
			errno=0;
			diritem=readdir(procdir);
			while(diritem!=NULL){
				if(diritem->d_type==DT_DIR) {
					///PRINT_DEBUG("Checking /proc/%s\n",diritem->d_name);
					if (check_pid(diritem->d_name,NULL)) {
						///PRINT_DEBUG("Found alive process PID=%s",diritem->d_name);
						if (parse_pid(diritem->d_name)==my_pid) {
							PRINT_DEBUG("%s - it's me.",diritem->d_name);
						} else {
							alive_posterity++;
							// Setting alive_posterity to 1
							// might be enough, and testing
							// it coupled with (diritem!=NULL)
							// would stop the loop and avoid
							// useless cycles, but counting
							// alive processes may be useful
							// for diagnostics.
							if(child_pid==0) {
								// readdir(3) gives entries "as is",
								// i.e. no sorting is done,
								// but I see that PIDs are processed
								// in order.
								child_pid=parse_pid(diritem->d_name);
							}
						} // if is't me
					} //if check_pid returns non-zero
				} // if item is a dir
				diritem=readdir(procdir);
			} // while(diritem!=NULL)
			if (errno!=0){
				// something wrong occured
				PRINT_DEBUG("An error occured while scanning /proc - ignoring");
				errno=0;
				//PRINT_DEBUG("Error occured while scanning /proc - discarding result");
				//alive_posterity=0;
			}
			if (alive_posterity==0) {
				PRINT_TRACE("Exiting: no children left");
				return child_exitcode;
			}
		}
	}
}
