#include <libproc.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <sqlite3.h>
#include <zlib.h>
#include <unistd.h>

// Swift's Darwin overlay marks fork() unavailable. We need it for the
// `--exec` sync-gate pattern (fork → child blocks on pipe → parent registers
// PID with sysext → parent closes pipe → child execs). posix_spawn doesn't
// expose that gating point.
static inline pid_t tractor_fork(void) { return fork(); }
