#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <libgen.h>
/* Safe Box launcher: runs Contents/Resources/run.sh, so the app opens from Finder and the Dock. */
int main(void) {
    char p[4096]; uint32_t n = sizeof p;
    if (_NSGetExecutablePath(p, &n) != 0) return 1;
    char *d = dirname(dirname(p));            /* .../Contents */
    char s[4200]; snprintf(s, sizeof s, "%s/Resources/run.sh", d);
    execl("/bin/sh", "sh", s, (char *)0);
    perror("leviathan-safebox"); return 1;
}
