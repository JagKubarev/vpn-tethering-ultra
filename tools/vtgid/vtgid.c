// vtgid — запуск команды с группой GID при том же uid (VPN Tethering Ultra, GPL-3.0).
// Замена `su -g GID -c КОМАНДА` там, где su её не умеет (Magisk старше 26: MT6580, Magisk 25.2):
// dnsproxy, opera-proxy и проверки модуля идут со своей группой — по ней их узнают правила
// (мимо перехвата DNS, мимо прокси AdGuard), а не по uid 0, под которым ходит и системный резолвер.
//   vtgid GID -c КОМАНДА   ->   setgroups(0), setresgid(GID), exec /system/bin/sh -c КОМАНДА
// Коды: 126 — не сменить группу, 127 — неверный вызов или не запустить sh; иначе — код команды.
#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	char *end;
	long g;

	if (argc != 4 || strcmp(argv[2], "-c") != 0) {
		fprintf(stderr, "usage: vtgid GID -c COMMAND\n");
		return 127;
	}
	errno = 0;
	g = strtol(argv[1], &end, 10);
	if (errno || *end || g <= 0 || g > 65535) {
		fprintf(stderr, "vtgid: bad GID %s\n", argv[1]);
		return 127;
	}
	if (setgroups(0, NULL) != 0 || setresgid((gid_t)g, (gid_t)g, (gid_t)g) != 0) {
		perror("vtgid");
		return 126;
	}
	execl("/system/bin/sh", "sh", "-c", argv[3], (char *)NULL);
	perror("vtgid: exec /system/bin/sh");
	return 127;
}
