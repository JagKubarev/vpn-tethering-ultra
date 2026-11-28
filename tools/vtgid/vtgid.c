// vtgid — запуск команды с группой GID при том же uid (VPN Tethering Ultra, GPL-3.0).
// Замена `su -g GID -c КОМАНДА` там, где su её не умеет (Magisk старше 26: MT6580, Magisk 25.2):
// dnsproxy, opera-proxy и проверки модуля идут со своей группой — по ней их узнают правила
// (мимо перехвата DNS, мимо прокси AdGuard), а не по uid 0, под которым ходит и системный резолвер.
//   vtgid GID -c КОМАНДА   ->   setgroups(0), setresgid(GID), exec /system/bin/sh -c КОМАНДА
// Вторая форма (28.11, MASQUE): ещё uid и дополнительные группы — usque идёт от uid 1000 (от root его UDP 443
// режет AdGuard), а на ядрах 3.x без группы inet (3003) не-root не откроет и сокет («permission denied», MT6580).
// su этого не умеет везде одинаково (Magisk 25 — ни -g, ни -G):
//   vtgid GID UID G1[,G2…] -c КОМАНДА   ->   setgroups(G1,G2…), setresgid(GID), setresuid(UID), exec sh -c
// Коды: 126 — не сменить группу или uid, 127 — неверный вызов или не запустить sh; иначе — код команды.
#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int num(const char *s, long *v)
{
	char *end;

	errno = 0;
	*v = strtol(s, &end, 10);
	// до 2^31−1: uid приложений второго пользователя и клонов — N*100000 + appId (ревью 28.11: было до 65535)
	return !(errno || *end || end == s || *v < 0 || *v > 2147483647L);
}

int main(int argc, char **argv)
{
	long g, u = -1, x;
	gid_t sup[16];
	int n = 0;
	char *p, *q, buf[128];

	if (!((argc == 4 && strcmp(argv[2], "-c") == 0) || (argc == 6 && strcmp(argv[4], "-c") == 0))) {
		fprintf(stderr, "usage: vtgid GID -c COMMAND | vtgid GID UID G1[,G2...] -c COMMAND\n");
		return 127;
	}
	if (!num(argv[1], &g) || g == 0) {
		fprintf(stderr, "vtgid: bad GID %s\n", argv[1]);
		return 127;
	}
	if (argc == 6) {
		if (!num(argv[2], &u) || u == 0) {
			fprintf(stderr, "vtgid: bad UID %s\n", argv[2]);
			return 127;
		}
		if (strlen(argv[3]) >= sizeof(buf)) {
			fprintf(stderr, "vtgid: groups too long\n");
			return 127;
		}
		strcpy(buf, argv[3]);
		for (p = strtok_r(buf, ",", &q); p; p = strtok_r(NULL, ",", &q)) {
			if (n >= 16 || !num(p, &x)) {
				fprintf(stderr, "vtgid: bad groups %s\n", argv[3]);
				return 127;
			}
			sup[n++] = (gid_t)x;
		}
	}
	if (setgroups((size_t)n, n ? sup : NULL) != 0 || setresgid((gid_t)g, (gid_t)g, (gid_t)g) != 0) {
		perror("vtgid");
		return 126;
	}
	if (u > 0 && setresuid((uid_t)u, (uid_t)u, (uid_t)u) != 0) {
		perror("vtgid");
		return 126;
	}
	execl("/system/bin/sh", "sh", "-c", argv[argc - 1], (char *)NULL);
	perror("vtgid: exec /system/bin/sh");
	return 127;
}
