// vtpoke — пустой TCP ACK со случайными seq/ack в чужие соединения (VPN Tethering Ultra, GPL-3.0).
// Сервер на пакет вне окна отвечает своим ACK (RFC 5961, challenge ACK; Linux — не чаще раза в 0,5 с на
// сокет), и по соединению идёт трафик в обе стороны: ТСПУ YOTA не забывает поток. Без этого после ~10 с
// тишины следующий запрос в соединении к Google остаётся без ответа (16.11: после 15 с простоя умерло
// 15 из 17 соединений, с пакетом раз в 3 с — 2 из 31; после 60 с — 23 из 23 и 6 из 24).
//   vtpoke ИФЕЙС SRC SPORT DST DPORT [SRC SPORT DST DPORT ...]   — по пакету в каждое
// Пакет — с меткой 0x40000000 (правила обхода модуля его пропускают), через ИФЕЙС (SO_BINDTODEVICE).
// Сборка: NDK, статически, armv7a/aarch64 android21 (см. tools/vtpoke/build.sh). Код выхода — сколько не ушло.
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static unsigned short csum(const void *p, int n, unsigned long s) {
    const unsigned short *w = p;
    for (; n > 1; n -= 2) s += *w++;
    if (n) s += *(const unsigned char *)w;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (unsigned short)~s;
}

int main(int argc, char **argv) {
    int one = 1, mark = 0x40000000, bad = 0;
    if (argc < 6 || (argc - 2) % 4) {
        fprintf(stderr, "vtpoke IFACE SRC SPORT DST DPORT [SRC SPORT DST DPORT ...]\n");
        return 255;
    }
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) { perror("socket"); return 255; }
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof one) < 0) { perror("hdrincl"); return 255; }
    if (setsockopt(s, SOL_SOCKET, SO_MARK, &mark, sizeof mark) < 0) perror("mark");
    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, argv[1], strlen(argv[1]) + 1) < 0) { perror("bind dev"); return 255; }
    srandom((unsigned)time(0) ^ (unsigned)getpid());
    for (int i = 2; i + 3 < argc; i += 4) {
        struct in_addr src, dst;
        int sp = atoi(argv[i + 1]), dp = atoi(argv[i + 3]);
        if (!inet_aton(argv[i], &src) || !inet_aton(argv[i + 2], &dst) || sp <= 0 || sp > 65535 || dp <= 0 || dp > 65535) { bad++; continue; }
        unsigned char pkt[40];
        struct iphdr *ip = (void *)pkt; struct tcphdr *th = (void *)(pkt + 20);
        memset(pkt, 0, sizeof pkt);
        ip->version = 4; ip->ihl = 5; ip->ttl = 64; ip->protocol = IPPROTO_TCP; ip->tot_len = htons(40);
        ip->frag_off = htons(IP_DF); ip->id = (unsigned short)random(); ip->saddr = src.s_addr; ip->daddr = dst.s_addr;
        ip->check = csum(ip, 20, 0);
        th->source = htons(sp); th->dest = htons(dp);
        th->seq = (unsigned)random() ^ ((unsigned)random() << 16); th->ack_seq = (unsigned)random() ^ ((unsigned)random() << 16);
        th->doff = 5; th->ack = 1; th->window = htons(65535);
        // псевдозаголовок для суммы TCP
        unsigned long ps = (src.s_addr & 0xffff) + (src.s_addr >> 16) + (dst.s_addr & 0xffff) + (dst.s_addr >> 16)
            + htons(IPPROTO_TCP) + htons(20);
        th->check = csum(th, 20, ps);
        struct sockaddr_in to = { .sin_family = AF_INET, .sin_addr = dst };
        if (sendto(s, pkt, sizeof pkt, 0, (struct sockaddr *)&to, sizeof to) < 0) bad++;
    }
    close(s);
    return bad > 254 ? 254 : bad;
}
