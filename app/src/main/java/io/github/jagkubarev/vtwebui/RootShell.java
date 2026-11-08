package io.github.jagkubarev.vtwebui;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Один постоянный root-шелл (как libsu): `su` запускается один раз, команды идут
 * в его stdin по очереди. Зачем не `su -c` на каждую команду:
 *  - Magisk по умолчанию показывает тост «получил права root» на каждый запуск su,
 *    а страница опрашивает статус раз в 3 с;
 *  - запуск su на MT6580 — заметная пауза.
 * Каждая команда — в подшелле ( … ) со stdin из /dev/null: exit/cd внутри не
 * трогают общий шелл, а команда не съест следующие строки скрипта. Конец вывода
 * отмечается случайной меткой в stdout (с кодом возврата) и в stderr.
 * Методы synchronized: команды строго по одной, как ksu.exec в KernelSU.
 */
final class RootShell {
    static final class Result {
        final int code;
        final String out, err;
        Result(int code, String out, String err) { this.code = code; this.out = out; this.err = err; }
    }

    private static final class Raw {
        final byte[] out;   // null — шелл не ответил / не запустился
        final int code;
        final String err;
        Raw(byte[] out, int code, String err) { this.out = out; this.code = code; this.err = err; }
    }

    private static final String[] SU = { "su", "/system/bin/su", "/system/xbin/su", "/sbin/su", "/debug_ramdisk/su" };

    private Process proc;
    private OutputStream in;
    private Drain out, err;

    /** Читает поток в буфер в своём потоке: иначе большой stderr забьёт трубу, пока ждём stdout. */
    private static final class Drain extends Thread {
        private final InputStream s;
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        private boolean eof;
        byte[] body;   // вывод до метки
        String tail;   // остаток строки метки (код возврата)

        Drain(InputStream s) { this.s = s; setDaemon(true); }

        @Override public void run() {
            byte[] b = new byte[8192];
            try {
                int n;
                while ((n = s.read(b)) > 0) synchronized (this) { buf.write(b, 0, n); notifyAll(); }
            } catch (IOException ignored) { }
            synchronized (this) { eof = true; notifyAll(); }
        }

        /** Ждёт "\n" + mark [+ " код"] + "\n" до deadline; true — дождались (body/tail заполнены). */
        synchronized boolean await(String mark, long deadline) throws InterruptedException {
            byte[] m = ("\n" + mark).getBytes(StandardCharsets.US_ASCII);
            while (true) {
                byte[] a = buf.toByteArray();
                int i = indexOf(a, m);
                if (i >= 0) {
                    int e = i + m.length;
                    while (e < a.length && a[e] != '\n') e++;
                    if (e < a.length) {   // строка метки дочитана
                        body = Arrays.copyOf(a, i);
                        tail = new String(a, i + m.length, e - i - m.length, StandardCharsets.US_ASCII).trim();
                        buf.reset();
                        buf.write(a, e + 1, a.length - e - 1);
                        return true;
                    }
                }
                if (eof) return false;
                long w = deadline - System.currentTimeMillis();
                if (w <= 0) return false;
                wait(w);
            }
        }

        private static int indexOf(byte[] a, byte[] m) {
            outer:
            for (int i = 0; i + m.length <= a.length; i++) {
                for (int j = 0; j < m.length; j++) if (a[i + j] != m[j]) continue outer;
                return i;
            }
            return -1;
        }
    }

    private void start() throws IOException {
        IOException last = null;
        for (String su : SU) {
            try {
                proc = new ProcessBuilder(su).start();
                break;
            } catch (IOException e) { last = e; proc = null; }
        }
        if (proc == null) throw last != null ? last : new IOException("su не найден");
        in = proc.getOutputStream();
        out = new Drain(proc.getInputStream()); out.start();
        err = new Drain(proc.getErrorStream()); err.start();
    }

    private void kill() {
        if (proc != null) proc.destroy();
        proc = null; in = null; out = null; err = null;
    }

    private static boolean alive(Process p) {
        try { p.exitValue(); return false; } catch (IllegalThreadStateException e) { return true; }
    }

    private Raw runRaw(String script, long timeoutSec) {
        try {
            if (proc == null || !alive(proc)) { kill(); start(); }
            String mark = "__VT_END_" + UUID.randomUUID().toString().replace("-", "") + "__";
            // printf '\n…': метка с новой строки, даже если вывод команды без \n в конце
            String s = "(\n" + script + "\n) </dev/null\n"
                    + "printf '\\n%s %s\\n' " + mark + " $?\n"
                    + "printf '\\n%s\\n' " + mark + " >&2\n";
            in.write(s.getBytes(StandardCharsets.UTF_8));
            in.flush();
            long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(timeoutSec);
            if (!out.await(mark, deadline) || !err.await(mark, deadline)) {
                boolean dead = !alive(proc);
                kill();
                return new Raw(null, dead ? 1 : 124, dead ? "root-шелл закрылся (нет root или доступ отозван)" : "команда не ответила за " + timeoutSec + " с");
            }
            int code;
            try { code = Integer.parseInt(out.tail); } catch (NumberFormatException x) { code = 1; }
            return new Raw(out.body, code, new String(err.body, StandardCharsets.UTF_8));
        } catch (IOException x) {
            kill();
            return new Raw(null, 1, "нет root: " + x.getMessage());
        } catch (InterruptedException x) {
            Thread.currentThread().interrupt();
            return new Raw(null, 1, "прервано");
        }
    }

    /** Выполнить скрипт; timeoutSec — сколько ждать, потом шелл убивается и код 124. */
    synchronized Result run(String script, long timeoutSec) {
        Raw r = runRaw(script, timeoutSec);
        String o = r.out == null ? "" : chop(new String(r.out, StandardCharsets.UTF_8));
        return new Result(r.code, o, chop(r.err));
    }

    /** Как libsu в KernelSU: строки через \n, без перевода строки в конце. */
    private static String chop(String s) {
        return s.endsWith("\n") ? s.substring(0, s.length() - 1) : s;
    }

    /** Файл через root целиком, байт в байт (для webroot). null — не прочитался. */
    synchronized byte[] readFile(String path) {
        // cat, а не base64: base64 в toybox Android 8 есть не везде (см. webctl.sh)
        String p = "'" + path.replace("'", "'\\''") + "'";
        Raw r = runRaw("[ -f " + p + " ] && cat " + p, 60);
        return r.out != null && r.code == 0 ? r.out : null;
    }

    synchronized void close() { kill(); }
}
