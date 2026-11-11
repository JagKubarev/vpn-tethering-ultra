package io.github.jagkubarev.vpntether;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.text.TextUtils;
import android.view.View;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Объект `ksu` для страницы — то же, что даёт менеджер KernelSU
 * (KernelSU manager WebViewInterface, KsuWebUIStandalone, оба GPL-3.0):
 * exec, toast, fullScreen, moduleInfo, listPackages, getPackagesInfo.
 * Отличие: exec(cmd, options, callback) не держит страницу — команда уходит в
 * свою очередь (по одной, порядок как у KernelSU), ответ — через callback.
 */
final class KsuBridge {
    // Долгое страница запускает в фоне (ctlBg: команда в фоне + опрос раз в 0,5 с),
    // синхронные ctl короткие; самые долгие — warp-save/warp-import (запрос к Cloudflare).
    // Больше 2 мин — зависла: шелл перезапускается, очередь идёт дальше.
    private static final long TIMEOUT_SEC = 120;

    private final Activity act;
    private final WebView web;
    private final RootShell sh;
    private final String modDir;
    private final ExecutorService queue = Executors.newSingleThreadExecutor();

    /** Команда в очереди и все, кто ждёт её ответа. */
    private static final class Job {
        final String script;
        final List<String> cbs = new ArrayList<>();
        Job(String script) { this.script = script; }
    }
    /** Последняя поставленная и ещё не начатая команда: точно такая же следом — склеивается с ней. */
    private Job tail;
    private volatile boolean closed;

    KsuBridge(Activity act, WebView web, RootShell sh, String modDir) {
        this.act = act; this.web = web; this.sh = sh; this.modDir = modDir;
    }

    /** Окно закрывается: идущая команда доработает (не рвём на полпути), ждущие не начнутся. */
    void close() {
        closed = true;
        queue.shutdown();
    }

    private static String withOptions(String cmd, String options) {
        StringBuilder sb = new StringBuilder();
        if (!TextUtils.isEmpty(options)) {
            try {
                JSONObject o = new JSONObject(options);
                String cwd = o.optString("cwd");
                if (!TextUtils.isEmpty(cwd)) sb.append("cd ").append(RootShell.quote(cwd)).append(" || exit 1\n");
                JSONObject env = o.optJSONObject("env");
                if (env != null) for (Iterator<String> it = env.keys(); it.hasNext(); ) {
                    String k = it.next();
                    if (!k.matches("[A-Za-z_][A-Za-z0-9_]*")) continue;   // не имя переменной — не код
                    sb.append("export ").append(k).append('=').append(RootShell.quote(env.optString(k))).append('\n');
                }
            } catch (JSONException ignored) { }
        }
        return sb.append(cmd).toString();
    }

    /** Синхронно, но через ту же очередь — не обгоняет команды, отправленные раньше. */
    @JavascriptInterface
    public String exec(final String cmd) {
        try {
            return queue.submit(() -> sh.run(cmd, TIMEOUT_SEC).out).get();
        } catch (Exception e) {
            return "";
        }
    }

    @JavascriptInterface
    public void exec(String cmd, String callback) { exec(cmd, null, callback); }

    @JavascriptInterface
    public void exec(String cmd, String options, String callback) {
        final String script = withOptions(cmd, options);
        // Таймеры страницы (статистика WARP раз в 3 с, клиенты, конфиги) не ждут
        // ответа: пока медленная команда держит очередь, повтор подряд склеивается с
        // последней ждущей. Только с последней — иначе «вкл, выкл, вкл» стало бы
        // «вкл, выкл» и порядок разошёлся бы с KernelSU.
        final Job job;
        synchronized (this) {
            if (tail != null && tail.script.equals(script)) { tail.cbs.add(callback); return; }
            job = new Job(script);
            job.cbs.add(callback);
            tail = job;
        }
        try {
            queue.execute(() -> {
                List<String> cbs;
                synchronized (KsuBridge.this) {
                    if (tail == job) tail = null;   // началась — к ней больше не клеим
                    cbs = new ArrayList<>(job.cbs);
                }
                if (closed) return;
                RootShell.Result r = sh.run(script, TIMEOUT_SEC);
                if (closed) return;
                String args = r.code + "," + JSONObject.quote(r.out) + "," + JSONObject.quote(r.err);
                StringBuilder js = new StringBuilder();
                for (String cb : cbs) js.append("(function(){try{").append(cb).append('(').append(args).append(");}catch(e){console.error(e);}})();");
                web.post(() -> web.evaluateJavascript(js.toString(), null));
            });
        } catch (java.util.concurrent.RejectedExecutionException e) {   // окно уже закрывается
            synchronized (this) { if (tail == job) tail = null; }
        }
    }

    @JavascriptInterface
    public void toast(final String msg) {
        act.runOnUiThread(() -> Toast.makeText(act, msg, Toast.LENGTH_SHORT).show());
    }

    @JavascriptInterface
    @SuppressWarnings("deprecation")
    public void fullScreen(final boolean on) {
        act.runOnUiThread(() -> act.getWindow().getDecorView().setSystemUiVisibility(on
                ? View.SYSTEM_UI_FLAG_FULLSCREEN | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION | View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                : 0));
    }

    @JavascriptInterface
    public String moduleInfo() {
        JSONObject o = new JSONObject();
        try {
            o.put("moduleDir", modDir);
            o.put("id", modDir.substring(modDir.lastIndexOf('/') + 1));
        } catch (JSONException ignored) { }
        return o.toString();
    }

    /** 'user' — установленные пользователем, 'system' — из прошивки, иначе все. */
    @JavascriptInterface
    public String listPackages(String type) {
        JSONArray a = new JSONArray();
        List<PackageInfo> list = act.getPackageManager().getInstalledPackages(0);
        for (PackageInfo p : list) {
            boolean sys = p.applicationInfo != null && (p.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if ("user".equals(type) && sys) continue;
            if ("system".equals(type) && !sys) continue;
            a.put(p.packageName);
        }
        return a.toString();
    }

    @JavascriptInterface
    @SuppressWarnings("deprecation")
    public String getPackagesInfo(String json) {
        JSONArray res = new JSONArray();
        PackageManager pm = act.getPackageManager();
        try {
            JSONArray in = new JSONArray(json);
            for (int i = 0; i < in.length(); i++) {
                String pkg = in.optString(i);
                try {
                    PackageInfo p = pm.getPackageInfo(pkg, 0);
                    JSONObject o = new JSONObject();
                    o.put("packageName", p.packageName);
                    o.put("versionName", p.versionName == null ? "" : p.versionName);
                    o.put("versionCode", Build.VERSION.SDK_INT >= 28 ? p.getLongVersionCode() : p.versionCode);
                    ApplicationInfo ai = p.applicationInfo;
                    o.put("appLabel", ai == null ? pkg : String.valueOf(ai.loadLabel(pm)));
                    o.put("isSystem", ai != null && (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0);
                    o.put("uid", ai == null ? -1 : ai.uid);
                    res.put(o);
                } catch (PackageManager.NameNotFoundException ignored) { }
            }
        } catch (JSONException ignored) { }
        return res.toString();
    }
}
