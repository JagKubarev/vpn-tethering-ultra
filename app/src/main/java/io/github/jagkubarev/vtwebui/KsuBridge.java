package io.github.jagkubarev.vtwebui;

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

import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Объект `ksu` для страницы — то же, что даёт менеджер KernelSU
 * (KernelSU manager WebViewInterface, KsuWebUIStandalone, оба GPL-3.0):
 * exec, toast, fullScreen, moduleInfo, listPackages, getPackagesInfo.
 * Отличие: exec(cmd, options, callback) не держит страницу — команда уходит в
 * свой поток (одна очередь, порядок как у KernelSU), ответ — через callback.
 */
final class KsuBridge {
    private static final long TIMEOUT_SEC = 300;   // ctlBg на стороне страницы ждёт 5 мин

    private final Activity act;
    private final WebView web;
    private final RootShell sh;
    private final String modDir;
    private final ExecutorService queue = Executors.newSingleThreadExecutor();

    KsuBridge(Activity act, WebView web, RootShell sh, String modDir) {
        this.act = act; this.web = web; this.sh = sh; this.modDir = modDir;
    }

    void shutdown() { queue.shutdownNow(); }

    private static String withOptions(String cmd, String options) {
        StringBuilder sb = new StringBuilder();
        if (!TextUtils.isEmpty(options)) {
            try {
                JSONObject o = new JSONObject(options);
                String cwd = o.optString("cwd");
                if (!TextUtils.isEmpty(cwd)) sb.append("cd ").append(cwd).append(";\n");
                JSONObject env = o.optJSONObject("env");
                if (env != null) for (Iterator<String> it = env.keys(); it.hasNext(); ) {
                    String k = it.next();
                    sb.append("export ").append(k).append('=').append(env.optString(k)).append(";\n");
                }
            } catch (JSONException ignored) { }
        }
        return sb.append(cmd).toString();
    }

    @JavascriptInterface
    public String exec(String cmd) {
        RootShell.Result r = sh.run(cmd, TIMEOUT_SEC);
        return r.out;
    }

    @JavascriptInterface
    public void exec(String cmd, String callback) { exec(cmd, null, callback); }

    @JavascriptInterface
    public void exec(final String cmd, final String options, final String callback) {
        queue.execute(() -> {
            RootShell.Result r = sh.run(withOptions(cmd, options), TIMEOUT_SEC);
            final String js = "(function(){try{" + callback + "(" + r.code + "," + JSONObject.quote(r.out) + ","
                    + JSONObject.quote(r.err) + ");}catch(e){console.error(e);}})();";
            web.post(() -> web.evaluateJavascript(js, null));
        });
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
