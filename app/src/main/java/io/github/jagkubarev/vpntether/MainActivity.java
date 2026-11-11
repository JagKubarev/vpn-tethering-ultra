package io.github.jagkubarev.vpntether;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.util.LruCache;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.ConsoleMessage;
import android.webkit.JsResult;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * WebUI модуля VPN Tethering Ultra без менеджера KernelSU: страница
 * /data/adb/modules/vpn-to-hotspot-usb/webroot/ читается через root и отдаётся
 * WebView по https://mui.kernelsu.org/ (тот же адрес, что у KernelSU, — тот же
 * origin для localStorage и «безопасный контекст» для буфера обмена).
 */
public class MainActivity extends Activity {
    static final String TAG = "vt_webui";
    static final String MOD = "/data/adb/modules/vpn-to-hotspot-usb";
    private static final String HOST = "mui.kernelsu.org";
    private static final int REQ_FILE = 1;

    // root-шелл переживает пересоздание окна (смена темы): идущая команда не рвётся,
    // Magisk не спрашивает/не тостит заново
    private RootShell sh;
    // значки для списка приложений: поиск перерисовывает список и снова просит их; не больше 2 МБ
    private final LruCache<String, byte[]> icons = new LruCache<String, byte[]>(2 << 20) {
        @Override protected int sizeOf(String k, byte[] v) { return v.length; }
    };
    private WebView web;
    private KsuBridge bridge;
    private LinearLayout msgBox;
    private TextView msg;
    private Button retry;
    private ValueCallback<Uri[]> fileCb;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Object kept = getLastNonConfigurationInstance();
        sh = kept instanceof RootShell ? (RootShell) kept : new RootShell();
        FrameLayout root = new FrameLayout(this);

        web = new WebView(this);
        web.setVisibility(View.INVISIBLE);
        root.addView(web, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        int pad = (int) (24 * getResources().getDisplayMetrics().density);
        msgBox = new LinearLayout(this);
        msgBox.setOrientation(LinearLayout.VERTICAL);
        msgBox.setGravity(Gravity.CENTER);
        msgBox.setPadding(pad, pad, pad, pad);
        msg = new TextView(this);
        msg.setTextSize(16);
        msg.setGravity(Gravity.CENTER);
        msg.setText(R.string.wait_root);
        retry = new Button(this);
        retry.setText(R.string.retry);
        retry.setVisibility(View.GONE);
        retry.setOnClickListener(v -> check());
        msgBox.addView(msg);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = pad;
        msgBox.addView(retry, lp);
        root.addView(msgBox, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        setContentView(root);

        setupWeb();
        check();
    }

    /** root есть и модуль на месте — грузим страницу, иначе понятное сообщение. */
    private void check() {
        retry.setVisibility(View.GONE);
        msg.setText(R.string.wait_root);
        new Thread(() -> {
            RootShell.Result r = sh.run("id -u; [ -f " + MOD + "/webroot/index.html ] && echo MOD", 60);
            final String[] l = r.out.split("\n");
            final boolean root = r.code != 124 && l.length > 0 && "0".equals(l[0].trim());
            final boolean mod = root && r.out.contains("MOD");
            if (!root) Log.w(TAG, "нет root: code=" + r.code + " out=" + r.out + " err=" + r.err);
            runOnUiThread(() -> {
                if (isFinishing()) return;
                if (!root) fail(getString(R.string.no_root));
                else if (!mod) fail(getString(R.string.no_module, MOD));
                else {
                    msgBox.setVisibility(View.GONE);
                    web.setVisibility(View.VISIBLE);
                    web.loadUrl("https://" + HOST + "/index.html");
                }
            });
        }, "vt-check").start();
    }

    private void fail(String text) {
        web.setVisibility(View.INVISIBLE);
        msgBox.setVisibility(View.VISIBLE);
        msg.setText(text);
        retry.setVisibility(View.VISIBLE);
    }

    @SuppressLint({"SetJavaScriptEnabled", "JavascriptInterface"})
    private void setupWeb() {
        boolean debuggable = (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        WebView.setWebContentsDebuggingEnabled(debuggable);   // в release нет: через отладку adb получил бы root
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setCacheMode(WebSettings.LOAD_NO_CACHE);   // после обновления модуля — сразу новая страница
        bridge = new KsuBridge(this, web, sh, MOD);
        web.addJavascriptInterface(bridge, "ksu");

        web.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView v, WebResourceRequest req) {
                Uri u = req.getUrl();
                String sc = u.getScheme();
                if ("ksu".equals(sc)) return "icon".equals(u.getHost()) ? icon(u.getLastPathSegment()) : notFound();
                // В окне есть root-мост ksu: в сеть отсюда ничего не уходит, чужое не грузится.
                // Странице сеть не нужна — всё через webctl.sh.
                if (!HOST.equals(u.getHost()) || !"https".equals(sc)) {
                    return "http".equals(sc) || "https".equals(sc) || "ws".equals(sc) || "wss".equals(sc) || "ftp".equals(sc)
                            ? forbidden() : null;
                }
                String p = u.getPath();
                if (p == null || p.isEmpty() || p.equals("/")) p = "/index.html";
                if (p.contains("..") || p.contains("'")) return notFound();
                byte[] data = sh.readFile(MOD + "/webroot" + p);
                if (data == null) return notFound();
                WebResourceResponse r = new WebResourceResponse(mime(p), mime(p).startsWith("text/") ? "utf-8" : null,
                        new ByteArrayInputStream(data));
                Map<String, String> h = new HashMap<>();
                h.put("Cache-Control", "no-store");
                r.setResponseHeaders(h);
                return r;
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest req) {
                Uri u = req.getUrl();
                if (HOST.equals(u.getHost())) return false;
                try { startActivity(new Intent(Intent.ACTION_VIEW, u)); } catch (ActivityNotFoundException ignored) { }
                return true;
            }
        });

        web.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onConsoleMessage(ConsoleMessage m) {
                Log.d(TAG, m.message() + " @" + m.lineNumber());
                return true;
            }

            // confirm()/alert() страницы: свой диалог, без заголовка «Подтвердите действие на https://mui.kernelsu.org»
            @Override
            public boolean onJsConfirm(WebView v, String url, String text, JsResult res) {
                new AlertDialog.Builder(MainActivity.this)
                        .setMessage(text)
                        .setPositiveButton(android.R.string.ok, (d, w) -> res.confirm())
                        .setNegativeButton(android.R.string.cancel, (d, w) -> res.cancel())
                        .setOnCancelListener(d -> res.cancel())
                        .show();
                return true;
            }

            @Override
            public boolean onJsAlert(WebView v, String url, String text, JsResult res) {
                new AlertDialog.Builder(MainActivity.this)
                        .setMessage(text)
                        .setPositiveButton(android.R.string.ok, (d, w) -> res.confirm())
                        .setOnCancelListener(d -> res.confirm())
                        .show();
                return true;
            }

            // <input type=file> (импорт настроек и конфигов WARP): без этого кнопка молчит
            @Override
            public boolean onShowFileChooser(WebView v, ValueCallback<Uri[]> cb, FileChooserParams p) {
                if (fileCb != null) fileCb.onReceiveValue(null);
                fileCb = cb;
                Intent i = new Intent(Intent.ACTION_GET_CONTENT);
                i.addCategory(Intent.CATEGORY_OPENABLE);
                i.setType("*/*");
                if (p.getMode() == FileChooserParams.MODE_OPEN_MULTIPLE) i.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
                try {
                    startActivityForResult(Intent.createChooser(i, null), REQ_FILE);
                } catch (ActivityNotFoundException e) {
                    fileCb = null;
                    return false;
                }
                return true;
            }
        });
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        if (req != REQ_FILE || fileCb == null) { super.onActivityResult(req, res, data); return; }
        Uri[] out = null;
        if (res == RESULT_OK && data != null) {
            List<Uri> l = new ArrayList<>();
            ClipData c = data.getClipData();
            if (c != null) for (int i = 0; i < c.getItemCount(); i++) l.add(c.getItemAt(i).getUri());
            else if (data.getData() != null) l.add(data.getData());
            out = l.toArray(new Uri[0]);
        }
        fileCb.onReceiveValue(out);
        fileCb = null;
    }

    private WebResourceResponse icon(String pkg) {
        if (pkg == null) return notFound();
        byte[] png = icons.get(pkg);
        if (png == null) {
            try {
                Drawable d = getPackageManager().getApplicationIcon(pkg);
                int n = (int) (48 * getResources().getDisplayMetrics().density);
                Bitmap bm = Bitmap.createBitmap(n, n, Bitmap.Config.ARGB_8888);
                d.setBounds(0, 0, n, n);
                d.draw(new Canvas(bm));
                ByteArrayOutputStream o = new ByteArrayOutputStream();
                bm.compress(Bitmap.CompressFormat.PNG, 100, o);
                bm.recycle();
                png = o.toByteArray();
                icons.put(pkg, png);
            } catch (Exception e) {
                return notFound();
            }
        }
        return new WebResourceResponse("image/png", null, new ByteArrayInputStream(png));
    }

    private static WebResourceResponse notFound() {
        return new WebResourceResponse("text/plain", "utf-8", 404, "Not Found", null, new ByteArrayInputStream(new byte[0]));
    }

    private static WebResourceResponse forbidden() {
        return new WebResourceResponse("text/plain", "utf-8", 403, "Forbidden", null, new ByteArrayInputStream(new byte[0]));
    }

    private static String mime(String p) {
        String e = p.substring(p.lastIndexOf('.') + 1).toLowerCase();
        switch (e) {
            case "html": case "htm": return "text/html";
            case "js": case "mjs": return "text/javascript";
            case "css": return "text/css";
            case "json": return "application/json";
            case "svg": return "image/svg+xml";
            case "png": return "image/png";
            case "jpg": case "jpeg": return "image/jpeg";
            case "webp": return "image/webp";
            case "woff2": return "font/woff2";
            case "txt": return "text/plain";
            default: return "application/octet-stream";
        }
    }

    // Свернули — таймеры страницы на паузу: опрос статуса раз в 3 с не гоняет root-шелл в фоне
    @Override
    protected void onPause() {
        super.onPause();
        web.onPause();
        web.pauseTimers();
    }

    @Override
    protected void onResume() {
        super.onResume();
        web.resumeTimers();
        web.onResume();
    }

    @Override
    public void onBackPressed() {
        if (web.canGoBack()) web.goBack();
        else super.onBackPressed();
    }

    @Override
    public Object onRetainNonConfigurationInstance() { return sh; }

    @Override
    protected void onDestroy() {
        bridge.close();
        web.destroy();
        // смена темы и т. п. — шелл достанется новому окну; закрыли совсем — гасим
        // (close ждёт идущую команду: не рвём запись настроек на полпути)
        if (!isChangingConfigurations()) new Thread(sh::close).start();
        super.onDestroy();
    }
}
