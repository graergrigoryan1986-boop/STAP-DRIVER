package am.stapdriver.app;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import java.util.Locale;

public class MainActivity extends Activity {
    private static final String PLATFORM_URL = "https://stap-driver-api.onrender.com/";
    private WebView webView;
    private ProgressBar progress;
    private LinearLayout errorPanel;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        final int dark = Color.rgb(13, 15, 18);
        final int gold = Color.rgb(211, 177, 112);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(dark);

        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setIndeterminate(true);
        progress.setVisibility(View.VISIBLE);

        webView = new WebView(this);
        webView.setBackgroundColor(dark);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setDomStorageEnabled(true);
        webView.getSettings().setLoadsImagesAutomatically(true);
        webView.getSettings().setJavaScriptCanOpenWindowsAutomatically(false);
        webView.setWebChromeClient(new WebChromeClient());
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageStarted(WebView view, String url, android.graphics.Bitmap favicon) {
                progress.setVisibility(View.VISIBLE);
                errorPanel.setVisibility(View.GONE);
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                progress.setVisibility(View.GONE);
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                String scheme = request.getUrl().getScheme();
                return !("https".equals(scheme) || "http".equals(scheme));
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, android.webkit.WebResourceError error) {
                if (request.isForMainFrame()) {
                    progress.setVisibility(View.GONE);
                    errorPanel.setVisibility(View.VISIBLE);
                }
            }
        });

        errorPanel = new LinearLayout(this);
        errorPanel.setOrientation(LinearLayout.VERTICAL);
        errorPanel.setGravity(Gravity.CENTER);
        errorPanel.setPadding(28, 24, 28, 24);
        errorPanel.setVisibility(View.GONE);

        TextView title = new TextView(this);
        title.setText("Կապը սերվերի հետ հասանելի չէ");
        title.setTextSize(20f);
        title.setGravity(Gravity.CENTER);
        title.setTextColor(Color.WHITE);

        TextView detail = new TextView(this);
        detail.setText("Ստուգեք ինտերնետ կապը և կրկին փորձեք։");
        detail.setTextSize(15f);
        detail.setGravity(Gravity.CENTER);
        detail.setTextColor(Color.LTGRAY);
        detail.setPadding(0, 12, 0, 20);

        Button retry = new Button(this);
        retry.setText("ԿՐԿԻՆ ՓՈՐՁԵԼ");
        retry.setTextColor(dark);
        retry.setBackgroundColor(gold);
        retry.setOnClickListener(v -> loadPlatform());

        errorPanel.addView(title);
        errorPanel.addView(detail);
        errorPanel.addView(retry);

        root.addView(progress, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 4));
        root.addView(webView, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        root.addView(errorPanel, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);
        loadPlatform();
    }

    private void loadPlatform() {
        String role = BuildConfig.APP_ROLE.toLowerCase(Locale.ROOT);
        webView.loadUrl(PLATFORM_URL + "?app=" + role);
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    protected void onDestroy() {
        if (webView != null) webView.destroy();
        super.onDestroy();
    }
}
