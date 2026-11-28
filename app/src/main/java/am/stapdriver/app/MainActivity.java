package am.stapdriver.app;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.pm.PackageManager;
import android.webkit.PermissionRequest;
import android.app.Activity;
import android.app.AlertDialog;
import android.provider.Settings;
import android.content.DialogInterface;
import android.graphics.Color;
import android.content.Intent;
import android.content.ClipData;
import android.net.Uri;
import android.provider.MediaStore;
import androidx.core.content.FileProvider;
import java.io.File;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.ValueCallback;
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
    private ValueCallback<Uri[]> fileChooserCallback;
    private static final int FILE_CHOOSER_REQUEST_CODE = 1001;
    private static final int CAMERA_PERMISSION_REQUEST_CODE = 1002;
    private PermissionRequest pendingCameraPermissionRequest;
    private Uri pendingCameraCaptureUri;
    private WebChromeClient.FileChooserParams pendingFileChooserParams;
    private boolean cameraPermissionRequestInFlight = false;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        final int dark = Color.rgb(13, 15, 18);
        final int gold = Color.rgb(211, 177, 112);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(dark);
        root.setFitsSystemWindows(true);

        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setIndeterminate(true);
        progress.setVisibility(View.VISIBLE);

        webView = new WebView(this);
        webView.setBackgroundColor(dark);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setDomStorageEnabled(true);
        webView.getSettings().setLoadsImagesAutomatically(true);
        webView.getSettings().setJavaScriptCanOpenWindowsAutomatically(false);
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onPermissionRequest(PermissionRequest request) {
                runOnUiThread(() -> {
                    boolean wantsCamera = false;
                    for (String resource : request.getResources()) if (PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(resource)) wantsCamera = true;
                    if (!wantsCamera || !isTrustedCameraOrigin(request.getOrigin())) { request.deny(); return; }
                    if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                        request.grant(new String[]{PermissionRequest.RESOURCE_VIDEO_CAPTURE});
                    } else {
                        if (pendingCameraPermissionRequest != null) pendingCameraPermissionRequest.deny();
                        pendingCameraPermissionRequest = request;
                        requestCameraPermissionIfNeeded();
                    }
                });
            }

            @Override
            public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback, FileChooserParams params) {
                if (fileChooserCallback != null) fileChooserCallback.onReceiveValue(null);
                fileChooserCallback = callback;
                if (params.isCaptureEnabled() && checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                    pendingFileChooserParams = params;
                    requestCameraPermissionIfNeeded();
                    return true;
                }
                launchFileChooser(params);
                return true;
            }
        });
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
        if (BuildConfig.APP_ROLE.equals("DRIVER")) requestCameraPermissionIfNeeded();
    }

    private boolean isTrustedCameraOrigin(Uri origin) {
        return origin != null && "https".equalsIgnoreCase(origin.getScheme())
                && "stap-driver-api.onrender.com".equalsIgnoreCase(origin.getHost());
    }

    private void requestCameraPermissionIfNeeded() {
        if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            cameraPermissionRequestInFlight = false;
            if (pendingCameraPermissionRequest != null) {
                pendingCameraPermissionRequest.grant(new String[]{PermissionRequest.RESOURCE_VIDEO_CAPTURE});
                pendingCameraPermissionRequest = null;
            }
            if (pendingFileChooserParams != null) {
                WebChromeClient.FileChooserParams params = pendingFileChooserParams;
                pendingFileChooserParams = null;
                launchFileChooser(params);
            }
            return;
        }
        if (cameraPermissionRequestInFlight) return;
        android.content.SharedPreferences prefs = getSharedPreferences("stap_permissions", MODE_PRIVATE);
        boolean requestedBefore = prefs.getBoolean("camera_requested", false);
        if (requestedBefore && !shouldShowRequestPermissionRationale(Manifest.permission.CAMERA)) {
            showCameraSettingsDialog();
            return;
        }
        prefs.edit().putBoolean("camera_requested", true).apply();
        cameraPermissionRequestInFlight = true;
        requestPermissions(new String[]{Manifest.permission.CAMERA}, CAMERA_PERMISSION_REQUEST_CODE);
    }

    private void showCameraSettingsDialog() {
        new AlertDialog.Builder(this)
                .setTitle("Տեսախցիկի թույլտվություն")
                .setMessage("Տեսախցիկը մերժված է։ Նկարահանման համար միացրեք Camera թույլտվությունը հավելվածի կարգավորումներում։")
                .setNegativeButton("Փակել", null)
                .setPositiveButton("Բացել կարգավորումները", (dialog, which) -> {
                    Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                            Uri.parse("package:" + getPackageName()));
                    startActivity(intent);
                }).show();
    }

    private void launchFileChooser(WebChromeClient.FileChooserParams params) {
        try {
            Intent contentIntent = params.createIntent();
            Intent chooserIntent = new Intent(Intent.ACTION_CHOOSER);
            chooserIntent.putExtra(Intent.EXTRA_INTENT, contentIntent);
            if (params.isCaptureEnabled()) {
                Intent cameraIntent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
                if (cameraIntent.resolveActivity(getPackageManager()) != null) {
                    File pictures = getExternalFilesDir(android.os.Environment.DIRECTORY_PICTURES);
                    if (pictures != null) {
                        File photo = File.createTempFile("stap_camera_", ".jpg", pictures);
                        pendingCameraCaptureUri = FileProvider.getUriForFile(MainActivity.this, getPackageName() + ".fileprovider", photo);
                        cameraIntent.putExtra(MediaStore.EXTRA_OUTPUT, pendingCameraCaptureUri);
                        cameraIntent.setClipData(ClipData.newRawUri("STAP camera photo", pendingCameraCaptureUri));
                        cameraIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
                        chooserIntent.putExtra(Intent.EXTRA_INITIAL_INTENTS, new Intent[]{cameraIntent});
                    }
                }
            }
            startActivityForResult(chooserIntent, FILE_CHOOSER_REQUEST_CODE);
        } catch (Exception error) {
            if (fileChooserCallback != null) {
                fileChooserCallback.onReceiveValue(null);
                fileChooserCallback = null;
            }
            pendingCameraCaptureUri = null;
        }
    }

    private void loadPlatform() {
        String role = BuildConfig.APP_ROLE.toLowerCase(Locale.ROOT);
        webView.loadUrl(PLATFORM_URL + "?app=" + role);
    }


    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == CAMERA_PERMISSION_REQUEST_CODE) {
            cameraPermissionRequestInFlight = false;
            boolean granted = grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED;
            if (pendingCameraPermissionRequest != null) {
                if (granted) pendingCameraPermissionRequest.grant(new String[]{PermissionRequest.RESOURCE_VIDEO_CAPTURE});
                else pendingCameraPermissionRequest.deny();
                pendingCameraPermissionRequest = null;
            }
            if (granted && pendingFileChooserParams != null) {
                WebChromeClient.FileChooserParams params = pendingFileChooserParams;
                pendingFileChooserParams = null;
                launchFileChooser(params);
            } else if (!granted && pendingFileChooserParams != null) {
                pendingFileChooserParams = null;
                if (fileChooserCallback != null) {
                    fileChooserCallback.onReceiveValue(null);
                    fileChooserCallback = null;
                }
                if (!shouldShowRequestPermissionRationale(Manifest.permission.CAMERA)) showCameraSettingsDialog();
            }
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == FILE_CHOOSER_REQUEST_CODE) {
            if (fileChooserCallback == null) return;
            Uri[] results = WebChromeClient.FileChooserParams.parseResult(resultCode, data);
            if ((results == null || results.length == 0) && resultCode == RESULT_OK && pendingCameraCaptureUri != null) {
                results = new Uri[]{pendingCameraCaptureUri};
            }
            fileChooserCallback.onReceiveValue(results);
            fileChooserCallback = null;
            pendingCameraCaptureUri = null;
        }
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
        if (pendingCameraPermissionRequest != null) { pendingCameraPermissionRequest.deny(); pendingCameraPermissionRequest = null; }
        if (fileChooserCallback != null) { fileChooserCallback.onReceiveValue(null); fileChooserCallback = null; }
        pendingFileChooserParams = null;
        if (webView != null) webView.destroy();
        super.onDestroy();
    }
}
