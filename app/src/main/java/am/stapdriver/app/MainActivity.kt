package am.stapdriver.app

import android.annotation.SuppressLint
import android.app.Activity
import android.os.Bundle
import android.view.View
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.graphics.Color
import android.view.Gravity
import android.view.ViewGroup

class MainActivity : Activity() {
    private val platformUrl = "https://stap-driver-api.onrender.com/"
    private lateinit var webView: WebView
    private lateinit var progress: ProgressBar
    private lateinit var errorPanel: LinearLayout

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val dark = Color.rgb(13, 15, 18)
        val gold = Color.rgb(211, 177, 112)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(dark)
        }
        progress = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            isIndeterminate = true
            setVisibility(View.VISIBLE)
        }
        webView = WebView(this).apply {
            setBackgroundColor(dark)
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.loadsImagesAutomatically = true
            settings.javaScriptCanOpenWindowsAutomatically = false
            webChromeClient = WebChromeClient()
            webViewClient = object : WebViewClient() {
                override fun onPageStarted(view: WebView?, url: String?, favicon: android.graphics.Bitmap?) {
                    progress.setVisibility(View.VISIBLE)
                    errorPanel.setVisibility(View.GONE)
                }
                override fun onPageFinished(view: WebView?, url: String?) {
                    progress.setVisibility(View.GONE)
                }
                override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                    val uri = request?.url ?: return false
                    return uri.scheme != "https" && uri.scheme != "http"
                }
                override fun onReceivedError(view: WebView?, request: WebResourceRequest?, error: android.webkit.WebResourceError?) {
                    if (request?.isForMainFrame == true) {
                        progress.setVisibility(View.GONE)
                        errorPanel.setVisibility(View.VISIBLE)
                    }
                }
            }
        }
        errorPanel = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(28, 24, 28, 24)
            setVisibility(View.GONE)
            val title = TextView(this@MainActivity).apply {
                text = "Կապը սերվերի հետ հասանելի չէ"
                textSize = 20f
                gravity = Gravity.CENTER
                setTextColor(Color.WHITE)
            }
            val detail = TextView(this@MainActivity).apply {
                text = "Ստուգեք ինտերնետ կապը և կրկին փորձեք։"
                textSize = 15f
                gravity = Gravity.CENTER
                setTextColor(Color.LTGRAY)
                setPadding(0, 12, 0, 20)
            }
            val retry = Button(this@MainActivity).apply {
                text = "ԿՐԿԻՆ ՓՈՐՁԵԼ"
                setTextColor(dark)
                setBackgroundColor(gold)
                setOnClickListener { loadPlatform() }
            }
            addView(title)
            addView(detail)
            addView(retry)
        }

        root.addView(progress, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 4))
        root.addView(webView, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        root.addView(errorPanel, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)
        loadPlatform()
    }

    private fun loadPlatform() {
        val role = BuildConfig.APP_ROLE.lowercase()
        webView.loadUrl("${platformUrl}?app=$role")
    }

    override fun onBackPressed() {
        if (::webView.isInitialized && webView.canGoBack()) webView.goBack() else super.onBackPressed()
    }

    override fun onDestroy() {
        if (::webView.isInitialized) webView.destroy()
        super.onDestroy()
    }
}
