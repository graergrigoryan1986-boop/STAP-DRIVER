package am.stapdriver.app

import android.app.Activity
import android.os.Bundle
import android.graphics.Color
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast

class MainActivity : Activity() {
    private val green = Color.rgb(57, 214, 154)
    private val dark = Color.rgb(11, 23, 20)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(28, 36, 28, 36)
            setBackgroundColor(dark)
        }
        val logo = TextView(this).apply {
            text = "STAP DRIVER"
            textSize = 30f
            setTextColor(green)
            gravity = Gravity.CENTER
        }
        val title = TextView(this).apply {
            text = "Քո մեքենան։ Մեր վարորդը։"
            textSize = 21f
            setTextColor(Color.WHITE)
            gravity = Gravity.CENTER
            setPadding(0, 24, 0, 12)
        }
        val subtitle = TextView(this).apply {
            text = "Սթափ վարորդի ծառայություն Երևանում"
            textSize = 16f
            setTextColor(Color.LTGRAY)
            gravity = Gravity.CENTER
        }
        val order = Button(this).apply {
            text = "Պատվիրել վարորդ"
            setTextColor(dark)
            setBackgroundColor(green)
            setOnClickListener { Toast.makeText(this@MainActivity, "Պատվերի համակարգը կմիացվի հաջորդ փուլում", Toast.LENGTH_LONG).show() }
        }
        root.addView(logo)
        root.addView(title)
        root.addView(subtitle)
        root.addView(order, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { topMargin = 32 })
        setContentView(root)
    }
}
