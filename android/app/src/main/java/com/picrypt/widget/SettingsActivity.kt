package com.picrypt.widget

import android.appwidget.AppWidgetManager
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import android.widget.TextView
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Configuration activity for the Picrypt widget.
 *
 * This activity serves two roles:
 * 1. The APPWIDGET_CONFIGURE activity (opened when widget is first placed)
 * 2. A standalone settings screen (opened from the widget gear icon or launcher)
 *
 * When opened as a configure activity, we must call setResult(RESULT_OK) with
 * the widget ID, or the widget placement is cancelled.
 */
class SettingsActivity : AppCompatActivity() {

    private val activityScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private lateinit var editServerUrl: TextInputEditText
    private lateinit var editLockPin: TextInputEditText
    private lateinit var textStatus: TextView
    private lateinit var btnTest: MaterialButton
    private lateinit var btnSave: MaterialButton

    /** Non-zero if opened as widget configure activity */
    private var appWidgetId = AppWidgetManager.INVALID_APPWIDGET_ID

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Default result for widget configure: cancelled
        setResult(RESULT_CANCELED)

        setContentView(R.layout.activity_settings)

        editServerUrl = findViewById(R.id.edit_server_url)
        editLockPin = findViewById(R.id.edit_lock_pin)
        textStatus = findViewById(R.id.text_connection_status)
        btnTest = findViewById(R.id.btn_test)
        btnSave = findViewById(R.id.btn_save)

        // Check if we were launched as a widget configure activity
        appWidgetId = intent.getIntExtra(
            AppWidgetManager.EXTRA_APPWIDGET_ID,
            AppWidgetManager.INVALID_APPWIDGET_ID,
        )

        // Load saved settings
        val savedUrl = PrefsHelper.getServerUrl(this)
        if (!savedUrl.isNullOrBlank()) {
            editServerUrl.setText(savedUrl)
        }
        val savedPin = PrefsHelper.getLockPin(this)
        if (!savedPin.isNullOrBlank()) {
            editLockPin.setText(savedPin)
        }

        btnTest.setOnClickListener { testConnection() }
        btnSave.setOnClickListener { saveSettings() }
    }

    override fun onDestroy() {
        super.onDestroy()
        activityScope.cancel()
    }

    private fun testConnection() {
        val url = editServerUrl.text?.toString()?.trim()
        if (url.isNullOrBlank()) {
            textStatus.text = "Enter a server URL first."
            return
        }

        btnTest.isEnabled = false
        textStatus.text = "Testing..."

        activityScope.launch {
            val api = PicryptApi(url)
            val result = withContext(Dispatchers.IO) {
                api.heartbeat()
            }

            btnTest.isEnabled = true

            when (result) {
                is PicryptApi.ApiResult.Success -> {
                    val state = result.data.state.name.lowercase()
                    textStatus.text = "Connected. Server state: $state"
                }
                is PicryptApi.ApiResult.Failure -> {
                    textStatus.text = "Connection failed: ${result.message}"
                }
            }
        }
    }

    private fun saveSettings() {
        val url = editServerUrl.text?.toString()?.trim()
        if (url.isNullOrBlank()) {
            editServerUrl.error = "URL is required"
            return
        }

        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            editServerUrl.error = "URL must start with http:// or https://"
            return
        }

        PrefsHelper.setServerUrl(this, url)
        val pin = editLockPin.text?.toString()?.trim()
        PrefsHelper.setLockPin(this, if (pin.isNullOrBlank()) null else pin)
        Toast.makeText(this, R.string.save, Toast.LENGTH_SHORT).show()

        // If this was a widget configure launch, confirm the widget placement
        if (appWidgetId != AppWidgetManager.INVALID_APPWIDGET_ID) {
            val resultIntent = Intent().apply {
                putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, appWidgetId)
            }
            setResult(RESULT_OK, resultIntent)
        }

        // Refresh all widgets with the new config
        LockWidgetProvider.refreshAllWidgets(this)

        finish()
    }
}
