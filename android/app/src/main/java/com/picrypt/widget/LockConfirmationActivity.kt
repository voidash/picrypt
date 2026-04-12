package com.picrypt.widget

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.dialog.MaterialAlertDialogBuilder

/**
 * Transparent activity that shows a confirmation dialog before locking.
 *
 * This exists because RemoteViews (widget) can't show dialogs directly.
 * The activity finishes itself immediately after the user makes a choice.
 */
class LockConfirmationActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val serverUrl = PrefsHelper.getServerUrl(this)
        if (serverUrl.isNullOrBlank()) {
            Toast.makeText(this, R.string.server_url_not_configured, Toast.LENGTH_LONG).show()
            startActivity(Intent(this, SettingsActivity::class.java))
            finish()
            return
        }

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.confirm_title)
            .setMessage(R.string.confirm_message)
            .setPositiveButton(R.string.confirm_lock) { _, _ ->
                sendLockBroadcast()
                finish()
            }
            .setNegativeButton(R.string.confirm_cancel) { dialog, _ ->
                dialog.dismiss()
                finish()
            }
            .setOnCancelListener {
                finish()
            }
            .show()
    }

    private fun sendLockBroadcast() {
        val intent = Intent(LockWidgetProvider.ACTION_LOCK_REQUESTED).apply {
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }
}
