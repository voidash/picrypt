package com.picrypt.widget

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.util.Log
import android.widget.Toast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Foreground service that executes the POST /lock call.
 *
 * We use a foreground service (not a plain IntentService) because:
 * - Android 8+ restricts background execution
 * - The lock command is time-sensitive and must not be deferred
 * - A foreground service survives process trimming
 *
 * The service starts, sends the HTTP request, toasts the result, and stops itself.
 */
class LockService : Service() {

    companion object {
        private const val TAG = "LockService"
        private const val CHANNEL_ID = "picrypt_lock_channel"
        private const val NOTIFICATION_ID = 1001

        fun startLock(context: Context) {
            val intent = Intent(context, LockService::class.java)
            context.startForegroundService(intent)
        }
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val serverUrl = PrefsHelper.getServerUrl(this)
        if (serverUrl.isNullOrBlank()) {
            Log.e(TAG, "No server URL configured, cannot lock")
            Toast.makeText(this, R.string.server_url_not_configured, Toast.LENGTH_LONG).show()
            stopSelf()
            return START_NOT_STICKY
        }

        serviceScope.launch {
            executeLock(serverUrl)
            stopSelf()
        }

        return START_NOT_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }

    private suspend fun executeLock(serverUrl: String) {
        val api = PicryptApi(serverUrl)
        val pin = PrefsHelper.getLockPin(this@LockService)

        val result = withContext(Dispatchers.IO) {
            api.lock(pin)
        }

        when (result) {
            is PicryptApi.ApiResult.Success -> {
                Log.i(TAG, "Lock command sent successfully")
                Toast.makeText(this@LockService, R.string.lock_success, Toast.LENGTH_SHORT).show()

                // Update stored state and refresh widget
                PrefsHelper.setLastState(this@LockService, "locked")
                LockWidgetProvider.refreshAllWidgets(this@LockService)
            }
            is PicryptApi.ApiResult.Failure -> {
                Log.e(TAG, "Lock command failed: ${result.message}", result.exception)
                Toast.makeText(this@LockService, R.string.lock_failed, Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.notification_channel_description)
        }
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notification_locking))
            .setSmallIcon(R.drawable.ic_lock)
            .build()
    }
}
