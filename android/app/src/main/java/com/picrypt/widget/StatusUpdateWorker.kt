package com.picrypt.widget

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Periodic WorkManager worker that polls GET /heartbeat and updates the widget's
 * status indicator.
 *
 * WorkManager guarantees execution even if the app process is killed, and it
 * respects Doze mode and battery optimization. The minimum interval is 15 minutes
 * (Android enforced), which is acceptable for a status indicator.
 */
class StatusUpdateWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    companion object {
        private const val TAG = "StatusUpdateWorker"
    }

    override suspend fun doWork(): Result {
        val serverUrl = PrefsHelper.getServerUrl(applicationContext)
        if (serverUrl.isNullOrBlank()) {
            Log.w(TAG, "No server URL configured, skipping heartbeat poll")
            return Result.success()
        }

        val api = PicryptApi(serverUrl)

        val result = withContext(Dispatchers.IO) {
            api.heartbeat()
        }

        when (result) {
            is PicryptApi.ApiResult.Success -> {
                val state = result.data.state.name.lowercase()
                Log.d(TAG, "Heartbeat: state=$state, timestamp=${result.data.timestamp}")
                PrefsHelper.setLastState(applicationContext, state)
            }
            is PicryptApi.ApiResult.Failure -> {
                Log.w(TAG, "Heartbeat failed: ${result.message}")
                PrefsHelper.setLastState(applicationContext, "unreachable")
            }
        }

        LockWidgetProvider.refreshAllWidgets(applicationContext)

        return Result.success()
    }
}
