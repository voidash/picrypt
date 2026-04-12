package com.picrypt.widget

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.util.Log
import android.widget.RemoteViews
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

/**
 * Widget provider for the Picrypt lock widget.
 *
 * Handles:
 * - Rendering the widget (lock button + status dot)
 * - Registering click PendingIntents
 * - Scheduling the periodic status polling worker
 * - Responding to ACTION_LOCK_REQUESTED from the confirmation dialog
 */
class LockWidgetProvider : AppWidgetProvider() {

    companion object {
        private const val TAG = "LockWidgetProvider"
        const val ACTION_LOCK_REQUESTED = "com.picrypt.widget.ACTION_LOCK_REQUESTED"
        private const val STATUS_WORK_NAME = "picrypt_status_poll"

        /**
         * Force-refresh all widget instances from anywhere in the app.
         */
        fun refreshAllWidgets(context: Context) {
            val appWidgetManager = AppWidgetManager.getInstance(context)
            val widgetIds = appWidgetManager.getAppWidgetIds(
                ComponentName(context, LockWidgetProvider::class.java)
            )
            if (widgetIds.isNotEmpty()) {
                val intent = Intent(context, LockWidgetProvider::class.java).apply {
                    action = AppWidgetManager.ACTION_APPWIDGET_UPDATE
                    putExtra(AppWidgetManager.EXTRA_APPWIDGET_IDS, widgetIds)
                }
                context.sendBroadcast(intent)
            }
        }
    }

    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray,
    ) {
        for (widgetId in appWidgetIds) {
            updateWidget(context, appWidgetManager, widgetId)
        }
    }

    override fun onEnabled(context: Context) {
        super.onEnabled(context)
        scheduleStatusPolling(context)
    }

    override fun onDisabled(context: Context) {
        super.onDisabled(context)
        WorkManager.getInstance(context).cancelUniqueWork(STATUS_WORK_NAME)
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)

        if (intent.action == ACTION_LOCK_REQUESTED) {
            Log.i(TAG, "Lock requested via widget broadcast")
            LockService.startLock(context)
        }
    }

    private fun updateWidget(
        context: Context,
        appWidgetManager: AppWidgetManager,
        widgetId: Int,
    ) {
        val views = RemoteViews(context.packageName, R.layout.widget_lock)

        // -- Status indicator --
        val lastState = PrefsHelper.getLastState(context)
        applyStatusToViews(context, views, lastState)

        // -- Lock button click -> open confirmation dialog --
        val confirmIntent = Intent(context, LockConfirmationActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val confirmPending = PendingIntent.getActivity(
            context,
            0,
            confirmIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        views.setOnClickPendingIntent(R.id.btn_lock, confirmPending)

        // -- Settings gear click -> open settings --
        val settingsIntent = Intent(context, SettingsActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        val settingsPending = PendingIntent.getActivity(
            context,
            1,
            settingsIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        views.setOnClickPendingIntent(R.id.btn_settings, settingsPending)

        appWidgetManager.updateAppWidget(widgetId, views)
    }

    private fun applyStatusToViews(context: Context, views: RemoteViews, state: String) {
        when (state.lowercase()) {
            "active" -> {
                views.setImageViewResource(R.id.status_dot, R.drawable.status_dot_active)
                views.setTextViewText(R.id.status_text, context.getString(R.string.status_active))
            }
            "sealed" -> {
                views.setImageViewResource(R.id.status_dot, R.drawable.status_dot_inactive)
                views.setTextViewText(R.id.status_text, context.getString(R.string.status_sealed))
            }
            "locked" -> {
                views.setImageViewResource(R.id.status_dot, R.drawable.status_dot_inactive)
                views.setTextViewText(R.id.status_text, context.getString(R.string.status_locked))
            }
            else -> {
                views.setImageViewResource(R.id.status_dot, R.drawable.status_dot_inactive)
                views.setTextViewText(R.id.status_text, context.getString(R.string.status_unreachable))
            }
        }
    }

    private fun scheduleStatusPolling(context: Context) {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val workRequest = PeriodicWorkRequestBuilder<StatusUpdateWorker>(
            15, TimeUnit.MINUTES,
        ).setConstraints(constraints)
            .build()

        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            STATUS_WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            workRequest,
        )

        Log.i(TAG, "Scheduled periodic status polling")
    }
}
