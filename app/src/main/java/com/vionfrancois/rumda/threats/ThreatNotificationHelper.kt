package com.vionfrancois.rumda.threats

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import com.vionfrancois.rumda.R
import com.vionfrancois.rumda.ThreatsActivity

class ThreatNotificationHelper(context: Context) {

    companion object {
        private const val CHANNEL_ID = "rumda_threats"
        private const val CHANNEL_NAME = "Threat Alerts"
        private const val NOTIFICATION_ID = 4301
    }

    private val appContext = context.applicationContext

    fun notifyThreatDetected(newThreatCount: Int) {
        if (newThreatCount <= 0) return
        if (!canPostNotifications()) return

        val notificationManager = appContext.getSystemService(NotificationManager::class.java)
        ensureChannel(notificationManager)

        val pendingIntent = PendingIntent.getActivity(
            appContext,
            0,
            Intent(appContext, ThreatsActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val text = appContext.resources.getQuantityString(
            R.plurals.notification_threat_detected_body,
            newThreatCount,
            newThreatCount,
        )

        val notification = Notification.Builder(appContext, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle(appContext.getString(R.string.notification_threat_detected_title))
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    private fun ensureChannel(notificationManager: NotificationManager) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

        val channel = NotificationChannel(
            CHANNEL_ID,
            CHANNEL_NAME,
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = appContext.getString(R.string.notification_threat_channel_description)
        }

        notificationManager.createNotificationChannel(channel)
    }

    private fun canPostNotifications(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true

        return appContext.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
    }
}
