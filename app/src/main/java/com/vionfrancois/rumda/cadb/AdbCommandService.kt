package com.vionfrancois.rumda.cadb

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import com.vionfrancois.rumda.R
import java.io.IOException
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

private const val TAG = "AdbCommandService"

class AdbCommandService : Service() {

    companion object {
        const val ACTION_START_LOOP = "com.vionfrancois.rumda.action.START_LOOP"
        const val ACTION_STOP_LOOP = "com.vionfrancois.rumda.action.STOP_LOOP"
        const val EXTRA_COMMAND = "command"
        const val EXTRA_INTERVAL_MS = "interval_ms"

        private const val CHANNEL_ID = "adb_command_loop"
        private const val NOTIFICATION_ID = 42

        fun startLoopIntent(
            context: Context,
            command: String = "date",
            intervalMs: Long = 10_000L
        ): Intent {
            return Intent(context, AdbCommandService::class.java)
                .setAction(ACTION_START_LOOP)
                .putExtra(EXTRA_COMMAND, command)
                .putExtra(EXTRA_INTERVAL_MS, intervalMs)
        }

        fun stopLoopIntent(context: Context): Intent {
            return Intent(context, AdbCommandService::class.java).setAction(ACTION_STOP_LOOP)
        }
    }

    private val scheduler = Executors.newSingleThreadScheduledExecutor()
    private var loopFuture: ScheduledFuture<*>? = null
    private var currentCommand: String = "date"
    private var currentIntervalMs: Long = 10_000L
    private lateinit var adbConnectionManager: AdbConnectionManager

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        adbConnectionManager = AdbConnectionManager.getInstance(applicationContext) as AdbConnectionManager
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START_LOOP -> {
                currentCommand = intent.getStringExtra(EXTRA_COMMAND)?.ifBlank { "date" } ?: "date"
                currentIntervalMs = intent.getLongExtra(EXTRA_INTERVAL_MS, 10_000L).coerceAtLeast(1_000L)
                startAsForeground("Starting loop: $currentCommand every ${currentIntervalMs / 1000}s")
                startLoop()
            }
            ACTION_STOP_LOOP -> {
                stopLoop()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            else -> {
                startAsForeground("ADB loop idle")
            }
        }
        return START_STICKY
    }

    private fun startLoop() {
        stopLoop()
        loopFuture = scheduler.scheduleAtFixedRate(
            { runLoopTick() },
            0,
            currentIntervalMs,
            TimeUnit.MILLISECONDS
        )
    }

    private fun stopLoop() {
        loopFuture?.cancel(true)
        loopFuture = null
    }

    private fun runLoopTick() {
        try {
            ensureConnected()
            val output = runCommandOnce(currentCommand).ifBlank { "(no output)" }
            Log.println(Log.INFO, "AdbCommandService:runLoopTick",output)
            updateNotification("Last: ${output.take(100)}")
        } catch (e: Throwable) {
            Log.e(TAG, "Loop tick failed", e)
            val msg = e.message ?: e.javaClass.simpleName
            updateNotification("Error: $msg")
        }
    }

    private fun ensureConnected() {
        if (adbConnectionManager.isConnected) return
        val connected = adbConnectionManager.connectTls(applicationContext, 5000)
        if (!connected) throw IOException("Unable to connect to ADB over TLS")
    }

    private fun runCommandOnce(command: String): String {
        val stream = adbConnectionManager.openStream("shell:$command")
        val out = StringBuilder()
        try {
            stream.openInputStream().bufferedReader().use { reader ->
                val buf = CharArray(1024)
                while (true) {
                    val n = try {
                        reader.read(buf)
                    } catch (io: IOException) {
                        if (io.message?.contains("Stream closed", ignoreCase = true) == true) break
                        throw io
                    }
                    if (n < 0) break
                    out.append(buf, 0, n)
                }
            }
        } finally {
            try {
                stream.close()
            } catch (_: Throwable) {
            }
        }
        return out.toString().trim()
    }

    private fun createNotificationChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_adb_loop),
                NotificationManager.IMPORTANCE_LOW
            )
        )
    }

    private fun startAsForeground(text: String) {
        val notification = buildNotification(text)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (t: Throwable) {
            Log.e(TAG, "startForeground typed failed", t)
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification {
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setContentTitle(getString(R.string.notification_adb_loop_title))
            .setContentText(text)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        stopLoop()
        scheduler.shutdownNow()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
