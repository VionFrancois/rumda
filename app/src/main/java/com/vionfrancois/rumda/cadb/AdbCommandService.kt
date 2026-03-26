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
import com.vionfrancois.rumda.collectors.APKCollector
import com.vionfrancois.rumda.collectors.StateCollector
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.IOException

private const val TAG = "AdbCommandService"

class AdbCommandService : Service() {

    companion object {
        const val ACTION_START_LOOP = "com.vionfrancois.rumda.action.START_LOOP"
        const val ACTION_STOP_LOOP = "com.vionfrancois.rumda.action.STOP_LOOP"
        const val EXTRA_INTERVAL_MS = "interval_ms"

        private const val CHANNEL_ID = "adb_command_loop"
        private const val NOTIFICATION_ID = 42

        fun startLoopIntent(
            context: Context,
            intervalMs: Long = 60_000L
        ): Intent {
            return Intent(context, AdbCommandService::class.java)
                .setAction(ACTION_START_LOOP)
                .putExtra(EXTRA_INTERVAL_MS, intervalMs)
        }

        fun stopLoopIntent(context: Context): Intent {
            return Intent(context, AdbCommandService::class.java).setAction(ACTION_STOP_LOOP)
        }
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var loopJob: Job? = null
    private var currentIntervalMs: Long = 60_000L
    private lateinit var adbConnectionManager: AdbConnectionManager
    private lateinit var adbManager: AdbManager

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        adbConnectionManager = AdbConnectionManager.getInstance(applicationContext) as AdbConnectionManager
        adbManager = AdbManager(applicationContext)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START_LOOP -> {
                currentIntervalMs = intent.getLongExtra(EXTRA_INTERVAL_MS, 60_000L).coerceAtLeast(1_000L)
                startAsForeground("Monitoring the device")
                startLoop()
            }
            ACTION_STOP_LOOP -> {
                stopLoop()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            else -> {
                startAsForeground("Not monitoring the device")
            }
        }
        return START_STICKY
    }

    private fun startLoop() {
        stopLoop()
        loopJob = serviceScope.launch {
            while (isActive) {
                runLoopTick()
                delay(currentIntervalMs)
            }
        }
    }

    private fun stopLoop() {
        loopJob?.cancel()
        loopJob = null
    }

    private suspend fun runLoopTick() {
        try {
            ensureConnected()
            Log.d(TAG, "Loop entry")
            val prefs = getSharedPreferences("rumda_prefs", Context.MODE_PRIVATE)
            val categories = prefs.getStringSet("monitoring_categories", emptySet())?.toSet().orEmpty()
            val collectors = mutableListOf<StateCollector>()
            val collectorNames = mutableListOf<String>()

            for (category in categories) {
                when (category) {
                    "APKS" -> {
                        collectors.add(APKCollector(adbManager, applicationContext))
                        collectorNames.add("APKS")
                    }
//                    "IPS" -> {
//                        collectors.add(IPSCollector(adbManager, applicationContext))
//                        collectorNames.add("IPS")
//                    }
//                    "SERVICES" -> {
//                        collectors.add(ServicesCollector(adbManager, applicationContext))
//                        collectorNames.add("SERVICES")
//                    }
                }
            }

            for (collector in collectors){
                collector.run()
            }
            
            val monitoringText = if (collectorNames.isEmpty()) {
                "Not monitoring"
            } else {
                "Monitoring: ${collectorNames.joinToString(", ")}"
            }
            updateNotification(monitoringText)
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
        serviceScope.cancel()
        adbManager.cleanup()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
