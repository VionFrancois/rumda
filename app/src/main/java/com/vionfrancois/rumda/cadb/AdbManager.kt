package com.vionfrancois.rumda.cadb

import android.content.Context
import android.content.IntentFilter
import android.os.Build
import android.util.Log
import io.github.muntashirakon.adb.AdbPairingRequiredException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.IOException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

private const val TAG = "AdbManager"

class AdbManager(private val appContext: Context) {
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val _adbState = MutableStateFlow<AdbState>(AdbState.Initial)
    val adbState: StateFlow<AdbState> = _adbState.asStateFlow()

    private val adbConnectionManager: AdbConnectionManager =
        AdbConnectionManager.getInstance(appContext) as AdbConnectionManager

    private val adbPairingReceiver =
        AdbPairingResultReceiver(
            onSuccess = {
                Log.d(TAG, "paired successfully")
                _adbState.value = AdbState.Ready
                stopAdbPairingService()
                autoConnect()
            },
            onFailure = { errorMessage ->
                Log.e(TAG, "pairing failed: $errorMessage")
                _adbState.value = AdbState.ErrorConnect
                stopAdbPairingService()
            }
        )
    @Volatile
    private var pairingReceiverRegistered = false

    fun startAdbPairingService() {
        if (!pairingReceiverRegistered) {
            val filter = IntentFilter(AdbPairingService.ACTION_PAIRING_RESULT)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                appContext.registerReceiver(adbPairingReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                @Suppress("UnspecifiedRegisterReceiverFlag")
                appContext.registerReceiver(adbPairingReceiver, filter)
            }
            pairingReceiverRegistered = true
        }

        val pairingIntent = AdbPairingService.startIntent(appContext)
        try {
            appContext.startForegroundService(pairingIntent)
        } catch (_: Throwable) {
            appContext.startService(pairingIntent)
        }
    }

    fun stopAdbPairingService() {
        if (pairingReceiverRegistered) {
            try {
                appContext.unregisterReceiver(adbPairingReceiver)
            } catch (_: IllegalArgumentException) {
            } catch (e: Exception) {
                Log.e(TAG, "error unregistering pairing receiver", e)
            } finally {
                pairingReceiverRegistered = false
            }
        }
        appContext.stopService(AdbPairingService.stopIntent(appContext))
    }

    fun autoConnect() {
        val state = _adbState.value
        if (state in arrayOf(
                AdbState.ConnectedIdle,
                AdbState.ConnectedAcquiring,
                AdbState.Connecting
            )
        ) return
        executor.submit { autoConnectInternal() }
    }

    private fun autoConnectInternal() {
        try {
            if (adbConnectionManager.isConnected) {
                _adbState.value = AdbState.ConnectedIdle
                return
            }
            _adbState.value = AdbState.Connecting
            val connected = adbConnectionManager.connectTls(appContext, 5000)
            _adbState.value = if (connected) AdbState.ConnectedIdle else AdbState.Ready
        } catch (_: AdbPairingRequiredException) {
            _adbState.value = AdbState.RequisitesMissing
        } catch (t: Throwable) {
            Log.e(TAG, "autoConnect failed", t)
            _adbState.value = AdbState.ErrorConnect
        }
    }

    suspend fun runCommand(command: String): String = withContext(Dispatchers.IO) {
        try {
            if (!adbConnectionManager.isConnected) {
                return@withContext "Not connected. Pair and connect first."
            }
            val stream = adbConnectionManager.openStream("shell:$command")
            val out = StringBuilder()
            try {
                stream.openInputStream().bufferedReader().use { reader ->
                    val buf = CharArray(1024)
                    while (true) {
                        val n = try {
                            reader.read(buf)
                        } catch (io: IOException) {
                            // Some devices close ADB streams aggressively after command completion.
                            if (io.message?.contains("Stream closed", ignoreCase = true) == true) {
                                break
                            }
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
            out.toString().ifBlank { "(no output)" }
        } catch (t: Throwable) {
            Log.e(TAG, "runCommand failed", t)
            "Command failed: ${t.message}"
        }
    }

    fun cleanup() {
        stopAdbPairingService()
        executor.shutdown()
    }
}
