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
import java.io.File
import java.io.IOException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

private const val TAG = "AdbManager"
private const val RUN_COMMAND_RETRIES = 1
private const val PULL_FILE_RETRIES = 1
private const val SHELL_STAGE_OK_MARKER = "__RUMDA_STAGE_OK__"
private const val ADB_CONNECT_TIMEOUT_MS = 15_000L

class AdbManager(private val appContext: Context) {
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val _adbState = MutableStateFlow<AdbState>(AdbState.Initial)
    val adbState: StateFlow<AdbState> = _adbState.asStateFlow()

    private val adbConnectionManager: AdbConnectionManager =
        AdbConnectionManager.getInstance(appContext) as AdbConnectionManager
    private val adbShell = AdbShell(adbConnectionManager, timeoutMs = 30_000L, inactivityMs = 5_000L, retries = 1)
    private val adbSync = AdbSync(adbConnectionManager)

    init {
        adbConnectionManager.setTimeout(10, TimeUnit.SECONDS)
    }

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
            val connected = adbConnectionManager.connectTls(appContext, ADB_CONNECT_TIMEOUT_MS)
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
            if (!ensureConnected()) {
                return@withContext "Not connected. Pair and connect first."
            }
            var lastError: Throwable? = null
            repeat(RUN_COMMAND_RETRIES + 1) { attempt ->
                try {
                    return@withContext adbShell.exec(command)
                } catch (t: Throwable) {
                    lastError = t
                    Log.w(TAG, "runCommand attempt ${attempt + 1} failed for `$command`: ${t.message}")
                    if (attempt < RUN_COMMAND_RETRIES) {
                        reconnectBestEffort()
                    }
                }
            }
            "Command failed: ${lastError?.message ?: "unknown error"}"
        } catch (t: Throwable) {
            Log.e(TAG, "runCommand failed", t)
            "Command failed: ${t.message}"
        }
    }

    suspend fun pullFile(remotePath: String, destination: File): File = withContext(Dispatchers.IO) {
        var lastError: Throwable? = null
        repeat(PULL_FILE_RETRIES + 1) { attempt ->
            try {
                if (!ensureConnected()) {
                    throw IOException("Not connected. Pair and connect first.")
                }
                adbSync.pull(remotePath, destination)
                return@withContext destination
            } catch (t: Throwable) {
                lastError = t
                Log.w(TAG, "pullFile attempt ${attempt + 1} failed for `$remotePath`: ${t.message}")

                // For some reason, adb can't pull some files despite they are readable
                // We then fall back to doing "cat > tmpfile" then pulling the tmp file
                if (isPermissionDeniedError(t)) {
                    val pulledByShellStage = runCatching {
                        pullViaShellStaging(remotePath, destination)
                    }.getOrElse { stageError ->
                        Log.w(TAG, "pullFile shell-stage fallback failed for `$remotePath`: ${stageError.message}")
                        false
                    }
                    if (pulledByShellStage) {
                        Log.i(TAG, "pullFile succeeded via shell-stage fallback for `$remotePath`")
                        return@withContext destination
                    }
                }

                if (attempt < PULL_FILE_RETRIES) {
                    reconnectBestEffort()
                }
            }
        }
        Log.e(TAG, "pullFile failed", lastError)
        throw IOException("Sync pull failed: ${lastError?.message}", lastError)
    }

    private fun isPermissionDeniedError(error: Throwable): Boolean {
        val message = error.message.orEmpty()
        return message.contains("permission denied", ignoreCase = true)
    }

    private fun pullViaShellStaging(remotePath: String, destination: File): Boolean {
        val originalFilename = remotePath.substringAfterLast('/').ifBlank { "file.apk" }
        val stagedPath = "/data/local/tmp/rumda_$originalFilename"

        val src = shSingleQuote(remotePath)
        val dst = shSingleQuote(stagedPath)

        val stageCommand =
            "cat $src > $dst && chmod 0644 $dst && /system/bin/printf \"%s\\n\" \"$SHELL_STAGE_OK_MARKER\""

        return try {
            val stageOutput = adbShell.exec(stageCommand)
            if (!stageOutput.contains(SHELL_STAGE_OK_MARKER)) {
                Log.w(TAG, "shell-stage did not confirm success for `$remotePath`: $stageOutput")
                return false
            }

            adbSync.pull(stagedPath, destination)
            true
        } finally {
            runCatching {
                adbShell.exec("rm -f $dst")
            }
        }
    }

    private fun shSingleQuote(value: String): String {
        val escaped = value.replace("'", "'\"'\"'")
        return "'$escaped'"
    }

    private fun ensureConnected(): Boolean {
        if (adbConnectionManager.isConnected) {
            return true
        }
        return try {
            val connected = adbConnectionManager.connectTls(appContext, 5000)
            if (connected) {
                _adbState.value = AdbState.ConnectedIdle
            }
            connected
        } catch (t: Throwable) {
            Log.w(TAG, "ensureConnected failed", t)
            false
        }
    }

    private fun reconnectBestEffort() {
        try {
            adbConnectionManager.disconnect()
        } catch (_: Throwable) {
        }
        ensureConnected()
    }

    fun handleWirelessDebuggingDisabled() {
        try {
            adbConnectionManager.disconnect()
        } catch (_: Throwable) {
        }

        if (_adbState.value != AdbState.Ready) {
            _adbState.value = AdbState.Ready
        }
    }

    fun cleanup() {
        stopAdbPairingService()
        executor.shutdown()
    }
}
