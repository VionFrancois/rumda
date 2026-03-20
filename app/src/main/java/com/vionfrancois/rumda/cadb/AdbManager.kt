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
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicReference

private const val TAG = "AdbManager"
private const val RUN_COMMAND_TIMEOUT_MS = 10_000L

class AdbManager(private val appContext: Context) {
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val commandExecutor: ExecutorService = Executors.newCachedThreadPool()
    private val _adbState = MutableStateFlow<AdbState>(AdbState.Initial)
    val adbState: StateFlow<AdbState> = _adbState.asStateFlow()

    private val adbConnectionManager: AdbConnectionManager =
        AdbConnectionManager.getInstance(appContext) as AdbConnectionManager

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
            val streamRef = AtomicReference<io.github.muntashirakon.adb.AdbStream?>()
            val future = commandExecutor.submit<String> {
                val stream = adbConnectionManager.openStream("shell:$command")
                streamRef.set(stream)
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
                    streamRef.set(null)
                }
                out.toString().ifBlank { "(no output)" }
            }

            try {
                future.get(RUN_COMMAND_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            } catch (_: TimeoutException) {
                Log.e(TAG, "runCommand timed out for `$command`")
                try {
                    streamRef.get()?.close()
                } catch (_: Throwable) {
                }
                try {
                    adbConnectionManager.disconnect()
                } catch (_: Throwable) {
                }
                future.cancel(true)
                "Command failed: timeout"
            }
        } catch (t: Throwable) {
            Log.e(TAG, "runCommand failed", t)
            "Command failed: ${t.message}"
        }
    }

    suspend fun pullFile(remotePath: String, destination: File): File = withContext(Dispatchers.IO) {
        try {
            if (!adbConnectionManager.isConnected) {
                throw IOException("Not connected. Pair and connect first.")
            }
            destination.parentFile?.mkdirs()
            val stream = adbConnectionManager.openStream("sync:")
            try {
                val input = stream.openInputStream()
                val output = stream.openOutputStream()

                val pathBytes = remotePath.toByteArray(Charsets.UTF_8)
                // Start an ADB sync "receive file" request for the remote path.
                output.write("RECV".toByteArray(Charsets.US_ASCII))
                writeInt(pathBytes.size, output)
                output.write(pathBytes)
                output.flush()

                destination.outputStream().buffered().use { fileOutput ->
                    val idBuffer = ByteArray(4)
                    val lengthBuffer = ByteArray(4)
                    val chunkBuffer = ByteArray(DEFAULT_BUFFER_SIZE)

                    while (true) {
                        readFully(input, idBuffer, 4)
                        readFully(input, lengthBuffer, 4)

                        // Each sync packet is 4-byte command id + 4-byte little-endian length.
                        val id = String(idBuffer, Charsets.US_ASCII)
                        val length = (lengthBuffer[0].toInt() and 0xff) or
                            ((lengthBuffer[1].toInt() and 0xff) shl 8) or
                            ((lengthBuffer[2].toInt() and 0xff) shl 16) or
                            ((lengthBuffer[3].toInt() and 0xff) shl 24)

                        when (id) {
                            "DATA" -> {
                                // DATA packets contain the next chunk of the remote file.
                                var remaining = length
                                while (remaining > 0) {
                                    val count = input.read(chunkBuffer, 0, minOf(chunkBuffer.size, remaining))
                                    if (count < 0) {
                                        throw IOException("Unexpected end of ADB sync file payload.")
                                    }
                                    fileOutput.write(chunkBuffer, 0, count)
                                    remaining -= count
                                }
                            }
                            "DONE" -> break
                            "FAIL" -> {
                                // FAIL packets return a human-readable error message from adbd.
                                val messageBuffer = ByteArray(length)
                                readFully(input, messageBuffer, length)
                                val message = String(messageBuffer, Charsets.UTF_8)
                                throw IOException("ADB sync failed: $message")
                            }
                            else -> throw IOException("Unexpected ADB sync response: $id")
                        }
                    }
                    fileOutput.flush()
                }
            } finally {
                try {
                    stream.close()
                } catch (_: Throwable) {
                }
            }
            destination
        } catch (t: Throwable) {
            Log.e(TAG, "pullFile failed", t)
            throw IOException("Sync pull failed: ${t.message}", t)
        }
    }

    private fun writeInt(value: Int, output: io.github.muntashirakon.adb.AdbOutputStream) {
        output.write(value and 0xff)
        output.write((value ushr 8) and 0xff)
        output.write((value ushr 16) and 0xff)
        output.write((value ushr 24) and 0xff)
    }

    private fun readFully(input: io.github.muntashirakon.adb.AdbInputStream, buffer: ByteArray, length: Int) {
        var bytesRead = 0
        while (bytesRead < length) {
            val n = input.read(buffer, bytesRead, length - bytesRead)
            if (n < 0) {
                throw IOException("Unexpected end of ADB sync stream.")
            }
            bytesRead += n
        }
    }

    fun cleanup() {
        stopAdbPairingService()
        executor.shutdown()
        commandExecutor.shutdownNow()
    }
}
