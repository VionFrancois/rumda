package com.vionfrancois.rumda.cadb

import android.util.Log
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.util.ArrayDeque
import java.util.UUID
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

class AdbShell(
    private val manager: AdbConnectionManager,
    private val tag: String = "AdbShell",
    private val timeoutMs: Long = 30_000L,
    private val inactivityMs: Long = 5_000L,
    private val retries: Int = 1,
) {
    fun exec(command: String): String {
        val output = ByteArrayOutputStream()
        execInternal(command, output)
        val result = output.toString(StandardCharsets.UTF_8.name()).trimEnd()
        return result.ifBlank { "(no output)" }
    }

    private fun execInternal(command: String, sink: ByteArrayOutputStream) {
        var lastError: Throwable? = null
        repeat(retries + 1) { attempt ->
            try {
                val marker = "__RUMDA__${UUID.randomUUID()}__EOX__"
                val script = "LC_ALL=C; exec 2>&1; { $command ; }; /system/bin/printf \"%s\\n\" \"$marker\""
                val wrapped = "/system/bin/sh -c ${shSingleQuote(script)}"
                val found = runWithStream("shell:$wrapped", sink, marker)
                if (!found) {
                    Log.w(tag, "[exec] Marker not seen; accepting collected output")
                }
                return
            } catch (t: Throwable) {
                lastError = t
                Log.w(tag, "[exec] attempt ${attempt + 1} failed: ${t.message}")
            }
        }
        throw IOException("All shell command attempts failed", lastError)
    }

    private fun runWithStream(command: String, sink: ByteArrayOutputStream, marker: String): Boolean {
        val stream = manager.openStream(command)
        val input = stream.openInputStream().buffered()
        val readerExecutor = Executors.newSingleThreadExecutor { Thread(it, "ShellReader").apply { isDaemon = true } }

        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        val markerBytes = marker.toByteArray(StandardCharsets.UTF_8)
        val sliding = ArrayDeque<Byte>(markerBytes.size)
        val startTime = System.nanoTime()
        var markerMatched = false

        try {
            while (true) {
                if (System.nanoTime() - startTime > TimeUnit.MILLISECONDS.toNanos(timeoutMs)) {
                    throw IOException("Shell command timed out: $command")
                }

                val bytesRead = try {
                    readOnceWithTimeout(readerExecutor, input, buffer, inactivityMs)
                } catch (_: TimeoutException) {
                    break
                }

                if (bytesRead < 0) {
                    break
                }

                var writeUntil = bytesRead
                for (i in 0 until bytesRead) {
                    sliding.addLast(buffer[i])
                    if (sliding.size > markerBytes.size) sliding.removeFirst()

                    if (sliding.size == markerBytes.size && slidingMatches(sliding, markerBytes)) {
                        markerMatched = true
                        writeUntil = i - markerBytes.size + 1
                        break
                    }
                }

                if (writeUntil > 0) {
                    sink.write(buffer, 0, writeUntil)
                }

                if (markerMatched) {
                    break
                }
            }

            return markerMatched
        } finally {
            readerExecutor.shutdownNow()
            stream.close()
        }
    }

    private fun readOnceWithTimeout(
        executor: ExecutorService,
        input: InputStream,
        buffer: ByteArray,
        timeoutMs: Long,
    ): Int {
        val future = executor.submit<Int> { input.read(buffer) }
        return try {
            future.get(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            future.cancel(true)
            throw e
        } catch (e: Exception) {
            future.cancel(true)
            val cause = e.cause
            if (cause is IOException) {
                throw cause
            }
            throw e
        }
    }

    private fun slidingMatches(window: ArrayDeque<Byte>, markerBytes: ByteArray): Boolean {
        if (window.size != markerBytes.size) return false
        var index = 0
        for (byte in window) {
            if (byte != markerBytes[index++]) return false
        }
        return true
    }

    private fun shSingleQuote(text: String): String {
        val escaped = text.replace("'", "'\"'\"'")
        return "'$escaped'"
    }
}
