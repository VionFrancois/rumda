package com.vionfrancois.rumda.cadb

import io.github.muntashirakon.adb.LocalServices
import java.io.EOFException
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import kotlin.math.min

class AdbSync(
    private val manager: AdbConnectionManager,
) {
    @Throws(IOException::class)
    fun pull(remotePath: String, localDest: File) {
        val temp = File(localDest.parentFile, localDest.name + ".part").apply {
            parentFile?.mkdirs()
            delete()
        }

        manager.openStream(LocalServices.SYNC).use { stream ->
            val out = stream.openOutputStream()
            val input = stream.openInputStream()

            val pathBytes = remotePath.toByteArray(StandardCharsets.UTF_8)
            val req = ByteBuffer.allocate(8 + pathBytes.size).order(ByteOrder.LITTLE_ENDIAN)
            req.put(AdbConstants.RECV.toByteArray(StandardCharsets.US_ASCII))
            req.putInt(pathBytes.size)
            req.put(pathBytes)
            out.write(req.array())
            out.flush()

            FileOutputStream(temp).use { fileOut ->
                val header = ByteArray(4)
                val lenBuf = ByteArray(4)
                val buf = ByteArray(8192)

                while (true) {
                    readFully(input, header, 0, 4)
                    val cmd = String(header, StandardCharsets.US_ASCII)

                    when (cmd) {
                        AdbConstants.DATA -> {
                            readFully(input, lenBuf, 0, 4)
                            var remaining = ByteBuffer.wrap(lenBuf).order(ByteOrder.LITTLE_ENDIAN).int
                            while (remaining > 0) {
                                val chunk = min(remaining, buf.size)
                                readFully(input, buf, 0, chunk)
                                fileOut.write(buf, 0, chunk)
                                remaining -= chunk
                            }
                        }

                        AdbConstants.DONE -> {
                            readFully(input, lenBuf, 0, 4)
                            break
                        }

                        AdbConstants.FAIL -> {
                            readFully(input, lenBuf, 0, 4)
                            val msgLen = ByteBuffer.wrap(lenBuf).order(ByteOrder.LITTLE_ENDIAN).int
                            val msgBytes = ByteArray(msgLen)
                            readFully(input, msgBytes, 0, msgLen)
                            val msg = String(msgBytes, StandardCharsets.UTF_8)
                            throw IOException("Sync failed: $msg")
                        }

                        else -> throw IOException("Unexpected sync response: $cmd")
                    }
                }
            }
        }

        if (localDest.exists()) localDest.delete()
        if (!temp.renameTo(localDest)) temp.copyTo(localDest, overwrite = true)
        temp.delete()
    }

    private fun readFully(input: InputStream, buffer: ByteArray, offset: Int, length: Int) {
        var off = offset
        var remaining = length
        while (remaining > 0) {
            val read = input.read(buffer, off, remaining)
            if (read < 0) throw EOFException()
            off += read
            remaining -= read
        }
    }
}
