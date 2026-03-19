package com.vionfrancois.rumda.collectors

import android.content.Context
import android.util.Log
import com.vionfrancois.rumda.MainActivity
import com.vionfrancois.rumda.cadb.AdbManager
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

class APKCollector(
    private val adbManager: AdbManager,
    context: Context
) : StateCollector {

    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences("apk_collector_state", Context.MODE_PRIVATE)
    private var lastCollectedRaw: String? = null
    private var lastPulledApk: File? = null

    private companion object {
        const val TAG = "APKCollector"
    }

    data class PackageEntry(
        val packageName: String,
        val apkPath: String,
        val lastUpdateDate: String,
        val givenPermisions: List<String>, // TODO : Make the permissions an enumeration ?,
        val lastVerdict: String?
    )

    override suspend fun collect(): String {
        // Collect package list
        val output = adbManager.runCommand("pm list packages -f")
        lastCollectedRaw = output
        Log.d(TAG, output)
        val packageList = parsePackageList(output)

        val apkCollection = mutableListOf<PackageEntry>()

        for (pkg in packageList){
            // Search the lastInstallationDate
            val output = adbManager.runCommand("dumpsys package ${pkg[0]}")
            val lastUpdateDate = parseLastUpdateTime(output)

            val grantedPermissions = parseGrantedPermissions(output)

            val packageEntry = PackageEntry(pkg[0], pkg[1], lastUpdateDate, grantedPermissions, null)
            apkCollection.add(packageEntry)
        }
        // Create JSON of the state
        val state = serializePackageList(apkCollection)

        return state
    }


    override fun saveState() {
//        val raw = lastCollectedRaw ?: return
//        val parsed = parsePackageList(raw) // TODO : Need to sort ?
//        val json = serializePackageList(parsed)
//        val hash = sha256(json)
//
//        prefs.edit()
//            .putString("last_apk_list", json)
//            .putString("last_hash", hash)
//            .apply()
    }

    override fun fetchLastState(): String? {
        return prefs.getString("last_hash", null)
    }


    override fun pushToRemote(content: String) {
        // TODO : Implement diff check
        // TODO : Implement loop
        //        val apkPath = "/product/app/GoogleContacts/GoogleContacts.apk"
//        val localFile = File(appContext.cacheDir,"GoogleContacts.apk")
//
//        Log.d(TAG, "Trying adb sync pull")
//        adbManager.pullFile(remotePath = apkPath, destination = localFile)
//        lastPulledApk = localFile
//        Log.d(TAG, "Pulled sample APK to ${localFile.absolutePath}")
//
//        Log.d(TAG, sha256File(localFile))
        val hashUrl = java.net.URL("${MainActivity.SERVER_BASE_URL}/analysis/apk/hash")
        val hashConnection = (hashUrl.openConnection() as java.net.HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
        }

        val hash = "9a607850b33ca84a9296d280bcf10e02541d269e3723c003baba8d279b0abe15"

        val hashBody = JSONObject()
            .put("hash", hash)
            .toString()

        hashConnection.outputStream.bufferedWriter().use { it.write(hashBody) }

        val responseCode = hashConnection.responseCode

        // If the hash is not found on the API
        if(responseCode == 502){
            // Upload the apk
            val apkFile = lastPulledApk ?: File(appContext.cacheDir, "sample.apk")
            if (!apkFile.exists()) {
                throw IllegalStateException("No APK has been pulled locally yet.")
            }
            val boundary = "Boundary-${System.currentTimeMillis()}"
            val fileUrl = java.net.URL("${MainActivity.SERVER_BASE_URL}/analysis/apk/file")
            val fileConnection = (fileUrl.openConnection() as java.net.HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
            }

            fileConnection.outputStream.use { output ->
                output.write("--$boundary\r\n".toByteArray())
                output.write(
                    "Content-Disposition: form-data; name=\"file\"; filename=\"${apkFile.name}\"\r\n"
                        .toByteArray()
                )
                output.write("Content-Type: application/vnd.android.package-archive\r\n\r\n".toByteArray())
                apkFile.inputStream().use { input -> input.copyTo(output) }
                output.write("\r\n--$boundary--\r\n".toByteArray())
            }

            val fileResponse = fileConnection.inputStream.bufferedReader().use { it.readText() }
            Log.d(TAG, "File endpoint response: $fileResponse")
            fileConnection.disconnect()
        }
        else{
            val hashResponse = hashConnection.inputStream.bufferedReader().use { it.readText() }

            Log.d(TAG, "Hash endpoint response: $hashResponse")

            hashConnection.disconnect()
        }
    }

    fun fetchLastApkList(): List<PackageEntry> {
        val json = prefs.getString("last_apk_list", null) ?: return emptyList()
        return deserializePackageList(json)
    }


    fun parsePackageList(input: String): List<List<String>> {
        return input.lines()
            .filter { it.startsWith("package:") }
            .map { line ->
                val withoutPrefix = line.removePrefix("package:")
                val (path, name) = withoutPrefix.split("=")
                listOf(name, path)
            }
    }

    fun parseLastUpdateTime(input: String): String {
        return input.lines()
            .firstOrNull { it.contains("lastUpdateTime=") }
            ?.trimStart()
            ?.removePrefix("lastUpdateTime=")
            ?: ""
    }

    fun parseGrantedPermissions(input: String): List<String> {
        return input.lines()
            .filter { it.contains("granted=true") }
            .map { it.trimStart().substringBefore(":") }
    }

    private fun serializePackageList(list: List<PackageEntry>): String {
        val jsonArray = JSONArray()
        for (item in list) {
            jsonArray.put(
                JSONObject()
                    .put("packageName", item.packageName)
                    .put("apkPath", item.apkPath)
                    .put("lastUpdateDate", item.lastUpdateDate)
                    .put("givenPermissions", item.givenPermisions)
                    .put("lastVerdict", item.lastVerdict)
            )
        }
        return jsonArray.toString()
    }

    private fun deserializePackageList(json: String): List<PackageEntry> {
        val array = JSONArray(json)
        val result = mutableListOf<PackageEntry>()
        for (i in 0 until array.length()) {
            val obj = array.optJSONObject(i) ?: continue
            val packageName = obj.optString("packageName")
            val apkPath = obj.optString("apkPath")
            val lastUpdateDate = obj.optString("lastUpdateDate")

            val givenPermissions = mutableListOf<String>()
            val permissionsArray = obj.optJSONArray("givenPermissions")
            if (permissionsArray != null) {
                for (j in 0 until permissionsArray.length()) {
                    givenPermissions.add(permissionsArray.getString(j))
                }
            }

            val lastVerdict = obj.optString("lastVerdict").takeIf { it != "null" }

            if (packageName.isNotBlank() && apkPath.isNotBlank()) {
                result.add(PackageEntry(packageName, apkPath, lastUpdateDate, givenPermissions, lastVerdict))
            }
        }
        return result
    }

    private fun sha256(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
        return digest.joinToString(separator = "") { "%02x".format(it) }
    }

    private fun sha256File(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { fis ->
            val buffer = ByteArray(8192)
            var bytesRead: Int
            while (fis.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

}
