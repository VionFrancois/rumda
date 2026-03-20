package com.vionfrancois.rumda.collectors

import android.content.Context
import android.util.Log
import com.vionfrancois.rumda.MainActivity
import com.vionfrancois.rumda.cadb.AdbManager
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

class APKCollector(
    private val adbManager: AdbManager,
    context: Context
) : StateCollector {

    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences("apk_collector_state", Context.MODE_PRIVATE)
    private var lastCollectedRaw: String? = null
    private var lastCollectedEntries: List<PackageEntry> = emptyList()
    private var lastPulledApk: File? = null

    private companion object {
        const val TAG = "APKCollector"
        const val PREF_LAST_APK_LIST = "last_apk_list"
        const val PREF_LAST_SNAPSHOT_HASH = "last_snapshot_hash"
    }

    data class PackageEntry(
        val packageName: String,
        val apkPath: String,
        val lastUpdateDate: String,
        val givenPermisions: List<String>, // TODO : Make the permissions an enumeration ?,
        var lastVerdict: String?
    )

    override suspend fun collect(): List<PackageEntry> {
        val output = adbManager.runCommand("pm list packages -f")
        lastCollectedRaw = output
        val packageList = parsePackageList(output)

        val apkCollection = mutableListOf<PackageEntry>()

        Log.d(TAG, "Taille de liste ${packageList.size}")
        var i = 0
        for (pkg in packageList) {
            val packageOutput = adbManager.runCommand("dumpsys package ${pkg[0]}")
            val lastUpdateDate = parseLastUpdateTime(packageOutput)
            val grantedPermissions = parseGrantedPermissions(packageOutput)

            val packageEntry = PackageEntry(
                packageName = pkg[0],
                apkPath = pkg[1],
                lastUpdateDate = lastUpdateDate,
                givenPermisions = grantedPermissions,
                lastVerdict = null
            )
            apkCollection.add(packageEntry)
            Log.d(TAG, "Created Entry for ${pkg[0]} ${packageList.size - i - 1} remaining")
            i++
        }
        Log.d(TAG, "Sorti de la boucle de création")

        val normalizedEntries = normalizeEntries(apkCollection)
        return normalizedEntries
    }


    override fun saveState() {
        if (lastCollectedEntries.isEmpty()) {
            return
        }

        val normalizedEntries = normalizeEntries(lastCollectedEntries)
        val json = serializePackageList(normalizedEntries)
        val hash = stateHash(normalizedEntries)

        prefs.edit()
            .putString(PREF_LAST_APK_LIST, json)
            .putString(PREF_LAST_SNAPSHOT_HASH, hash)
            .apply()
    }


    suspend fun pushToRemote(newState: MutableList<PackageEntry>) {
        // Find changes
        val oldState = fetchLastApkList()
        val changes = diffStates(oldState, newState)

        // Ask analysis for changed APK
        for(added in changes[0]){
            val verdict = requestAPKAnalysis(added.apkPath)
            // TODO : Trigger notification ?
            val index = newState.indexOf(added)
            newState[index] = added.copy(lastVerdict = verdict)
        }

        for(modified in changes[1]){
            val verdict = requestAPKAnalysis(modified.apkPath)
            // TODO : Trigger notification ?
            val index = newState.indexOf(modified)
            newState[index] = modified.copy(lastVerdict = verdict)
        }
    }

    suspend fun requestAPKAnalysis(packagePath: String): String{
        val filename = packagePath.substringAfterLast("/")
        val localFile = File(appContext.cacheDir,filename)

        Log.d(TAG, "Trying adb sync pull")
        adbManager.pullFile(remotePath = packagePath, destination = localFile)
        lastPulledApk = localFile
        Log.d(TAG, "Pulled APK to ${localFile.absolutePath}")

        val hashUrl = java.net.URL("${MainActivity.SERVER_BASE_URL}/analysis/apk/hash")
        val hashConnection = (hashUrl.openConnection() as java.net.HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
        }

        val sha256Hash = sha256File(localFile)
        Log.d(TAG, sha256Hash)

        val hashBody = JSONObject()
            .put("hash", sha256Hash)
            .toString()

        hashConnection.outputStream.bufferedWriter().use { it.write(hashBody) }

        val responseCode = hashConnection.responseCode

        // If the hash is not found on the API
        val responseBody = if (responseCode == 502) {
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
                    "Content-Disposition: form-data; name=\"file\"; filename=\"${localFile.name}\"\r\n".toByteArray()
                )
                output.write("Content-Type: application/vnd.android.package-archive\r\n\r\n".toByteArray())
                localFile.inputStream().use { input -> input.copyTo(output) }
                output.write("\r\n--$boundary--\r\n".toByteArray())
            }

            fileConnection.inputStream.bufferedReader().use { it.readText() }.also {
                fileConnection.disconnect()
            }
        } else {
            hashConnection.inputStream.bufferedReader().use { it.readText() }
        }

        hashConnection.disconnect()

        Log.d(TAG, responseBody)
        return responseBody
    }

    fun fetchLastApkList(): List<PackageEntry> {
        val json = prefs.getString(PREF_LAST_APK_LIST, null) ?: return emptyList()
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

    private fun diffStates(oldEntries: List<PackageEntry>, newEntries: List<PackageEntry>): List<List<PackageEntry>> {
        val oldMap = normalizeEntries(oldEntries).associateBy { it.packageName }
        val newMap = normalizeEntries(newEntries).associateBy { it.packageName }

        val oldKeys = oldMap.keys
        val newKeys = newMap.keys

        val added = (newKeys - oldKeys)
            .mapNotNull(newMap::get)
            .sortedBy { it.packageName }
        val removed = (oldKeys - newKeys)
            .mapNotNull(oldMap::get)
            .sortedBy { it.packageName }
        val changed = (oldKeys intersect newKeys)
            .mapNotNull { packageName ->
                val oldEntry = oldMap.getValue(packageName)
                val newEntry = newMap.getValue(packageName)

                if (entryHash(oldEntry) != entryHash(newEntry)) {
                    newEntry
                } else {
                    null
                }
            }
            .sortedBy { it.packageName }

        return listOf(added, removed, changed)
    }

    private fun normalizeEntries(entries: List<PackageEntry>): List<PackageEntry> {
        return entries
            .map { entry ->
                entry.copy(givenPermisions = entry.givenPermisions.sorted())
            }
            .sortedBy { it.packageName }
    }

    private fun entryHash(entry: PackageEntry): String {
        val normalizedPermissions = entry.givenPermisions.sorted().joinToString("|")
        val raw = listOf(
            entry.packageName,
            entry.apkPath,
            entry.lastUpdateDate,
            normalizedPermissions,
            entry.lastVerdict.orEmpty()
        ).joinToString("||")
        return sha256(raw)
    }

    private fun stateHash(entries: List<PackageEntry>): String {
        val raw = normalizeEntries(entries)
            .joinToString("\n") { entry -> "${entry.packageName}:${entryHash(entry)}" }
        return sha256(raw)
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
