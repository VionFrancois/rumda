package com.vionfrancois.rumda.collectors

import android.content.Context
import android.util.Log
import com.vionfrancois.rumda.MainActivity
import com.vionfrancois.rumda.cadb.AdbManager
import com.vionfrancois.rumda.threats.ThreatKind
import com.vionfrancois.rumda.threats.ThreatNotificationHelper
import com.vionfrancois.rumda.threats.ThreatRecord
import com.vionfrancois.rumda.threats.ThreatStoring
import com.vionfrancois.rumda.threats.ThreatSeverity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

class APKCollector(
    private val adbManager: AdbManager,
    context: Context,
    private val threatStoring: ThreatStoring,
) : StateCollector() {

    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences("apk_collector_state", Context.MODE_PRIVATE)
    private val threatNotificationHelper = ThreatNotificationHelper(appContext)
    private var lastCollectedRaw: String? = null
    private var lastCollectedEntries: List<PackageEntry> = emptyList()
    private var lastPulledApk: File? = null

    private companion object {
        const val TAG = "APKCollector"
        const val PREF_LAST_APK_LIST = "last_apk_list"
        const val MAX_ANALYSIS_PER_TICK = 10

        val HTTP_CLIENT: OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.MINUTES)
            .readTimeout(15, TimeUnit.MINUTES)
            .callTimeout(20, TimeUnit.MINUTES)
            .build()
    }

    data class PackageEntry(
        val packageName: String,
        val apkPath: String,
        val lastUpdateDate: String,
        val givenPermisions: List<String>, // TODO : Make the permissions an enumeration ?,
        var lastAnalysis: APKAnalysis?
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is PackageEntry) return false

            return packageName == other.packageName &&
                apkPath == other.apkPath &&
                lastUpdateDate == other.lastUpdateDate
                // TODO: put permissions back
                // && givenPermisions.sorted() == other.givenPermisions.sorted()
        }
    }

    data class APKAnalysis(
        val found: Boolean,
        val analysisType: String,
        val malicious: Boolean,
        val degree: String,
        val details: Map<String, Any?>
    ) {
        fun toJson(): JSONObject {
            val detailsJson = JSONObject()
            for ((key, value) in details) {
                detailsJson.put(key, value)
            }

            return JSONObject()
                .put("found", found)
                .put("analysisType", analysisType)
                .put("malicious", malicious)
                .put("degree", degree)
                .put("details", detailsJson)
        }
    }

    override fun fetchLastState(): Pair<List<PackageEntry>, Boolean>{
        val json = prefs.getString(PREF_LAST_APK_LIST, null) ?: return Pair(emptyList(), false)
        return deserializePackageList(json)
    }

    override suspend fun collectState(): List<PackageEntry> { // TODO : Also return an hash later ?
        val packageListOutput = adbManager.runCommand("pm list packages -f")
        lastCollectedRaw = packageListOutput
        val packageList = parsePackageList(packageListOutput)
        Log.d(TAG, "Found ${packageList.size} packages")


        val apkCollection = mutableListOf<PackageEntry>()

        var i = 0
        for (pkg in packageList) {
            val packageOutput = adbManager.runCommand("dumpsys package ${pkg[0]}")
            val lastUpdateDate = parseLastUpdateTime(packageOutput)
            // TODO: put permissions back
            // val grantedPermissions = parseGrantedPermissions(packageOutput)

            val packageEntry = PackageEntry(
                packageName = pkg[0],
                apkPath = pkg[1],
                lastUpdateDate = lastUpdateDate,
                // TODO: put permissions back
                // givenPermisions = grantedPermissions,
                givenPermisions = emptyList(),
                lastAnalysis = null
            )
            apkCollection.add(packageEntry)
            i++
        }

        val normalizedEntries = normalizeEntries(apkCollection)
        return normalizedEntries
    }

    override suspend fun pushDiffToRemote(oldState: List<PackageEntry>, newState: MutableList<PackageEntry>): Pair<List<ThreatRecord>, MutableList<PackageEntry>> {
        recoverAnalysesFromPreviousState(oldState, newState)

        // Find changes
        val (addedEntries, changedEntries) = diffStates(oldState, newState)

        val threats = mutableListOf<ThreatRecord>()

        var i = 0
        // Ask analysis for changed APK
        for (added in addedEntries) {
            Log.d(TAG, "Processing ${i} of $MAX_ANALYSIS_PER_TICK : ${added.packageName}")
            val analysis = runCatching { requestAPKAnalysis(added.apkPath) }
                .getOrElse { error ->
                    Log.w(TAG, "Analysis failed for ${added.packageName}: ${error.message}")
                    null
                }
            val index = newState.indexOf(added)
            newState[index] = added.copy(lastAnalysis = analysis)
            if (analysis?.malicious == true) {
                threats.add(
                    buildApkThreat(
                        packageName = added.packageName,
                        rawDegree = analysis.degree,
                    )
                )
            }
            i++
            if(i >= MAX_ANALYSIS_PER_TICK){
                // We want to avoid huge processing
                break
            }
        }

        i = 0
        for (modified in changedEntries) {
            Log.d(TAG, "Processing ${i} of $MAX_ANALYSIS_PER_TICK : ${modified.packageName}")
            val analysis = runCatching { requestAPKAnalysis(modified.apkPath) }
                .getOrElse { error ->
                    Log.w(TAG, "Analysis failed for ${modified.packageName}: ${error.message}")
                    null
                }
            val index = newState.indexOf(modified)
            newState[index] = modified.copy(lastAnalysis = analysis)
            if (analysis?.malicious == true) {
                threats.add(
                    buildApkThreat(
                        packageName = modified.packageName,
                        rawDegree = analysis.degree,
                    )
                )
            }
            i++
            if(i >= MAX_ANALYSIS_PER_TICK){
                // We want to avoid huge processing
                break
            }
        }

        return Pair(threats, newState)
    }

    private fun recoverAnalysesFromPreviousState(
        oldState: List<PackageEntry>,
        newState: MutableList<PackageEntry>
    ) {
        val oldByPackageName = oldState.associateBy { it.packageName }

        for (index in newState.indices) {
            val currentEntry = newState[index]
            val oldEntry = oldByPackageName[currentEntry.packageName] ?: continue

            if (
                currentEntry.lastAnalysis == null &&
                oldEntry.lastAnalysis != null &&
                currentEntry.lastUpdateDate == oldEntry.lastUpdateDate
            ) {
                newState[index] = currentEntry.copy(lastAnalysis = oldEntry.lastAnalysis)
            }
        }
    }

    override suspend fun handleVerdict(response: List<ThreatRecord>) {
        if (response.isEmpty()) return

        val insertedThreatCount = threatStoring.addActiveThreats(response)
        if (insertedThreatCount > 0) {
            threatNotificationHelper.notifyThreatDetected(insertedThreatCount)
        }
    }

    private fun buildApkThreat(packageName: String, rawDegree: String): ThreatRecord {
        return threatStoring.buildThreat(
            kind = ThreatKind.APK,
            title = packageName,
            summary = "Potential malicious APK detected",
            severity = mapDegreeToSeverity(rawDegree),
            sourceCollector = "APKS",
            attributes = emptyMap(), // TODO : Add report ?
        )
    }

    private fun mapDegreeToSeverity(rawDegree: String): ThreatSeverity {
        val normalized = rawDegree.trim().uppercase()
        return when {
            normalized.contains("CRIT") -> ThreatSeverity.CRITICAL
            normalized.contains("HIGH") -> ThreatSeverity.HIGH
            normalized.contains("MEDIUM") -> ThreatSeverity.MEDIUM
            normalized.contains("LOW") -> ThreatSeverity.LOW
            else -> ThreatSeverity.MEDIUM
        }
    }


    override fun saveState(state: List<PackageEntry>) {
        lastCollectedEntries = normalizeEntries(state)
        val normalizedEntries = lastCollectedEntries
        val json = serializePackageList(normalizedEntries)

        prefs.edit()
            .putString(PREF_LAST_APK_LIST, json)
            .apply()
        Log.d(TAG, "Saved state")
    }


    suspend fun requestAPKAnalysis(packagePath: String): APKAnalysis = withContext(Dispatchers.IO) {
        Log.d(TAG, "Requested APK Analysis for $packagePath")
        val filename = packagePath.substringAfterLast("/")
        var localFile: File? = null

        try {
            val sha256Hash = computeRemoteSha256(packagePath)
                ?: run {
                    Log.w(TAG, "Remote SHA-256 unavailable for $packagePath, pulling APK to hash locally")
                    val pulledFile = File(appContext.cacheDir, filename)
                    try {
                        adbManager.pullFile(remotePath = packagePath, destination = pulledFile)
                    } catch (t: Throwable) {
                        throw IOException("ADB pull failed for $packagePath", t)
                    }
                    localFile = pulledFile
                    lastPulledApk = pulledFile
                    sha256File(pulledFile)
                }

            val hashBody = JSONObject()
                .put("hash", sha256Hash)
                .toString()

            val hashRequest = Request.Builder()
                .url("${MainActivity.SERVER_BASE_URL}/analysis/apk/hash")
                .post(
                    hashBody.toRequestBody(
                        "application/json; charset=utf-8".toMediaType()
                    )
                )
                .build()

            val hashResponseBody = HTTP_CLIENT.newCall(hashRequest).execute().use { response ->
                response.body?.string().orEmpty()
            }

            Log.d(TAG, "ResponseBody : ${hashResponseBody}")

            val hashFound = runCatching {
                JSONObject(hashResponseBody).optBoolean("found", false)
            }.getOrDefault(false)

            // If the hash is not found on the API
            val responseBody = if (!hashFound) {
                if (localFile == null) {
                    val pulledFile = File(appContext.cacheDir, filename)
                    try {
                        adbManager.pullFile(remotePath = packagePath, destination = pulledFile)
                    } catch (t: Throwable) {
                        throw IOException("ADB pull failed for upload $packagePath", t)
                    }
                    localFile = pulledFile
                    lastPulledApk = pulledFile
                }

                val fileRequestBody = localFile!!.asRequestBody(
                    "application/vnd.android.package-archive".toMediaType()
                )
                val multipartBody = MultipartBody.Builder()
                    .setType(MultipartBody.FORM)
                    .addFormDataPart("file", localFile!!.name, fileRequestBody)
                    .build()

                val fileRequest = Request.Builder()
                    .url("${MainActivity.SERVER_BASE_URL}/analysis/apk/file")
                    .post(multipartBody)
                    .build()

                Log.d(TAG, "Uploading $packagePath and waiting for server verdict")

                HTTP_CLIENT.newCall(fileRequest).execute().use { response ->
                    val fileResponseBody = response.body?.string().orEmpty()
                    if (!response.isSuccessful) {
                        throw IOException("File analysis failed with HTTP ${response.code}: $fileResponseBody")
                    }
                    fileResponseBody
                }
            } else {
                hashResponseBody
            }

            Log.d(TAG, responseBody)
            parseAPKAnalysis(responseBody)
        } finally {
            if (localFile?.exists() == true && !localFile!!.delete()) {
                Log.w(TAG, "Failed to delete cached APK ${localFile!!.absolutePath}")
            }
            if (lastPulledApk?.absolutePath == localFile?.absolutePath) {
                lastPulledApk = null
            }
        }
    }

    private suspend fun computeRemoteSha256(packagePath: String): String? {
        val quotedPath = shellSingleQuote(packagePath)
        val command = "sha256sum $quotedPath 2>/dev/null"
        val output = adbManager.runCommand(command)
        if (output.startsWith("Command failed:", ignoreCase = true)) {
            return null
        }
        val firstLine = output.lineSequence().firstOrNull()?.trim().orEmpty()
        val candidate = firstLine.substringBefore(' ').trim()
        return if (candidate.matches(Regex("^[a-fA-F0-9]{64}$"))) {
            candidate.lowercase()
        } else {
            null
        }
    }

    private fun shellSingleQuote(value: String): String {
        val escaped = value.replace("'", "'\"'\"'")
        return "'$escaped'"
    }

    private fun parseAPKAnalysis(responseBody: String): APKAnalysis {
        val responseJson = JSONObject(responseBody)
        val detailsJson = responseJson.optJSONObject("details") ?: JSONObject()
        val details = buildMap<String, Any?> {
            val keys = detailsJson.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                put(key, detailsJson.opt(key))
            }
        }

        return APKAnalysis(
            found = responseJson.optBoolean("found", false),
            analysisType = responseJson.optString("analysis_type"),
            malicious = responseJson.optBoolean("malicious", false),
            degree = responseJson.optString("degree"),
            details = details
        )
    }

    private fun parsePackageList(input: String): List<List<String>> {
        return input.lines()
            .filter { it.startsWith("package:") }
            .mapNotNull { line ->
                val withoutPrefix = line.removePrefix("package:")
                val separatorIndex = withoutPrefix.lastIndexOf('=')
                if (separatorIndex <= 0 || separatorIndex == withoutPrefix.lastIndex) {
                    Log.w(TAG, "parsePackageList(): unable to parse line `$line`")
                    return@mapNotNull null
                }
                val path = withoutPrefix.substring(0, separatorIndex)
                val name = withoutPrefix.substring(separatorIndex + 1)
                listOf(name, path)
            }
    }

    private fun parseLastUpdateTime(input: String): String {
        return input.lines()
            .firstOrNull { it.contains("lastUpdateTime=") }
            ?.trimStart()
            ?.removePrefix("lastUpdateTime=")
            ?: ""
    }

    private fun parseGrantedPermissions(input: String): List<String> {
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
                    // TODO: put permissions back
                    // .put("givenPermissions", item.givenPermisions)
                    .put("lastAnalysis", item.lastAnalysis?.toJson())
            )
        }
        return jsonArray.toString()
    }

    private fun deserializePackageList(json: String): Pair<List<PackageEntry>, Boolean> {
        val array = JSONArray(json)
        val result = mutableListOf<PackageEntry>()
        var isComplete = true
        for (i in 0 until array.length()) {
            val obj = array.optJSONObject(i) ?: continue
            val packageName = obj.optString("packageName")
            val apkPath = obj.optString("apkPath")
            val lastUpdateDate = obj.optString("lastUpdateDate")

            val givenPermissions = mutableListOf<String>()
            // TODO: put permissions back
            // val permissionsArray = obj.optJSONArray("givenPermissions")
            // if (permissionsArray != null) {
            //     for (j in 0 until permissionsArray.length()) {
            //         givenPermissions.add(permissionsArray.getString(j))
            //     }
            // }

            val lastAnalysis = obj.optJSONObject("lastAnalysis")?.let { analysisJson ->
                APKAnalysis(
                    found = analysisJson.optBoolean("found", false),
                    analysisType = analysisJson.optString("analysisType"),
                    malicious = analysisJson.optBoolean("malicious", false),
                    degree = analysisJson.optString("degree"),
                    details = analysisJson.optJSONObject("details")?.toMap().orEmpty()
                )
            }

            if(lastAnalysis == null){
                isComplete = false
            }


            if (packageName.isNotBlank() && apkPath.isNotBlank()) {
                result.add(PackageEntry(packageName, apkPath, lastUpdateDate, givenPermissions, lastAnalysis))
            }
        }
        return Pair(result, isComplete)
    }

    private fun diffStates(oldEntries: List<PackageEntry>, newEntries: List<PackageEntry>): Pair<List<PackageEntry>, List<PackageEntry>> {
        val oldMap = normalizeEntries(oldEntries).associateBy { it.packageName }
        val newMap = normalizeEntries(newEntries).associateBy { it.packageName }

        val oldKeys = oldMap.keys
        val newKeys = newMap.keys

        val packagesNeedingAnalysis = (oldKeys intersect newKeys)
            .filter { packageName -> oldMap[packageName]?.lastAnalysis == null }
            .toSet()

        Log.d(TAG, "packages needing analysis : ${packagesNeedingAnalysis}")

        val addedPackageNames = (newKeys - oldKeys) + packagesNeedingAnalysis

        val added = addedPackageNames
            .mapNotNull(newMap::get)
            .sortedBy { it.packageName }
        val changed = (oldKeys intersect newKeys)
            .filterNot { it in addedPackageNames }
            .mapNotNull { packageName ->
                val oldEntry = oldMap.getValue(packageName)
                val newEntry = newMap.getValue(packageName)

                if (oldEntry != newEntry) {
                    newEntry
                } else {
                    null
                }
            }
            .sortedBy { it.packageName }

        return added to changed
    }

    private fun normalizeEntries(entries: List<PackageEntry>): List<PackageEntry> {
        return entries
            // TODO: put permissions back
            // .map { entry ->
            //     entry.copy(givenPermisions = entry.givenPermisions.sorted())
            // }
            .sortedBy { it.packageName }
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

    private fun JSONObject.toMap(): Map<String, Any?> {
        val result = mutableMapOf<String, Any?>()
        val keys = keys()
        while (keys.hasNext()) {
            val key = keys.next()
            result[key] = opt(key)
        }
        return result
    }

}
