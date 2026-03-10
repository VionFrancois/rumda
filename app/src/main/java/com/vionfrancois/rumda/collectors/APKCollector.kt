package com.vionfrancois.rumda.collectors

import android.content.Context
import android.util.Log
import com.vionfrancois.rumda.cadb.AdbManager
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

class APKCollector(
    private val adbManager: AdbManager,
    context: Context
) : StateCollector {

    private val prefs = context.getSharedPreferences("apk_collector_state", Context.MODE_PRIVATE)
    private var lastCollectedRaw: String? = null

    private companion object {
        const val TAG = "APKCollector"
    }

    data class PackageEntry(
        val packageName: String,
        val apkPath: String
    )

    override suspend fun collect(): String {
        val output = adbManager.runCommand("pm list packages -f")
        lastCollectedRaw = output
        Log.d(TAG, output)
        return output
    }


    override fun saveState() {
        val raw = lastCollectedRaw ?: return
        val parsed = parsePackageList(raw) // TODO : Need to sort ?
        val json = serializePackageList(parsed)
        val hash = sha256(json)

        prefs.edit()
            .putString("last_apk_list", json)
            .putString("last_hash", hash)
            .apply()
    }

    override fun fetchLastState(): String? {
        return prefs.getString("last_hash", null)
    }


    override fun pushToRemote(content: String) {
        TODO("Not yet implemented")
    }

    fun fetchLastApkList(): List<PackageEntry> {
        val json = prefs.getString("last_apk_list", null) ?: return emptyList()
        return deserializePackageList(json)
    }

    fun parsePackageList(raw: String): List<PackageEntry> {
        return raw.lineSequence()
            .map { it.trim() }
            .filter { it.startsWith("package:") && it.contains("=") }
            .mapNotNull { line ->
                val body = line.removePrefix("package:")
                val parts = body.split("=", limit = 2)
                if (parts.size != 2) {
                    null
                } else {
                    PackageEntry(
                        apkPath = parts[0],
                        packageName = parts[1]
                    )
                }
            }
            .toList()
    }

    private fun serializePackageList(list: List<PackageEntry>): String {
        val jsonArray = JSONArray()
        for (item in list) {
            jsonArray.put(
                JSONObject()
                    .put("packageName", item.packageName)
                    .put("apkPath", item.apkPath)
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
            if (packageName.isNotBlank() && apkPath.isNotBlank()) {
                result.add(PackageEntry(packageName = packageName, apkPath = apkPath))
            }
        }
        return result
    }

    private fun sha256(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
        return digest.joinToString(separator = "") { "%02x".format(it) }
    }

}
