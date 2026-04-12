package com.vionfrancois.rumda.collectors

import android.content.Context
import android.util.Log
import com.vionfrancois.rumda.MainActivity
import com.vionfrancois.rumda.cadb.AdbManager
import com.vionfrancois.rumda.threats.ThreatKind
import com.vionfrancois.rumda.threats.ThreatNotificationHelper
import com.vionfrancois.rumda.threats.ThreatRecord
import com.vionfrancois.rumda.threats.ThreatSeverity
import com.vionfrancois.rumda.threats.ThreatStoring
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress
import java.util.concurrent.TimeUnit

class IPCollector(
    private val adbManager: AdbManager,
    context: Context,
) : EventCollector() {

    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val threatStoring = ThreatStoring(appContext)
    private val threatNotificationHelper = ThreatNotificationHelper(appContext)

    private data class NetEvent(
        val protocol: String,
        val uid: Int,
        val remoteIp: String,
        val remotePort: Int,
        val state: String,
    )

    private data class Verdict(
        val ip: String,
        val malicious: Boolean,
        val degree: String,
    )

    private companion object {
        const val TAG = "IPCollector"
        const val SECTION_MARKER = "__PROCNET_FILE__="
        const val PREFS_NAME = "ip_collector_state"
        const val PREF_VERDICT_CACHE = "ip_verdict_cache"
        const val VERDICT_TTL_MS = 24 * 60 * 60 * 1000L

        val HTTP_CLIENT: OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .callTimeout(40, TimeUnit.SECONDS)
            .build()

        val FILES = listOf(
            "/proc/net/tcp",
            "/proc/net/tcp6",
            "/proc/net/udp",
            "/proc/net/udp6",
            "/proc/net/raw",
            "/proc/net/raw6",
        )
    }

    override suspend fun collectEvents(): String {
        // Build command
        val filesArgument = FILES.joinToString(" ")
        val command =  "for f in $filesArgument; do echo \"${SECTION_MARKER}\$f\"; cat \"\$f\"; done"

        val output = adbManager.runCommand(command)

        val connections = parseProcNets(output)
            .distinctBy { "${it.protocol}|${it.uid}|${it.remoteIp}|${it.remotePort}" }

        val json = JSONArray()
        for (event in connections) {
            json.put(
                JSONObject()
                    .put("protocol", event.protocol)
                    .put("uid", event.uid)
                    .put("ip", event.remoteIp)
                    .put("port", event.remotePort)
                    .put("state", event.state)
            )
        }

        Log.d(TAG, json.toString())
        Log.d(TAG, "Collected ${connections.size} network events")
        return json.toString()
    }

    override suspend fun sendForAnalysis(events: String): String {
        Log.d(TAG, "Requesting analysis")
        val eventArray = JSONArray(events)
        if (eventArray.length() == 0) return "[]"

        val now = System.currentTimeMillis()
        val cache = loadVerdictCache()
        val activeCache = mutableMapOf<String, Verdict>()
        val ipsToQuery = linkedSetOf<String>()

        for (i in 0 until eventArray.length()) {
            val item = eventArray.optJSONObject(i) ?: continue
            val ip = item.optString("ip").trim()
            if (ip.isBlank()) continue

            val cached = cache.optJSONObject(ip)
            if (cached != null) {
                val updatedAt = cached.optLong("updatedAt", 0L)
                if ((now - updatedAt) <= VERDICT_TTL_MS) {
                    activeCache[ip] = Verdict(
                        ip = ip,
                        malicious = cached.optBoolean("malicious"),
                        degree = cached.optString("degree"),
                    )
                }
            } else {
                ipsToQuery.add(ip)
            }
        }

        val remoteVerdicts = requestRemoteVerdicts(ipsToQuery.toList())
        for (verdict in remoteVerdicts) {
            activeCache[verdict.ip] = verdict
            cache.put(
                verdict.ip,
                JSONObject()
                    .put("malicious", verdict.malicious)
                    .put("degree", verdict.degree)
                    .put("updatedAt", now),
            )
        }

        pruneCache(cache, now)
        saveVerdictCache(cache)

        // Create JSON list of malicious events
        val maliciousEvents = JSONArray()
        for (i in 0 until eventArray.length()) {
            val event = eventArray.optJSONObject(i)
            val ip = event.optString("ip").trim()
            val verdict = activeCache[ip]
            if(verdict!!.malicious){
                val uid =event.optInt("uid")
                val packages = if (uid >= 0) resolvePackagesByUid(uid) else emptyList()

                maliciousEvents.put(
                    JSONObject()
                        .put("ip", ip)
                        .put("uid", uid)
                        .put("protocol", event.optString("protocol"))
                        .put("port", event.optInt("port"))
                        .put("state", event.optString("state"))
                        .put("degree", verdict.degree)
                        .put("packages", JSONArray(packages))
                )
            }
        }

        return maliciousEvents.toString()
    }

    override suspend fun buildThreats(result: String): List<ThreatRecord> {
        val maliciousEvents = JSONArray(result)
        if (maliciousEvents.length() == 0) return emptyList()

        val threats = mutableListOf<ThreatRecord>()
        for (i in 0 until maliciousEvents.length()) {
            val item = maliciousEvents.optJSONObject(i)
            val ip = item.optString("ip").trim()
            val uid = item.optInt("uid")
            val protocol = item.optString("protocol")
            val degree = item.optString("degree")
            val packages = item.optJSONArray("packages")
            val packageNames = buildList {
                if (packages != null) {
                    for (idx in 0 until packages.length()) {
                        val value = packages.optString(idx).trim()
                        if (value.isNotBlank()) add(value)
                    }
                }
            }

            val title = if (packageNames.isNotEmpty()) {
                packageNames.joinToString(", ")
            } else {
                "UID $uid"
            }

            threats += threatStoring.buildThreat(
                kind = ThreatKind.IP,
                title = title,
                summary = "Potential malicious IP communication detected",
                severity = ThreatSeverity.MEDIUM,
                sourceCollector = "IPS",
                attributes = mapOf(
                    "ip" to ip,
                    "uid" to uid.toString(),
                    "protocol" to protocol,
                    "port" to item.optInt("port").toString(),
                    "degree" to degree,
                    "packages" to packageNames.joinToString(","),
                )
            )
        }

        return threats
    }

    override suspend fun handleThreats(threats: List<ThreatRecord>) {
        if (threats.isEmpty()) return

        val inserted = threatStoring.addActiveThreats(threats)
        if (inserted > 0) {
            threatNotificationHelper.notifyThreatDetected(inserted)
        }
    }

    private fun parseProcNet(raw: String, protocol: String): List<NetEvent> {
        val events = mutableListOf<NetEvent>()
        val lines = raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .toList()
        if (lines.isEmpty()) return emptyList()

        for (line in lines.drop(1)) {
            val columns = line.split(Regex("\\s+"))
            if (columns.size < 8) continue

            val remoteAddressColumn = if (protocol.endsWith("6")) 2 else 2
            val stateColumn = if (protocol.endsWith("6")) 3 else 3
            val uidColumn = 7

            val remote = columns.getOrNull(remoteAddressColumn) ?: continue
            val state = columns.getOrNull(stateColumn).orEmpty()
            val uid = columns.getOrNull(uidColumn)?.toIntOrNull() ?: continue

            val parsedRemote = parseAddress(remote, protocol.endsWith("6")) ?: continue
            if (parsedRemote.second <= 0) continue
            if (isUnspecifiedIp(parsedRemote.first)) continue

            events += NetEvent(
                protocol = protocol,
                uid = uid,
                remoteIp = parsedRemote.first,
                remotePort = parsedRemote.second,
                state = state,
            )
        }
        return events
    }

    private fun parseProcNets(raw: String): List<NetEvent> {
        val events = mutableListOf<NetEvent>()
        val sectionLines = mutableListOf<String>()
        var currentProtocol: String? = null

        fun flushSection() {
            val protocol = currentProtocol ?: return
            if (sectionLines.isEmpty()) return
            val sectionRaw = sectionLines.joinToString("\n")
            events += parseProcNet(sectionRaw, protocol)
            sectionLines.clear()
        }

        for (line in raw.lineSequence()) {
            val trimmed = line.trim()
            if (trimmed.startsWith(SECTION_MARKER)) {
                flushSection()
                val file = trimmed.removePrefix(SECTION_MARKER).trim()
                currentProtocol = file.substringAfterLast('/')
                continue
            }
            if (currentProtocol != null) {
                sectionLines += line
            }
        }

        flushSection()
        return events
    }

    private fun parseAddress(raw: String, isIpv6: Boolean): Pair<String, Int>? {
        val idx = raw.indexOf(':')
        if (idx <= 0 || idx == raw.lastIndex) return null
        val rawIp = raw.substring(0, idx)
        val rawPort = raw.substring(idx + 1)
        val port = rawPort.toIntOrNull(16) ?: return null
        val ip = if (isIpv6) decodeIpv6(rawIp) else decodeIpv4(rawIp)
        return ip to port
    }

    private fun decodeIpv4(hex: String): String {
        val bytes = hex.chunked(2).map { it.toInt(16).toByte() }.reversed().toByteArray()
        return InetAddress.getByAddress(bytes).hostAddress
    }

    private fun decodeIpv6(hex: String): String {
        val transformed = hex.chunked(8)
            .flatMap { chunk -> chunk.chunked(2).reversed() }
            .map { it.toInt(16).toByte() }
            .toByteArray()
        return InetAddress.getByAddress(transformed).hostAddress
    }

    private fun isUnspecifiedIp(ip: String): Boolean {
        return ip == "0.0.0.0" || ip == "::" || ip == "0:0:0:0:0:0:0:0"
    }

    private suspend fun requestRemoteVerdicts(ips: List<String>): List<Verdict> {
        if (ips.isEmpty()) return emptyList()

        val payload = JSONObject()
            .put("ips", JSONArray(ips))
            .toString()

        val request = Request.Builder()
            .url("${MainActivity.SERVER_BASE_URL}/analysis/ips")
            .post(payload.toRequestBody("application/json; charset=utf-8".toMediaType()))
            .build()

        return runCatching {
            HTTP_CLIENT.newCall(request).execute().use { response ->
                val body = response.body?.string().orEmpty()
                if (!response.isSuccessful) {
                    Log.w(TAG, "IP analysis request failed ${response.code}: $body")
                    return emptyList()
                }
                parseApiResponse(body)
            }
        }.getOrElse { error ->
            Log.w(TAG, "IP analysis request crashed: ${error.message}")
            emptyList()
        }
    }

    private fun parseApiResponse(responseBody: String): List<Verdict> {
        val responseJSON = JSONObject(responseBody)
        val candidates = responseJSON.optJSONArray("results") ?: return emptyList()

        val verdicts = mutableListOf<Verdict>()
        for (i in 0 until candidates.length()) {
            val item = candidates.optJSONObject(i) ?: continue
            val ip = item.optString("ip").trim()
            if (ip.isBlank()) continue
            val malicious = item.optBoolean("malicious", false)
            val degree = item.optString("degree", "none")

            verdicts += Verdict(
                ip = ip,
                malicious = malicious,
                degree = degree,
            )
        }

        return verdicts
    }

    private suspend fun resolvePackagesByUid(uid: Int): List<String> {
        val output = adbManager.runCommand("pm list packages --uid $uid")
        return output.lineSequence()
            .map { it.trim() }
            .filter { it.startsWith("package:") }
            .map { it.removePrefix("package:").trim() }
            .filter { it.isNotBlank() }
            .distinct()
            .toList()
    }

    private fun loadVerdictCache(): JSONObject {
        val raw = prefs.getString(PREF_VERDICT_CACHE, null).orEmpty()
        if (raw.isBlank()) return JSONObject()
        return runCatching { JSONObject(raw) }.getOrElse {
            Log.w(TAG, "Cache decode failed, resetting: ${it.message}")
            JSONObject()
        }
    }

    private fun saveVerdictCache(cache: JSONObject) {
        prefs.edit().putString(PREF_VERDICT_CACHE, cache.toString()).apply()
    }

    private fun pruneCache(cache: JSONObject, now: Long) {
        val toRemove = mutableListOf<String>()
        val keys = cache.keys()
        while (keys.hasNext()) {
            val ip = keys.next()
            val entry = cache.optJSONObject(ip)
            val updatedAt = entry?.optLong("updatedAt", 0L) ?: 0L
            if ((now - updatedAt) > VERDICT_TTL_MS) {
                toRemove += ip
            }
        }
        for (ip in toRemove) {
            cache.remove(ip)
        }
    }
}