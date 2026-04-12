package com.vionfrancois.rumda.threats

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import org.json.JSONObject

class ThreatStoring(context: Context) : AutoCloseable {

    companion object {
        private const val DB_NAME = "threat_store.db"
        private const val DB_VERSION = 2

        private const val TABLE_THREATS = "threats"
        private const val TABLE_META = "threat_meta"

        private const val COL_ID = "id"
        private const val COL_FINGERPRINT = "fingerprint"
        private const val COL_KIND = "kind"
        private const val COL_TITLE = "title"
        private const val COL_SUMMARY = "summary"
        private const val COL_SEVERITY = "severity"
        private const val COL_STATUS = "status"
        private const val COL_SOURCE_COLLECTOR = "source_collector"
        private const val COL_DETECTED_AT = "detected_at_epoch_ms"
        private const val COL_RESOLVED_AT = "resolved_at_epoch_ms"
        private const val COL_ATTRIBUTES_JSON = "attributes_json"

        private const val STATUS_ACTIVE = "ACTIVE"
        private const val META_NEXT_THREAT_ID = "next_threat_id"
    }

    private val dbHelper = ThreatDbHelper(context.applicationContext)

    @Synchronized
    override fun close() {
        dbHelper.close()
    }

    @Synchronized
    fun getActiveThreats(): List<ThreatRecord> {
        val db = dbHelper.readableDatabase
        db.query(
            TABLE_THREATS,
            null,
            "$COL_STATUS = ?",
            arrayOf(STATUS_ACTIVE),
            null,
            null,
            "$COL_DETECTED_AT DESC",
        ).use { cursor ->
            return buildThreatList(cursor)
        }
    }

    @Synchronized
    fun getThreatHistory(): List<ThreatRecord> {
        val db = dbHelper.readableDatabase
        db.query(
            TABLE_THREATS,
            null,
            "$COL_STATUS != ?",
            arrayOf(STATUS_ACTIVE),
            null,
            null,
            "COALESCE($COL_RESOLVED_AT, $COL_DETECTED_AT) DESC",
        ).use { cursor ->
            return buildThreatList(cursor)
        }
    }

    @Synchronized
    fun addActiveThreats(candidates: List<ThreatRecord>): Int {
        if (candidates.isEmpty()) return 0

        val db = dbHelper.writableDatabase
        var inserted = 0

        db.beginTransaction()
        try {
            for (candidate in candidates) {
                val rowId = db.insertWithOnConflict(
                    TABLE_THREATS,
                    null,
                    toContentValues(candidate),
                    SQLiteDatabase.CONFLICT_IGNORE,
                )
                if (rowId != -1L) inserted++
            }

            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }

        return inserted
    }

    @Synchronized
    fun resolveThreat(threatId: Long, newStatus: ThreatStatus): ThreatRecord? {
        if (newStatus == ThreatStatus.ACTIVE) return null

        val db = dbHelper.writableDatabase
        db.beginTransaction()
        try {
            val existing = getActiveThreatById(db, threatId) ?: return null
            val resolved = existing.copy(
                status = newStatus,
                resolvedAtEpochMs = System.currentTimeMillis(),
            )

            val values = ContentValues().apply {
                put(COL_STATUS, resolved.status.name)
                put(COL_RESOLVED_AT, resolved.resolvedAtEpochMs)
            }
            db.update(
                TABLE_THREATS,
                values,
                "$COL_ID = ?",
                arrayOf(threatId.toString()),
            )

            db.setTransactionSuccessful()
            return resolved
        } finally {
            db.endTransaction()
        }
    }

    @Synchronized
    fun nextThreatId(): Long {
        val db = dbHelper.writableDatabase
        db.beginTransaction()
        try {
            val current = getMetaLong(db, META_NEXT_THREAT_ID, 1L)
            val next = current + 1L
            setMetaLong(db, META_NEXT_THREAT_ID, next)
            db.setTransactionSuccessful()
            return current
        } finally {
            db.endTransaction()
        }
    }

    fun buildThreat(
        kind: ThreatKind,
        title: String,
        summary: String,
        severity: ThreatSeverity,
        sourceCollector: String,
        attributes: Map<String, String>,
    ): ThreatRecord {
        val now = System.currentTimeMillis()
        val fingerprint = buildFingerprint(kind, sourceCollector, attributes)

        return ThreatRecord(
            id = nextThreatId(),
            fingerprint = fingerprint,
            kind = kind,
            title = title,
            summary = summary,
            severity = severity,
            status = ThreatStatus.ACTIVE,
            sourceCollector = sourceCollector,
            detectedAtEpochMs = now,
            resolvedAtEpochMs = null,
            attributes = attributes,
        )
    }

    private fun buildFingerprint(
        kind: ThreatKind,
        sourceCollector: String,
        attributes: Map<String, String>,
    ): String {
        val canonicalAttributes = attributes.toSortedMap()
            .entries
            .joinToString("|") { "${it.key}=${it.value}" }

        return listOf(kind.name, sourceCollector, canonicalAttributes)
            .joinToString("#")
    }

    private fun buildThreatList(cursor: Cursor): List<ThreatRecord> {
        val threats = mutableListOf<ThreatRecord>()
        while (cursor.moveToNext()) {
            val threat = cursorToThreat(cursor) ?: continue
            threats.add(threat)
        }
        return threats
    }

    private fun getActiveThreatById(db: SQLiteDatabase, threatId: Long): ThreatRecord? {
        db.query(
            TABLE_THREATS,
            null,
            "$COL_ID = ? AND $COL_STATUS = ?",
            arrayOf(threatId.toString(), STATUS_ACTIVE),
            null,
            null,
            null,
            "1",
        ).use { cursor ->
            if (!cursor.moveToFirst()) return null
            return cursorToThreat(cursor)
        }
    }

    private fun toContentValues(record: ThreatRecord): ContentValues {
        return ContentValues().apply {
            put(COL_ID, record.id)
            put(COL_FINGERPRINT, record.fingerprint)
            put(COL_KIND, record.kind.name)
            put(COL_TITLE, record.title)
            put(COL_SUMMARY, record.summary)
            put(COL_SEVERITY, record.severity.name)
            put(COL_STATUS, record.status.name)
            put(COL_SOURCE_COLLECTOR, record.sourceCollector)
            put(COL_DETECTED_AT, record.detectedAtEpochMs)
            if (record.resolvedAtEpochMs == null) {
                putNull(COL_RESOLVED_AT)
            } else {
                put(COL_RESOLVED_AT, record.resolvedAtEpochMs)
            }
            put(COL_ATTRIBUTES_JSON, mapToAttributesJson(record.attributes))
        }
    }

    private fun cursorToThreat(cursor: Cursor): ThreatRecord? {
        val rawKind = cursor.getString(cursor.getColumnIndexOrThrow(COL_KIND))
        val kind = runCatching { ThreatKind.valueOf(rawKind) }.getOrNull() ?: return null
        val severity = runCatching {
            ThreatSeverity.valueOf(cursor.getString(cursor.getColumnIndexOrThrow(COL_SEVERITY)))
        }.getOrDefault(ThreatSeverity.MEDIUM)
        val status = runCatching {
            ThreatStatus.valueOf(cursor.getString(cursor.getColumnIndexOrThrow(COL_STATUS)))
        }.getOrDefault(ThreatStatus.ACTIVE)

        val resolvedIndex = cursor.getColumnIndexOrThrow(COL_RESOLVED_AT)
        val resolvedAt = if (cursor.isNull(resolvedIndex)) null else cursor.getLong(resolvedIndex)

        return ThreatRecord(
            id = cursor.getLong(cursor.getColumnIndexOrThrow(COL_ID)),
            fingerprint = cursor.getString(cursor.getColumnIndexOrThrow(COL_FINGERPRINT)),
            kind = kind,
            title = cursor.getString(cursor.getColumnIndexOrThrow(COL_TITLE)),
            summary = cursor.getString(cursor.getColumnIndexOrThrow(COL_SUMMARY)),
            severity = severity,
            status = status,
            sourceCollector = cursor.getString(cursor.getColumnIndexOrThrow(COL_SOURCE_COLLECTOR)),
            detectedAtEpochMs = cursor.getLong(cursor.getColumnIndexOrThrow(COL_DETECTED_AT)),
            resolvedAtEpochMs = resolvedAt,
            attributes = attributesJsonToMap(
                cursor.getString(cursor.getColumnIndexOrThrow(COL_ATTRIBUTES_JSON)),
            ),
        )
    }

    private fun mapToAttributesJson(attributes: Map<String, String>): String {
        val json = JSONObject()
        for ((key, value) in attributes) {
            json.put(key, value)
        }
        return json.toString()
    }

    private fun attributesJsonToMap(raw: String?): Map<String, String> {
        if (raw.isNullOrBlank()) return emptyMap()
        val json = runCatching { JSONObject(raw) }.getOrNull() ?: return emptyMap()
        val attributes = mutableMapOf<String, String>()
        val keys = json.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            attributes[key] = json.optString(key)
        }
        return attributes
    }

    private fun getMetaLong(db: SQLiteDatabase, key: String, defaultValue: Long): Long {
        db.query(
            TABLE_META,
            arrayOf("meta_value"),
            "meta_key = ?",
            arrayOf(key),
            null,
            null,
            null,
            "1",
        ).use { cursor ->
            if (!cursor.moveToFirst()) return defaultValue
            return cursor.getLong(0)
        }
    }

    private fun setMetaLong(db: SQLiteDatabase, key: String, value: Long) {
        val values = ContentValues().apply {
            put("meta_key", key)
            put("meta_value", value)
        }

        db.insertWithOnConflict(
            TABLE_META,
            null,
            values,
            SQLiteDatabase.CONFLICT_REPLACE,
        )
    }

    private class ThreatDbHelper(context: Context) : SQLiteOpenHelper(context, DB_NAME, null, DB_VERSION) {

        override fun onCreate(db: SQLiteDatabase) {
            createV2Schema(db)
        }

        override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            if (oldVersion < 2) {
                migrateV1ToV2(db)
            }
        }

        private fun createV2Schema(db: SQLiteDatabase) {
            db.execSQL(
                """
                CREATE TABLE IF NOT EXISTS $TABLE_THREATS (
                    $COL_ID INTEGER PRIMARY KEY,
                    $COL_FINGERPRINT TEXT NOT NULL,
                    $COL_KIND TEXT NOT NULL,
                    $COL_TITLE TEXT NOT NULL,
                    $COL_SUMMARY TEXT NOT NULL,
                    $COL_SEVERITY TEXT NOT NULL,
                    $COL_STATUS TEXT NOT NULL,
                    $COL_SOURCE_COLLECTOR TEXT NOT NULL,
                    $COL_DETECTED_AT INTEGER NOT NULL,
                    $COL_RESOLVED_AT INTEGER,
                    $COL_ATTRIBUTES_JSON TEXT NOT NULL
                )
                """.trimIndent(),
            )
            db.execSQL(
                """
                CREATE TABLE IF NOT EXISTS $TABLE_META (
                    meta_key TEXT PRIMARY KEY,
                    meta_value INTEGER NOT NULL
                )
                """.trimIndent(),
            )

            db.execSQL(
                "INSERT OR IGNORE INTO $TABLE_META(meta_key, meta_value) VALUES('$META_NEXT_THREAT_ID', 1)",
            )
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_threats_status ON $TABLE_THREATS($COL_STATUS)")
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_threats_detected ON $TABLE_THREATS($COL_DETECTED_AT DESC)")
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_threats_resolved ON $TABLE_THREATS($COL_RESOLVED_AT DESC)")
            db.execSQL(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_threats_active_fingerprint ON $TABLE_THREATS($COL_FINGERPRINT) WHERE $COL_STATUS = '$STATUS_ACTIVE'",
            )
        }

        private fun migrateV1ToV2(db: SQLiteDatabase) {
            createV2Schema(db)

            if (tableExists(db, "active_threats")) {
                db.execSQL(
                    """
                    INSERT OR REPLACE INTO $TABLE_THREATS (
                        $COL_ID,
                        $COL_FINGERPRINT,
                        $COL_KIND,
                        $COL_TITLE,
                        $COL_SUMMARY,
                        $COL_SEVERITY,
                        $COL_STATUS,
                        $COL_SOURCE_COLLECTOR,
                        $COL_DETECTED_AT,
                        $COL_RESOLVED_AT,
                        $COL_ATTRIBUTES_JSON
                    )
                    SELECT
                        $COL_ID,
                        $COL_FINGERPRINT,
                        $COL_KIND,
                        $COL_TITLE,
                        $COL_SUMMARY,
                        $COL_SEVERITY,
                        $COL_STATUS,
                        $COL_SOURCE_COLLECTOR,
                        $COL_DETECTED_AT,
                        $COL_RESOLVED_AT,
                        $COL_ATTRIBUTES_JSON
                    FROM active_threats
                    """.trimIndent(),
                )
            }

            if (tableExists(db, "threat_history")) {
                db.execSQL(
                    """
                    INSERT OR REPLACE INTO $TABLE_THREATS (
                        $COL_ID,
                        $COL_FINGERPRINT,
                        $COL_KIND,
                        $COL_TITLE,
                        $COL_SUMMARY,
                        $COL_SEVERITY,
                        $COL_STATUS,
                        $COL_SOURCE_COLLECTOR,
                        $COL_DETECTED_AT,
                        $COL_RESOLVED_AT,
                        $COL_ATTRIBUTES_JSON
                    )
                    SELECT
                        $COL_ID,
                        $COL_FINGERPRINT,
                        $COL_KIND,
                        $COL_TITLE,
                        $COL_SUMMARY,
                        $COL_SEVERITY,
                        $COL_STATUS,
                        $COL_SOURCE_COLLECTOR,
                        $COL_DETECTED_AT,
                        $COL_RESOLVED_AT,
                        $COL_ATTRIBUTES_JSON
                    FROM threat_history
                    """.trimIndent(),
                )
            }

            val maxThreatId = db.rawQuery("SELECT COALESCE(MAX($COL_ID), 0) FROM $TABLE_THREATS", null).use { cursor ->
                if (cursor.moveToFirst()) cursor.getLong(0) else 0L
            }
            val currentMetaNextId = db.rawQuery(
                "SELECT COALESCE(meta_value, 1) FROM $TABLE_META WHERE meta_key = ? LIMIT 1",
                arrayOf(META_NEXT_THREAT_ID),
            ).use { cursor ->
                if (cursor.moveToFirst()) cursor.getLong(0) else 1L
            }
            val migratedNextId = maxOf(currentMetaNextId, maxThreatId + 1L)

            db.execSQL(
                "INSERT OR REPLACE INTO $TABLE_META(meta_key, meta_value) VALUES(?, ?)",
                arrayOf(META_NEXT_THREAT_ID, migratedNextId),
            )

            if (tableExists(db, "active_threats")) {
                db.execSQL("DROP TABLE IF EXISTS active_threats")
            }
            if (tableExists(db, "threat_history")) {
                db.execSQL("DROP TABLE IF EXISTS threat_history")
            }
        }

        private fun tableExists(db: SQLiteDatabase, tableName: String): Boolean {
            db.rawQuery(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1",
                arrayOf(tableName),
            ).use { cursor ->
                return cursor.moveToFirst()
            }
        }
    }
}
