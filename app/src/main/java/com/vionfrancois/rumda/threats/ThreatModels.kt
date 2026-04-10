package com.vionfrancois.rumda.threats

enum class ThreatKind {
    APK,
    IP
}

enum class ThreatStatus {
    ACTIVE,
    MITIGATED,
    IGNORED,
}

enum class ThreatSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
}

data class ThreatRecord(
    val id: Long,
    val fingerprint: String,
    val kind: ThreatKind,
    val title: String,
    val summary: String,
    val severity: ThreatSeverity,
    val status: ThreatStatus,
    val sourceCollector: String,
    val detectedAtEpochMs: Long,
    val resolvedAtEpochMs: Long?,
    val attributes: Map<String, String>,
)
