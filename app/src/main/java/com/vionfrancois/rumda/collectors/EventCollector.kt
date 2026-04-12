package com.vionfrancois.rumda.collectors

import com.vionfrancois.rumda.threats.ThreatRecord

abstract class EventCollector : Collector {
    abstract suspend fun collectEvents(): String //TODO : Change type ?
    abstract suspend fun sendForAnalysis(events: String): String // TODO : Change type ?
    abstract suspend fun buildThreats(result: String): List<ThreatRecord>
    abstract suspend fun handleThreats(threats: List<ThreatRecord>)

    override suspend fun run(){
        val events = collectEvents()
        val result = sendForAnalysis(events)
        val threats = buildThreats(result)
        handleThreats(threats)
    }
}