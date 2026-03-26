package com.vionfrancois.rumda.collectors

abstract class EventCollector : Collector {
    abstract suspend fun collectEvents(): String //TODO : Change type ?
    abstract suspend fun sendForAnalysis(events: String): String // TODO : Change type ?
    abstract suspend fun handleResult(result: String) // TODO : Change type ?

    override suspend fun run(){
        val events = collectEvents()
        val result = sendForAnalysis(events)
        handleResult(result)
    }
}