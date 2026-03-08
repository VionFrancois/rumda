package com.vionfrancois.rumda.collectors

interface Collector {
    suspend fun collect(): String
    fun pushToRemote(content: String) // TODO: Change String to valid type
}
