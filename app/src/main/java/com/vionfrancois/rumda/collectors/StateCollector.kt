package com.vionfrancois.rumda.collectors

interface StateCollector : Collector {
    fun saveState()
    fun fetchLastState(): String?
    fun pushDiffToRemote(diff: String){ // TODO: Change String to valid type
        pushToRemote(diff)
    }
}
