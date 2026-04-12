package com.vionfrancois.rumda.collectors

import com.vionfrancois.rumda.collectors.APKCollector.PackageEntry
import com.vionfrancois.rumda.threats.ThreatRecord

abstract class StateCollector : Collector {
    abstract fun fetchLastState(): Pair<List<PackageEntry>, Boolean>
    abstract suspend fun collectState(): List<PackageEntry>
    abstract suspend fun pushDiffToRemote(
        oldState: List<PackageEntry>,
        newState: MutableList<PackageEntry>
    ): Pair<List<ThreatRecord>, MutableList<PackageEntry>>
    abstract suspend fun handleVerdict(response: List<ThreatRecord>)
    abstract fun saveState(state: List<PackageEntry>)

    override suspend fun run() {
        val (lastState, isComplete) = fetchLastState()
        var state  = collectState()

        if (lastState != state || !isComplete) {
            val (threats, state) = pushDiffToRemote(lastState, state.toMutableList())
            handleVerdict(threats)
            saveState(state)
        }
    }
}
