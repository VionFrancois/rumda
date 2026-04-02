package com.vionfrancois.rumda.collectors

import com.vionfrancois.rumda.collectors.APKCollector.PackageEntry

abstract class StateCollector : Collector {
    abstract fun fetchLastState(): Pair<List<PackageEntry>, Boolean>
    abstract suspend fun collectState(): List<PackageEntry>
    abstract suspend fun pushDiffToRemote(
        oldState: List<PackageEntry>,
        newState: MutableList<PackageEntry>
    ): Pair<MutableList<String>, MutableList<PackageEntry>>
    abstract suspend fun handleVerdict(response: MutableList<String>)
    abstract fun saveState(state: List<PackageEntry>)

    override suspend fun run() {
        val (lastState, isComplete) = fetchLastState()
        var state  = collectState()

        if (lastState != state || !isComplete) {
            val (verdict, state) = pushDiffToRemote(lastState, state.toMutableList())
            handleVerdict(verdict)
            saveState(state)
        }
    }
}
