package com.vionfrancois.rumda.collectors

import com.vionfrancois.rumda.collectors.APKCollector.PackageEntry

abstract class StateCollector : Collector {
    abstract fun fetchLastState(): List<PackageEntry>
    abstract suspend fun collectState(): List<PackageEntry>
    abstract suspend fun pushDiffToRemote(
        oldState: List<PackageEntry>,
        newState: MutableList<PackageEntry>
    ): MutableList<String>
    abstract suspend fun handleVerdict(response: MutableList<String>)
    abstract fun saveState(state: List<PackageEntry>)

    override suspend fun run() {
        val lastState = fetchLastState()
        val state = collectState().toMutableList()

        if (lastState != state) {
            val verdict = pushDiffToRemote(lastState, state)
            handleVerdict(verdict)
            saveState(state)
        }
    }
}
