package com.vionfrancois.rumda.collectors

import android.util.Log
import com.vionfrancois.rumda.cadb.AdbManager

class APKCollector(
    private val adbManager: AdbManager
) : StateCollector {

    private companion object {
        const val TAG = "APKCollector"
    }

    override suspend fun collect(): String {
        val output = adbManager.runCommand("pm list packages -f")
        Log.d(TAG, output)
        return output
    }


    override fun saveState() {
        TODO("Not yet implemented")
    }

    override fun fetchLastState() {
        TODO("Not yet implemented")
    }


    override fun pushToRemote(content: String) {
        TODO("Not yet implemented")
    }


}
