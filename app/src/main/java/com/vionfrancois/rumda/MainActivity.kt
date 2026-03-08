package com.vionfrancois.rumda

import android.Manifest
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.vionfrancois.rumda.cadb.AdbCommandService
import com.vionfrancois.rumda.cadb.AdbManager
import com.vionfrancois.rumda.collectors.APKCollector
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {
    private lateinit var adbManager: AdbManager
    private lateinit var introText: TextView
    private lateinit var statusText: TextView
    private lateinit var outputText: TextView

    private val notificationsPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        updateIntro()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        adbManager = AdbManager(applicationContext)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
        }

        introText = TextView(this).apply {
            text = getString(R.string.adb_flow_hint)
            setPadding(0, 0, 0, 20)
            textSize = 16f
        }

        statusText = TextView(this).apply {
            text = getString(R.string.adb_state_template, "Initial")
            textSize = 18f
            setPadding(0, 0, 0, 24)
        }

        val notificationsButton = Button(this).apply {
            text = getString(R.string.adb_btn_notifications)
            setOnClickListener {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    notificationsPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                }
            }
            isEnabled = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        }

        val wirelessSettingsButton = Button(this).apply {
            text = getString(R.string.adb_btn_wireless_settings)
            setOnClickListener {
                val intent = Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS).apply {
                    putExtra(":settings:fragment_args_key", "toggle_adb_wireless")
                }
                startActivity(intent)
            }
        }

        val pairButton = Button(this).apply {
            text = getString(R.string.adb_btn_pair)
            setOnClickListener { adbManager.startAdbPairingService() }
        }
        val connectButton = Button(this).apply {
            text = getString(R.string.adb_btn_connect)
            setOnClickListener { adbManager.autoConnect() }
        }
        val commandButton = Button(this).apply {
            text = getString(R.string.adb_btn_run_date)
            setOnClickListener {
                lifecycleScope.launch {
                    outputText.text = adbManager.runCommand("date")
                }
            }
        }
        val collectApkButton = Button(this).apply {
            text = getString(R.string.adb_btn_collect_apk)
            setOnClickListener {
                lifecycleScope.launch {
                    val collector = APKCollector(adbManager)
                    outputText.text = collector.collect()
                }
            }
        }
        val startLoopButton = Button(this).apply {
            text = getString(R.string.adb_btn_start_loop)
            setOnClickListener {
                val intent = AdbCommandService.startLoopIntent(
                    context = this@MainActivity,
                    command = "date",
                    intervalMs = 10_000L
                )
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    startForegroundService(intent)
                } else {
                    startService(intent)
                }
            }
        }
        val stopLoopButton = Button(this).apply {
            text = getString(R.string.adb_btn_stop_loop)
            setOnClickListener {
                startService(AdbCommandService.stopLoopIntent(this@MainActivity))
            }
        }

        outputText = TextView(this).apply {
            text = getString(R.string.adb_output_placeholder)
            setPadding(0, 24, 0, 0)
            textSize = 16f
        }

        val scroll = ScrollView(this).apply {
            addView(outputText, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        }

        root.addView(introText, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        root.addView(statusText, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        root.addView(notificationsButton, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        root.addView(wirelessSettingsButton, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        root.addView(pairButton, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        root.addView(connectButton, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        root.addView(commandButton, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        root.addView(collectApkButton, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        root.addView(startLoopButton, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        root.addView(stopLoopButton, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        root.addView(scroll, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        setContentView(root)
        updateIntro()

        lifecycleScope.launch {
            repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                launch {
                    adbManager.adbState.collect {
                        statusText.text = getString(R.string.adb_state_template, it.name)
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        adbManager.cleanup()
        super.onDestroy()
    }

    override fun onResume() {
        super.onResume()
        updateIntro()
    }

    override fun onPause() {
        super.onPause()
    }

    private fun updateIntro() {
        val notificationsReady = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
        introText.text = if (notificationsReady) {
            getString(R.string.adb_flow_hint)
        } else {
            getString(R.string.adb_flow_need_notifications)
        }
    }
}
