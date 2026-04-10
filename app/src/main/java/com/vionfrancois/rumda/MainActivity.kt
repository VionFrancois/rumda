package com.vionfrancois.rumda

import android.Manifest
import android.app.ActivityOptions
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.GestureDetector
import android.provider.Settings
import android.view.MotionEvent
import android.widget.Button
import android.widget.CheckBox
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.vionfrancois.rumda.cadb.AdbCommandService
import com.vionfrancois.rumda.cadb.AdbManager
import com.vionfrancois.rumda.cadb.AdbState
import com.google.android.material.bottomnavigation.BottomNavigationView
import kotlinx.coroutines.launch
import kotlin.math.abs

class MainActivity : AppCompatActivity() {
    companion object {
        const val SERVER_BASE_URL = "http://10.0.2.2:8000"
        private const val PREFS_NAME = "rumda_prefs"
        private const val PREF_ONBOARDING_COMPLETED = "onboarding_completed"
        private const val PREF_MONITORING_CATEGORIES = "monitoring_categories"
        private const val WIRELESS_DEBUGGING_KEY = "adb_wifi_enabled"
        private const val CATEGORY_APKS = "APKS"
        private const val CATEGORY_IPS = "IPS"
        private const val CATEGORY_SERVICES = "SERVICES"
        private const val SWIPE_DISTANCE_THRESHOLD_PX = 120
        private const val SWIPE_VELOCITY_THRESHOLD = 200
    }

    private lateinit var prefs: SharedPreferences
    private lateinit var adbManager: AdbManager
    private lateinit var checklistBodyText: TextView
    private lateinit var primaryActionButton: Button
    private lateinit var statusTitleText: TextView
    private lateinit var statusBodyText: TextView
    private lateinit var apkCheckBox: CheckBox
    private lateinit var ipsCheckBox: CheckBox
    private lateinit var servicesCheckBox: CheckBox
    private lateinit var bottomNavigationView: BottomNavigationView
    private lateinit var swipeGestureDetector: GestureDetector
    private var wirelessDebuggingDialogVisible = false
    private var notificationsDialogVisible = false
    private var backgroundLoopStarted = false
    private var tabSwitchInProgress = false

    private val notificationsPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        refreshUi(triggerAutoActions = true)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportActionBar?.hide()
        prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)

        if (!prefs.getBoolean(PREF_ONBOARDING_COMPLETED, false)) {
            startActivity(Intent(this, OnboardingActivity::class.java))
            finish()
            return
        }

        adbManager = AdbManager(applicationContext)
        setContentView(R.layout.activity_main)
        setupSwipeNavigation()
        bindViews()
        refreshUi(triggerAutoActions = false)

        lifecycleScope.launch {
            repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                adbManager.adbState.collect {
                    handleBackgroundServiceState()
                    refreshUi(triggerAutoActions = false)
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        tabSwitchInProgress = false
        if (!prefs.getBoolean(PREF_ONBOARDING_COMPLETED, false)) {
            startActivity(Intent(this, OnboardingActivity::class.java))
            finish()
            return
        }
        if (!::adbManager.isInitialized) return
        bottomNavigationView.selectedItemId = R.id.navigation_configuration
        refreshUi(triggerAutoActions = true)
    }

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        if (::swipeGestureDetector.isInitialized) {
            swipeGestureDetector.onTouchEvent(ev)
        }
        return super.dispatchTouchEvent(ev)
    }

    override fun onDestroy() {
        if (::adbManager.isInitialized) {
            adbManager.cleanup()
        }
        super.onDestroy()
    }

    private fun bindViews() {
        statusTitleText = findViewById(R.id.statusTitleText)
        statusBodyText = findViewById(R.id.statusBodyText)
        primaryActionButton = findViewById(R.id.primaryActionButton)
        checklistBodyText = findViewById(R.id.checklistBodyText)
        apkCheckBox = findViewById(R.id.apkCheckBox)
        ipsCheckBox = findViewById(R.id.ipsCheckBox)
        servicesCheckBox = findViewById(R.id.servicesCheckBox)
        bottomNavigationView = findViewById(R.id.bottomNavigationView)
        setupBottomNavigation()
        restoreMonitoringSelections()
        bindMonitoringPreferenceListeners()
    }

    private fun setupBottomNavigation() {
        bottomNavigationView.selectedItemId = R.id.navigation_configuration
        bottomNavigationView.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.navigation_configuration -> true
                R.id.navigation_threats -> {
                    openThreatsTab()
                    true
                }
                else -> false
            }
        }
    }

    private fun setupSwipeNavigation() {
        swipeGestureDetector = GestureDetector(
            this,
            object : GestureDetector.SimpleOnGestureListener() {
                override fun onFling(
                    e1: MotionEvent?,
                    e2: MotionEvent,
                    velocityX: Float,
                    velocityY: Float,
                ): Boolean {
                    if (e1 == null) return false
                    val deltaX = e2.x - e1.x
                    val deltaY = e2.y - e1.y
                    if (abs(deltaX) < SWIPE_DISTANCE_THRESHOLD_PX) return false
                    if (abs(deltaX) < abs(deltaY)) return false
                    if (abs(velocityX) < SWIPE_VELOCITY_THRESHOLD) return false

                    if (deltaX < 0) {
                        openThreatsTab()
                        return true
                    }
                    return false
                }
            },
        )
    }

    private fun openThreatsTab() {
        if (tabSwitchInProgress) return
        tabSwitchInProgress = true

        val intent = Intent(this, ThreatsActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        val options = ActivityOptions.makeCustomAnimation(
            this,
            R.anim.slide_in_right,
            R.anim.slide_out_left,
        )
        startActivity(intent, options.toBundle())
    }

    private fun refreshUi(triggerAutoActions: Boolean) {
        val notificationsReady = notificationsPermissionGranted()
        val wirelessDebuggingReady = isWirelessDebuggingEnabled()
        if (notificationsReady) notificationsDialogVisible = false
        if (wirelessDebuggingReady) wirelessDebuggingDialogVisible = false
        if (!wirelessDebuggingReady) {
            adbManager.handleWirelessDebuggingDisabled()
        }
        val adbState = adbManager.adbState.value
        val connected = wirelessDebuggingReady && adbState in AdbState.successStates()

        statusTitleText.text = dashboardStatusTitle(notificationsReady, wirelessDebuggingReady, adbState)
        statusBodyText.text = dashboardStatusBody(notificationsReady, wirelessDebuggingReady, adbState)
        primaryActionButton.text = primaryActionText(notificationsReady, wirelessDebuggingReady, adbState)
        primaryActionButton.setOnClickListener { handlePrimaryAction() }
        primaryActionButton.isEnabled = adbState != AdbState.Connecting

        checklistBodyText.text = if (connected) {
            getString(R.string.main_checklist_body)
        } else {
            getString(R.string.main_checklist_body_locked)
        }
        setCollectionControlsEnabled(connected)

        if (triggerAutoActions) {
            runLaunchAutomation(notificationsReady, wirelessDebuggingReady, connected)
        }
    }

    private fun setCollectionControlsEnabled(enabled: Boolean) {
        checklistBodyText.alpha = if (enabled) 1f else 0.7f
        apkCheckBox.isEnabled = enabled
        ipsCheckBox.isEnabled = enabled
        servicesCheckBox.isEnabled = enabled
        apkCheckBox.alpha = if (enabled) 1f else 0.5f
        ipsCheckBox.alpha = if (enabled) 1f else 0.5f
        servicesCheckBox.alpha = if (enabled) 1f else 0.5f
    }

    private fun handlePrimaryAction() {
        when {
            !notificationsPermissionGranted() -> showNotificationsDialog()
            !isWirelessDebuggingEnabled() -> showWirelessDebuggingDialog()
            adbManager.adbState.value == AdbState.RequisitesMissing -> adbManager.startAdbPairingService()
            else -> adbManager.autoConnect()
        }
    }

    private fun runLaunchAutomation(
        notificationsReady: Boolean,
        wirelessDebuggingReady: Boolean,
        connected: Boolean,
    ) {
        if (!notificationsReady) {
            showNotificationsDialog()
            return
        }
        if (!wirelessDebuggingReady) {
            showWirelessDebuggingDialog()
            return
        }
        if (!connected) {
            adbManager.autoConnect()
        }
    }

    private fun primaryActionText(
        notificationsReady: Boolean,
        wirelessDebuggingReady: Boolean,
        adbState: AdbState,
    ): String {
        return when {
            !notificationsReady -> getString(R.string.onboarding_action_enable_notifications)
            !wirelessDebuggingReady -> getString(R.string.onboarding_action_open_settings)
            adbState == AdbState.RequisitesMissing -> getString(R.string.onboarding_action_start_pairing)
            adbState == AdbState.Connecting -> getString(R.string.launch_btn_connecting)
            else -> getString(R.string.launch_btn_reconnect_adb)
        }
    }

    private fun dashboardStatusTitle(
        notificationsReady: Boolean,
        wirelessDebuggingReady: Boolean,
        adbState: AdbState,
    ): String {
        return when {
            !notificationsReady -> getString(R.string.dashboard_status_attention)
            !wirelessDebuggingReady -> getString(R.string.dashboard_status_attention)
            adbState == AdbState.Connecting -> getString(R.string.dashboard_status_connecting)
            adbState in AdbState.successStates() -> getString(R.string.dashboard_status_connected)
            adbState == AdbState.RequisitesMissing -> getString(R.string.dashboard_status_pairing)
            adbState == AdbState.ErrorConnect -> getString(R.string.dashboard_status_attention)
            else -> getString(R.string.dashboard_status_idle)
        }
    }

    private fun dashboardStatusBody(
        notificationsReady: Boolean,
        wirelessDebuggingReady: Boolean,
        adbState: AdbState,
    ): String {
        return when {
            !notificationsReady -> getString(R.string.dashboard_body_notifications)
            !wirelessDebuggingReady -> getString(R.string.dashboard_body_wireless)
            adbState == AdbState.RequisitesMissing -> getString(R.string.dashboard_body_pairing)
            adbState == AdbState.Connecting -> getString(R.string.dashboard_body_connecting)
            adbState in AdbState.successStates() -> getString(R.string.dashboard_body_connected)
            else -> getString(R.string.dashboard_body_idle)
        }
    }

    private fun notificationsPermissionGranted(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
    }

    private fun requestNotificationsPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notificationsPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            openNotificationSettings()
        }
    }

    private fun showNotificationsDialog() {
        if (notificationsDialogVisible) return
        notificationsDialogVisible = true

        AlertDialog.Builder(this)
            .setTitle(R.string.notifications_dialog_title)
            .setMessage(R.string.notifications_dialog_message)
            .setNegativeButton(R.string.notifications_dialog_cancel, null)
            .setPositiveButton(R.string.notifications_dialog_open_settings) { _, _ ->
                requestNotificationsPermission()
            }
            .setOnDismissListener { notificationsDialogVisible = false }
            .show()
    }

    private fun openNotificationSettings() {
        val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
            putExtra(Settings.EXTRA_APP_PACKAGE, packageName)
            putExtra("app_package", packageName)
            putExtra("app_uid", applicationInfo.uid)
        }
        startActivity(intent)
    }

    private fun isWirelessDebuggingEnabled(): Boolean {
        return runCatching {
            Settings.Global.getInt(contentResolver, WIRELESS_DEBUGGING_KEY, 0) == 1
        }.getOrDefault(false)
    }

    private fun showWirelessDebuggingDialog() {
        if (wirelessDebuggingDialogVisible) return
        wirelessDebuggingDialogVisible = true

        AlertDialog.Builder(this)
            .setTitle(R.string.wireless_debugging_dialog_title)
            .setMessage(R.string.wireless_debugging_dialog_message)
            .setNegativeButton(R.string.wireless_debugging_dialog_cancel, null)
            .setPositiveButton(R.string.wireless_debugging_dialog_open_settings) { _, _ ->
                openWirelessDebuggingSettings()
            }
            .setOnDismissListener { wirelessDebuggingDialogVisible = false }
            .show()
    }

    private fun openWirelessDebuggingSettings() {
        val intent = Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            putExtra(":settings:fragment_args_key", "toggle_adb_wireless")
        }
        startActivity(intent)
    }

    private fun restoreMonitoringSelections() {
        val selectedCategories = prefs.getStringSet(PREF_MONITORING_CATEGORIES, emptySet()).orEmpty()
        apkCheckBox.isChecked = CATEGORY_APKS in selectedCategories
        ipsCheckBox.isChecked = CATEGORY_IPS in selectedCategories
        servicesCheckBox.isChecked = CATEGORY_SERVICES in selectedCategories
    }

    private fun bindMonitoringPreferenceListeners() {
        apkCheckBox.setOnCheckedChangeListener { _, _ -> saveMonitoringSelections() }
        ipsCheckBox.setOnCheckedChangeListener { _, _ -> saveMonitoringSelections() }
        servicesCheckBox.setOnCheckedChangeListener { _, _ -> saveMonitoringSelections() }
    }

    private fun saveMonitoringSelections() {
        val selectedCategories = buildSet {
            if (apkCheckBox.isChecked) add(CATEGORY_APKS)
            if (ipsCheckBox.isChecked) add(CATEGORY_IPS)
            if (servicesCheckBox.isChecked) add(CATEGORY_SERVICES)
        }

        prefs.edit()
            .putStringSet(PREF_MONITORING_CATEGORIES, selectedCategories)
            .apply()
    }

    private fun ensureBackgroundServiceStarted() {
        if (backgroundLoopStarted) return

        val serviceIntent = AdbCommandService.startLoopIntent(applicationContext)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                applicationContext.startForegroundService(serviceIntent)
            } else {
                applicationContext.startService(serviceIntent)
            }
            backgroundLoopStarted = true
        } catch (_: Throwable) {
            applicationContext.startService(serviceIntent)
            backgroundLoopStarted = true
        }
    }

    private fun handleBackgroundServiceState() {
        val connected = isWirelessDebuggingEnabled() && adbManager.adbState.value in AdbState.successStates()
        if (connected) {
            ensureBackgroundServiceStarted()
        } else {
            backgroundLoopStarted = false
        }
    }
}
