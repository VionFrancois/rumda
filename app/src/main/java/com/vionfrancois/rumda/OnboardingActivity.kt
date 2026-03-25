package com.vionfrancois.rumda

import android.Manifest
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.edit
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.vionfrancois.rumda.cadb.AdbManager
import com.vionfrancois.rumda.cadb.AdbState
import kotlinx.coroutines.launch

class OnboardingActivity : AppCompatActivity() {
    companion object {
        private const val PREFS_NAME = "rumda_prefs"
        private const val PREF_ONBOARDING_COMPLETED = "onboarding_completed"
        private const val PREF_WELCOME_SEEN = "welcome_seen"
        private const val WIRELESS_DEBUGGING_KEY = "adb_wifi_enabled"
    }

    private enum class OnboardingStep {
        Welcome,
        Notifications,
        WirelessDebugging,
        Pairing,
        Connecting,
        Ready,
    }

    private data class OnboardingPage(
        val badge: String,
        val title: String,
        val description: String,
        val helper: String,
        val primaryAction: String,
        val secondaryAction: String? = null,
    )

    private lateinit var adbManager: AdbManager
    private lateinit var prefs: SharedPreferences
    private lateinit var heroBadgeText: TextView
    private lateinit var heroTitleText: TextView
    private lateinit var heroBodyText: TextView
    private lateinit var heroHelperText: TextView
    private lateinit var primaryActionButton: Button
    private lateinit var secondaryActionButton: Button

    private val notificationsPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        refreshUi(triggerAutoActions = true)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportActionBar?.hide()
        prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        if (prefs.getBoolean(PREF_ONBOARDING_COMPLETED, false)) {
            openMainAndFinish()
            return
        }

        adbManager = AdbManager(applicationContext)
        setContentView(R.layout.activity_onboarding)
        bindViews()
        refreshUi(triggerAutoActions = false)

        lifecycleScope.launch {
            repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                launch {
                    adbManager.adbState.collect {
                        refreshUi(triggerAutoActions = false)
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (!::adbManager.isInitialized) return
        refreshUi(triggerAutoActions = true)
    }

    override fun onDestroy() {
        if (::adbManager.isInitialized) {
            adbManager.cleanup()
        }
        super.onDestroy()
    }

    private fun bindViews() {
        heroBadgeText = findViewById(R.id.heroBadgeText)
        heroTitleText = findViewById(R.id.heroTitleText)
        heroBodyText = findViewById(R.id.heroBodyText)
        heroHelperText = findViewById(R.id.heroHelperText)
        primaryActionButton = findViewById(R.id.primaryActionButton)
        secondaryActionButton = findViewById(R.id.secondaryActionButton)
    }

    private fun refreshUi(triggerAutoActions: Boolean) {
        val step = currentOnboardingStep()
        renderOnboarding(pageFor(step))

        if (triggerAutoActions && step == OnboardingStep.Connecting && adbManager.adbState.value !in AdbState.successStates()) {
            adbManager.autoConnect()
        }
    }

    private fun renderOnboarding(page: OnboardingPage) {
        heroBadgeText.text = page.badge
        heroTitleText.text = page.title
        heroBodyText.text = page.description
        heroHelperText.text = page.helper
        primaryActionButton.text = page.primaryAction
        primaryActionButton.setOnClickListener { handleOnboardingPrimaryAction() }

        if (page.secondaryAction == null) {
            secondaryActionButton.visibility = View.GONE
        } else {
            secondaryActionButton.visibility = View.VISIBLE
            secondaryActionButton.text = page.secondaryAction
            secondaryActionButton.setOnClickListener { handleOnboardingSecondaryAction() }
        }
    }

    private fun currentOnboardingStep(): OnboardingStep {
        if (!prefs.getBoolean(PREF_WELCOME_SEEN, false)) return OnboardingStep.Welcome
        if (!notificationsPermissionGranted()) return OnboardingStep.Notifications
        if (!isWirelessDebuggingEnabled()) return OnboardingStep.WirelessDebugging
        if (adbManager.adbState.value in AdbState.successStates()) return OnboardingStep.Ready
        if (adbManager.adbState.value == AdbState.RequisitesMissing) return OnboardingStep.Pairing
        return OnboardingStep.Connecting
    }

    private fun pageFor(step: OnboardingStep): OnboardingPage {
        return when (step) {
            OnboardingStep.Welcome -> OnboardingPage(
                badge = getString(R.string.onboarding_badge_welcome),
                title = getString(R.string.onboarding_title_welcome),
                description = getString(R.string.onboarding_description_welcome),
                helper = getString(R.string.onboarding_helper_welcome),
                primaryAction = getString(R.string.onboarding_action_get_started),
            )
            OnboardingStep.Notifications -> OnboardingPage(
                badge = getString(R.string.onboarding_badge_step, 1, 4),
                title = getString(R.string.onboarding_title_notifications),
                description = getString(R.string.onboarding_description_notifications),
                helper = getString(R.string.onboarding_helper_notifications),
                primaryAction = getString(R.string.onboarding_action_enable_notifications),
            )
            OnboardingStep.WirelessDebugging -> OnboardingPage(
                badge = getString(R.string.onboarding_badge_step, 2, 4),
                title = getString(R.string.onboarding_title_wireless),
                description = getString(R.string.onboarding_description_wireless),
                helper = getString(R.string.onboarding_helper_wireless),
                primaryAction = getString(R.string.onboarding_action_open_settings),
                secondaryAction = getString(R.string.onboarding_action_review_intro),
            )
            OnboardingStep.Pairing -> OnboardingPage(
                badge = getString(R.string.onboarding_badge_step, 3, 4),
                title = getString(R.string.onboarding_title_pairing),
                description = getString(R.string.onboarding_description_pairing),
                helper = getString(R.string.onboarding_helper_pairing),
                primaryAction = getString(R.string.onboarding_action_start_pairing),
                secondaryAction = getString(R.string.onboarding_action_open_settings),
            )
            OnboardingStep.Connecting -> OnboardingPage(
                badge = getString(R.string.onboarding_badge_step, 4, 4),
                title = getString(R.string.onboarding_title_connecting),
                description = getString(R.string.onboarding_description_connecting),
                helper = getString(R.string.onboarding_helper_connecting),
                primaryAction = getString(R.string.onboarding_action_try_connect),
                secondaryAction = getString(R.string.onboarding_action_start_pairing),
            )
            OnboardingStep.Ready -> OnboardingPage(
                badge = getString(R.string.onboarding_badge_ready),
                title = getString(R.string.onboarding_title_ready),
                description = getString(R.string.onboarding_description_ready),
                helper = getString(R.string.onboarding_helper_ready),
                primaryAction = getString(R.string.onboarding_action_open_dashboard),
            )
        }
    }

    private fun handleOnboardingPrimaryAction() {
        when (currentOnboardingStep()) {
            OnboardingStep.Welcome -> prefs.edit { putBoolean(PREF_WELCOME_SEEN, true) }
            OnboardingStep.Notifications -> requestNotificationsPermission()
            OnboardingStep.WirelessDebugging -> openWirelessDebuggingSettings()
            OnboardingStep.Pairing -> adbManager.startAdbPairingService()
            OnboardingStep.Connecting -> adbManager.autoConnect()
            OnboardingStep.Ready -> {
                prefs.edit { putBoolean(PREF_ONBOARDING_COMPLETED, true) }
                openMainAndFinish()
                return
            }
        }
        refreshUi(triggerAutoActions = true)
    }

    private fun handleOnboardingSecondaryAction() {
        when (currentOnboardingStep()) {
            OnboardingStep.WirelessDebugging -> prefs.edit { putBoolean(PREF_WELCOME_SEEN, false) }
            OnboardingStep.Pairing -> openWirelessDebuggingSettings()
            OnboardingStep.Connecting -> adbManager.startAdbPairingService()
            else -> Unit
        }
        refreshUi(triggerAutoActions = false)
    }

    private fun openMainAndFinish() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
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
        }
    }

    private fun isWirelessDebuggingEnabled(): Boolean {
        return runCatching {
            Settings.Global.getInt(contentResolver, WIRELESS_DEBUGGING_KEY, 0) == 1
        }.getOrDefault(false)
    }

    private fun openWirelessDebuggingSettings() {
        val intent = Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            putExtra(":settings:fragment_args_key", "toggle_adb_wireless")
        }
        startActivity(intent)
    }
}
