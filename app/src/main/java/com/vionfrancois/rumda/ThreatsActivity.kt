package com.vionfrancois.rumda

import android.app.ActivityOptions
import android.content.Intent
import android.os.Bundle
import android.view.GestureDetector
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.vionfrancois.rumda.threats.ThreatRecord
import com.vionfrancois.rumda.threats.ThreatStoring
import com.vionfrancois.rumda.threats.ThreatStatus
import java.text.DateFormat
import java.util.Date
import kotlin.math.abs

class ThreatsActivity : AppCompatActivity() {

    companion object {
        private const val SWIPE_DISTANCE_THRESHOLD_PX = 120
        private const val SWIPE_VELOCITY_THRESHOLD = 200
    }

    private lateinit var threatStoring: ThreatStoring
    private lateinit var activeThreatsContainer: LinearLayout
    private lateinit var historyThreatsContainer: LinearLayout
    private lateinit var activeThreatsEmptyText: TextView
    private lateinit var historyEmptyText: TextView
    private lateinit var bottomNavigationView: BottomNavigationView
    private lateinit var swipeGestureDetector: GestureDetector
    private var tabSwitchInProgress = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_threats)
        supportActionBar?.hide()

        threatStoring = ThreatStoring(applicationContext)
        setupSwipeNavigation()
        bindViews()
        setupBottomNavigation()
        renderThreats()
    }

    override fun onResume() {
        super.onResume()
        tabSwitchInProgress = false
        bottomNavigationView.selectedItemId = R.id.navigation_threats
        renderThreats()
    }

    override fun onDestroy() {
        if (::threatStoring.isInitialized) {
            threatStoring.close()
        }
        super.onDestroy()
    }

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        if (::swipeGestureDetector.isInitialized) {
            swipeGestureDetector.onTouchEvent(ev)
        }
        return super.dispatchTouchEvent(ev)
    }

    private fun bindViews() {
        activeThreatsContainer = findViewById(R.id.activeThreatsContainer)
        historyThreatsContainer = findViewById(R.id.historyThreatsContainer)
        activeThreatsEmptyText = findViewById(R.id.activeThreatsEmptyText)
        historyEmptyText = findViewById(R.id.historyEmptyText)
        bottomNavigationView = findViewById(R.id.bottomNavigationView)
    }

    private fun setupBottomNavigation() {
        bottomNavigationView.selectedItemId = R.id.navigation_threats
        bottomNavigationView.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.navigation_threats -> true
                R.id.navigation_configuration -> {
                    openConfigurationTab()
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

                    if (deltaX > 0) {
                        openConfigurationTab()
                        return true
                    }
                    return false
                }
            },
        )
    }

    private fun openConfigurationTab() {
        if (tabSwitchInProgress) return
        tabSwitchInProgress = true

        val intent = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        val options = ActivityOptions.makeCustomAnimation(
            this,
            R.anim.slide_in_left,
            R.anim.slide_out_right,
        )
        startActivity(intent, options.toBundle())
    }

    private fun renderThreats() {
        val activeThreats = threatStoring.getActiveThreats()
        val historyThreats = threatStoring.getThreatHistory()

        renderActiveThreats(activeThreats)
        renderThreatHistory(historyThreats)
    }

    private fun renderActiveThreats(activeThreats: List<ThreatRecord>) {
        activeThreatsContainer.removeAllViews()
        activeThreatsEmptyText.visibility = if (activeThreats.isEmpty()) View.VISIBLE else View.GONE

        val inflater = LayoutInflater.from(this)
        for (threat in activeThreats) {
            val card = inflater.inflate(R.layout.item_threat_active, activeThreatsContainer, false)

            val titleText = card.findViewById<TextView>(R.id.threatTitleText)
            val summaryText = card.findViewById<TextView>(R.id.threatSummaryText)
            val metadataText = card.findViewById<TextView>(R.id.threatMetadataText)
            val ignoreButton = card.findViewById<Button>(R.id.ignoreThreatButton)
            val mitigateButton = card.findViewById<Button>(R.id.mitigateThreatButton)

            titleText.text = threat.title
            summaryText.text = threat.summary
            metadataText.text = buildString {
                append(getString(R.string.threats_metadata_kind, threat.kind.name))
                append(" • ")
                append(getString(R.string.threats_metadata_severity, threat.severity.name))
                append(" • ")
                append(formatTimestamp(threat.detectedAtEpochMs))
            }

            ignoreButton.setOnClickListener {
                showResolveConfirmation(threat, ThreatStatus.IGNORED)
            }
            mitigateButton.setOnClickListener {
                showResolveConfirmation(threat, ThreatStatus.MITIGATED)
            }

            activeThreatsContainer.addView(card)
        }
    }

    private fun renderThreatHistory(historyThreats: List<ThreatRecord>) {
        historyThreatsContainer.removeAllViews()
        historyEmptyText.visibility = if (historyThreats.isEmpty()) View.VISIBLE else View.GONE

        val inflater = LayoutInflater.from(this)
        for (threat in historyThreats) {
            val card = inflater.inflate(R.layout.item_threat_history, historyThreatsContainer, false)

            val titleText = card.findViewById<TextView>(R.id.historyThreatTitleText)
            val summaryText = card.findViewById<TextView>(R.id.historyThreatSummaryText)
            val statusText = card.findViewById<TextView>(R.id.historyThreatStatusText)

            titleText.text = threat.title
            summaryText.text = threat.summary

            val actionLabel = when (threat.status) {
                ThreatStatus.IGNORED -> getString(R.string.threats_status_ignored)
                ThreatStatus.MITIGATED -> getString(R.string.threats_status_mitigated)
                ThreatStatus.ACTIVE -> getString(R.string.threats_status_active)
            }

            val actionTimestamp = threat.resolvedAtEpochMs ?: threat.detectedAtEpochMs
            statusText.text = getString(
                R.string.threats_history_status,
                actionLabel,
                formatTimestamp(actionTimestamp),
            )

            historyThreatsContainer.addView(card)
        }
    }

    private fun showResolveConfirmation(threat: ThreatRecord, targetStatus: ThreatStatus) {
        val titleRes = if (targetStatus == ThreatStatus.MITIGATED) {
            R.string.threats_confirm_mitigate_title
        } else {
            R.string.threats_confirm_ignore_title
        }

        val messageRes = if (targetStatus == ThreatStatus.MITIGATED) {
            R.string.threats_confirm_mitigate_message
        } else {
            R.string.threats_confirm_ignore_message
        }

        AlertDialog.Builder(this)
            .setTitle(titleRes)
            .setMessage(getString(messageRes, threat.title))
            .setNegativeButton(R.string.threats_confirm_cancel, null)
            .setPositiveButton(R.string.threats_confirm_yes) { _, _ ->
                threatStoring.resolveThreat(threat.id, targetStatus)
                renderThreats()
            }
            .show()
    }

    private fun formatTimestamp(epochMs: Long): String {
        return DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
            .format(Date(epochMs))
    }
}
