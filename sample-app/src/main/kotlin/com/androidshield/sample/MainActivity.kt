package com.androidshield.sample

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.androidshield.core.model.SecurityReport
import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat
import com.androidshield.core.report.SecurityReportBuilder
import com.androidshield.nativebridge.NativeShield
import com.androidshield.runtime.api.AndroidShield
import com.androidshield.sample.demo.ProtectedSecrets

/**
 * Compose dashboard exercising verify, monitoring, secure storage, native, and reports.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AndroidShield.protectScreen(this)
        setContent {
            MaterialTheme(colorScheme = sampleColorScheme) {
                ShieldDemoScreen()
            }
        }
    }
}

private val Navy = Color(0xFF0B1F33)
private val Teal = Color(0xFF1F6F6B)
private val Sand = Color(0xFFE6DFD3)
private val Ink = Color(0xFF14212B)
private val Soft = Color(0xFFF7F3EC)
private val Danger = Color(0xFF8B2E2E)
private val Ok = Color(0xFF1B5E3B)

private val sampleColorScheme =
    lightColorScheme(
        primary = Navy,
        secondary = Teal,
        background = Sand,
        surface = Soft,
        onPrimary = Soft,
        onSecondary = Soft,
        onBackground = Ink,
        onSurface = Ink,
    )

private data class DemoState(
    val report: SecurityReport? = null,
    val monitoring: Boolean = AndroidShield.isMonitoring(),
    val nativeLine: String = nativeSummary(),
    val storageLine: String = "Secure storage idle",
    val actionLine: String = "Tap Verify to run detectors",
)

@Composable
private fun ShieldDemoScreen() {
    var state by remember { mutableStateOf(DemoState()) }

    Column(
        modifier =
        Modifier
            .fillMaxSize()
            .background(Sand)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 28.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(
            text = "AndroidShield",
            fontSize = 34.sp,
            fontWeight = FontWeight.Bold,
            color = Navy,
        )
        Text(
            text = "Sample protection dashboard — report-only by default",
            color = Teal,
            fontSize = 14.sp,
        )
        Text(
            text = "Annotation demo: ${ProtectedSecrets.greeting("engineer")}",
            color = Ink.copy(alpha = 0.75f),
            fontSize = 13.sp,
        )

        StatusPanel(state.report)

        SectionTitle("Actions")
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Button(
                onClick = {
                    val report = AndroidShield.verify()
                    state =
                        state.copy(
                            report = report,
                            actionLine = "Verify complete · threats=${report.threats.size}",
                            nativeLine = nativeSummary(),
                        )
                },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = Navy),
            ) {
                Text("Verify")
            }
            OutlinedButton(
                onClick = {
                    if (AndroidShield.isMonitoring()) {
                        AndroidShield.stopMonitoring()
                        state =
                            state.copy(
                                monitoring = false,
                                actionLine = "Monitoring stopped",
                            )
                    } else {
                        AndroidShield.startMonitoring()
                        state =
                            state.copy(
                                monitoring = true,
                                actionLine = "Monitoring started (periodic RASP)",
                            )
                    }
                },
                modifier = Modifier.weight(1f),
            ) {
                Text(if (state.monitoring) "Stop monitor" else "Start monitor")
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            OutlinedButton(
                onClick = {
                    val storage = AndroidShield.secureStorage()
                    val key = "demo.secret"
                    storage.putString(key, "shield-${System.currentTimeMillis()}")
                    val roundTrip = storage.getString(key)
                    state =
                        state.copy(
                            storageLine = "prefs[$key]=$roundTrip",
                            actionLine = "SecureStorage put/get OK",
                        )
                },
                modifier = Modifier.weight(1f),
            ) {
                Text("Secure storage")
            }
            OutlinedButton(
                onClick = {
                    state =
                        state.copy(
                            report = AndroidShield.generateReport(),
                            actionLine = "generateReport() · compromised=${AndroidShield.isCompromised()}",
                            nativeLine = nativeSummary(),
                        )
                },
                modifier = Modifier.weight(1f),
            ) {
                Text("Report")
            }
        }

        SectionTitle("Native")
        MonoBlock(state.nativeLine)

        SectionTitle("Secure storage")
        MonoBlock(state.storageLine)

        SectionTitle("Status")
        MonoBlock(state.actionLine)

        val report = state.report
        if (report != null) {
            SectionTitle("Threats (${report.threats.size})")
            if (report.threats.isEmpty()) {
                Text("No threats in last evaluation.", color = Ok)
            } else {
                report.threats.forEach { ThreatRow(it) }
            }
            SectionTitle("JSON")
            MonoBlock(SecurityReportBuilder.toJson(report))
        }

        Spacer(modifier = Modifier.height(24.dp))
    }
}

@Composable
private fun StatusPanel(report: SecurityReport?) {
    val secure = report?.secure
    val score = report?.score
    val color =
        when {
            secure == null -> Teal
            secure -> Ok
            else -> Danger
        }
    Column(
        modifier =
        Modifier
            .fillMaxWidth()
            .background(Soft)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(
            text =
            when (secure) {
                null -> "Awaiting first verify"
                true -> "SECURE"
                false -> "INSECURE"
            },
            color = color,
            fontWeight = FontWeight.Bold,
            fontSize = 18.sp,
        )
        Text(
            text = "score=${score ?: "—"} · compromised=${if (report == null) "—" else AndroidShield.isCompromised()}",
            color = Ink,
        )
        Text(
            text = "initialized=${AndroidShield.isInitialized()} · monitoring=${AndroidShield.isMonitoring()}",
            color = Ink.copy(alpha = 0.7f),
            fontSize = 13.sp,
        )
    }
}

@Composable
private fun ThreatRow(threat: Threat) {
    Column(
        modifier =
        Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
    ) {
        Text(
            text = "${threat.severity} · ${threat.id}",
            color = severityColor(threat.severity),
            fontWeight = FontWeight.SemiBold,
            fontSize = 13.sp,
        )
        Text(text = threat.title, color = Ink, fontSize = 14.sp)
        Text(
            text = threat.description,
            color = Ink.copy(alpha = 0.7f),
            fontSize = 12.sp,
        )
        Spacer(
            Modifier
                .padding(top = 8.dp)
                .fillMaxWidth()
                .height(1.dp)
                .background(Navy.copy(alpha = 0.12f)),
        )
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(
        text = text.uppercase(),
        color = Navy,
        fontWeight = FontWeight.Bold,
        fontSize = 12.sp,
        letterSpacing = 1.2.sp,
        modifier = Modifier.padding(top = 4.dp),
    )
}

@Composable
private fun MonoBlock(text: String) {
    Text(
        text = text,
        fontFamily = FontFamily.Monospace,
        fontSize = 12.sp,
        color = Ink,
        modifier =
        Modifier
            .fillMaxWidth()
            .background(Soft)
            .padding(12.dp),
    )
}

private fun severityColor(severity: Severity): Color =
    when (severity) {
        Severity.LOW -> Teal
        Severity.MEDIUM -> Color(0xFF8A5A00)
        Severity.HIGH -> Color(0xFF9A3B1A)
        Severity.CRITICAL -> Danger
    }

private fun nativeSummary(): String {
    if (!NativeShield.isAvailable()) {
        return "libandroidshield: not loaded (ABI / install check)"
    }
    val findings = NativeShield.evaluate()
    return "libandroidshield: loaded · clean=${findings.isClean} · " +
        "debug=0x${findings.debuggerFlags.toString(16)} · " +
        "hook=0x${findings.hookFlags.toString(16)} · " +
        "mem=0x${findings.memoryFlags.toString(16)}"
}
