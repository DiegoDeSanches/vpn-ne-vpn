package org.onionroute.mobile

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.provider.Settings
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import org.onionroute.mobile.tunnel.OnionRouteVpnService

class MainActivity : ComponentActivity() {
    private val vpnConsent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) OnionRouteVpnService.start(this)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 64, 48, 48)
        }
        layout.addView(TextView(this).apply {
            text = "OnionRoute mobile prototype\n\nVpnService is only the local packet interface. " +
                "Server transport is Tor, not a VPN protocol. This build intentionally blocks " +
                "packets until the production Rust/Tor adapter is integrated. Android always-on " +
                "and lockdown are enabled by the user in system VPN settings."
        })
        layout.addView(TextView(this).apply {
            text = "Prototype privacy: no site history or traffic content is collected. " +
                "Diagnostics are local closed-schema states only. Production terms and " +
                "territory availability require separate legal review."
        })
        layout.addView(button("Connect") {
            VpnService.prepare(this)?.let(vpnConsent::launch) ?: OnionRouteVpnService.start(this)
        })
        layout.addView(button("Disconnect") {
            startService(Intent(this, OnionRouteVpnService::class.java).apply {
                action = OnionRouteVpnService.ACTION_DISCONNECT
            })
        })
        layout.addView(button("VPN settings / always-on / lockdown") {
            startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
        })
        setContentView(layout)
    }

    private fun button(label: String, action: () -> Unit) = Button(this).apply {
        text = label
        setOnClickListener { action() }
        layoutParams = ViewGroup.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        )
    }
}
