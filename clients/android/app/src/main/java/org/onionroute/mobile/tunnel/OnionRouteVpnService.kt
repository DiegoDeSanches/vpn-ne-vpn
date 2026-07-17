package org.onionroute.mobile.tunnel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import org.onionroute.mobile.MainActivity
import org.onionroute.mobile.core.NativeCore
import java.io.FileInputStream
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Local packet interception only. No VPN protocol is used to reach a server;
 * the future production adapter sends protected flows through Tor.
 */
class OnionRouteVpnService : VpnService(), NetworkMonitor.Listener {
    private val running = AtomicBoolean(false)
    private val packetExecutor = Executors.newSingleThreadExecutor()
    private val controlExecutor = Executors.newSingleThreadScheduledExecutor()
    private val reconnectPolicy = ReconnectPolicy()
    private var reconnectTask: ScheduledFuture<*>? = null
    private var reconnectAttempt = 0
    private var tun: ParcelFileDescriptor? = null
    private var coreHandle = 0L
    @Volatile private var networkHealthy = false
    private lateinit var networkMonitor: NetworkMonitor
    private lateinit var powerManager: PowerManager
    private val sleepReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                Intent.ACTION_SCREEN_OFF -> NativeCore.nativeSuspend(
                    coreHandle,
                    SystemClock.elapsedRealtime(),
                )
                Intent.ACTION_SCREEN_ON, Intent.ACTION_USER_PRESENT -> NativeCore.nativeResume(
                    coreHandle,
                    SystemClock.elapsedRealtime(),
                    networkHealthy,
                )
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, notification("Traffic blocked while preparing Tor"))
        coreHandle = NativeCore.nativeCreate(EVENT_CAPACITY, MEMORY_BUDGET_BYTES)
        check(coreHandle != 0L) { "Rust core ABI initialization failed" }
        powerManager = getSystemService(PowerManager::class.java)
        networkMonitor = NetworkMonitor(
            getSystemService(ConnectivityManager::class.java),
            this,
        ).also { it.start() }
        val sleepFilter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_USER_PRESENT)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(sleepReceiver, sleepFilter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(sleepReceiver, sleepFilter)
        }
        controlExecutor.scheduleWithFixedDelay(::drainEvents, 0, 100, TimeUnit.MILLISECONDS)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action ?: ACTION_CONNECT) {
            ACTION_CONNECT -> connect(intent)
            ACTION_DISCONNECT -> if (!isAlwaysOn) disconnectAndStop()
            ACTION_SOFT_ROTATE -> NativeCore.nativeRotate(coreHandle, false)
            ACTION_HARD_ROTATE -> NativeCore.nativeRotate(coreHandle, true)
        }
        return START_STICKY
    }

    private fun connect(intent: Intent?) {
        if (!running.compareAndSet(false, true)) return
        val country = (intent?.getStringExtra(EXTRA_COUNTRY) ?: "US").uppercase()
        val mode = intent?.getIntExtra(EXTRA_MODE, 0) ?: 0
        if (country.length != 2 || NativeCore.nativeSetCountry(coreHandle, country.encodeToByteArray()) != 0 ||
            NativeCore.nativeSetMode(coreHandle, mode) != 0 ||
            NativeCore.nativeConnect(coreHandle) != 0
        ) {
            running.set(false)
            return
        }

        val builder = Builder()
            .setSession("OnionRoute — Tor protected")
            .setMtu(1280)
            .addAddress("10.77.0.1", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("10.77.0.2")
            .addAddress("fd77:6f6e:696f::1", 128)
            .addRoute("::", 0)
            .addDnsServer("fd77:6f6e:696f::2")
            .setBlocking(true)

        val excluded = intent?.getStringArrayExtra(EXTRA_EXCLUDED_PACKAGES).orEmpty()
        for (packageName in excluded.take(MAX_SPLIT_APPS)) {
            runCatching { builder.addDisallowedApplication(packageName) }
        }

        tun = builder.establish()
        if (tun == null) {
            NativeCore.nativeSetTunnelReady(coreHandle, false)
            running.set(false)
            return
        }
        NativeCore.nativeSetTunnelReady(coreHandle, true)
        packetExecutor.execute(::packetLoop)
    }

    private fun packetLoop() {
        val descriptor = tun ?: return
        val input = FileInputStream(descriptor.fileDescriptor)
        val packet = ByteArray(MAX_PACKET_BYTES)
        while (running.get()) {
            val length = runCatching { input.read(packet) }.getOrElse { -1 }
            if (length <= 0) break
            // The prototype returns UNAVAILABLE and drops the packet. This is the
            // required fail-closed behavior until CP-0006 provides a real adapter.
            NativeCore.nativeSubmitPacket(coreHandle, packet, length)
        }
    }

    override fun onUsableNetwork(network: Network, expensive: Boolean, constrained: Boolean) {
        reconnectTask?.cancel(false)
        setUnderlyingNetworks(arrayOf(network))
        val delay = reconnectPolicy.delayMs(
            reconnectAttempt,
            powerManager.isPowerSaveMode,
            expensive,
            constrained,
        )
        reconnectTask = controlExecutor.schedule({
            NativeCore.nativeSetNetwork(coreHandle, true, expensive, constrained, false)
            networkHealthy = true
            reconnectAttempt = 0
        }, delay, TimeUnit.MILLISECONDS)
    }

    override fun onCaptiveNetwork(network: Network) {
        networkHealthy = false
        setUnderlyingNetworks(emptyArray())
        NativeCore.nativeSetNetwork(coreHandle, true, false, false, true)
        updateNotification("Captive portal detected — OnionRoute remains blocked")
    }

    override fun onNoNetwork() {
        networkHealthy = false
        reconnectAttempt = (reconnectAttempt + 1).coerceAtMost(8)
        setUnderlyingNetworks(emptyArray())
        NativeCore.nativeSetNetwork(coreHandle, false, false, false, false)
        updateNotification("No usable network — traffic remains blocked")
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= TRIM_MEMORY_RUNNING_LOW) drainEvents()
    }

    override fun onRevoke() {
        disconnectAndStop()
        super.onRevoke()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // UI task removal must not stop the separate tunnel process.
    }

    override fun onDestroy() {
        running.set(false)
        reconnectTask?.cancel(true)
        networkMonitor.close()
        runCatching { unregisterReceiver(sleepReceiver) }
        if (coreHandle != 0L) {
            NativeCore.nativeDisconnect(coreHandle)
            NativeCore.nativeDestroy(coreHandle)
            coreHandle = 0
        }
        tun?.close()
        tun = null
        packetExecutor.shutdownNow()
        controlExecutor.shutdownNow()
        super.onDestroy()
    }

    private fun disconnectAndStop() {
        running.set(false)
        NativeCore.nativeDisconnect(coreHandle)
        tun?.close()
        tun = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun drainEvents() {
        if (coreHandle == 0L) return
        while (true) {
            val event = runCatching { NativeCore.pollEvent(coreHandle) }.getOrNull() ?: break
            if (event.kind == EVENT_STATE_CHANGED) {
                updateNotification(stateLabel(event.value))
            }
        }
    }

    private fun stateLabel(state: Long): String = when (state) {
        2L -> "Kill switch active"
        3L -> "Bootstrapping Tor — traffic blocked"
        4L -> "Protected through Tor"
        5L -> "Rotating protected route"
        6L -> "Reconnecting — traffic blocked"
        7L -> "Blocked for safety"
        else -> "OnionRoute is preparing"
    }

    private fun createNotificationChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "OnionRoute tunnel", NotificationManager.IMPORTANCE_LOW),
        )
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(
            NOTIFICATION_ID,
            notification(text),
        )
    }

    private fun notification(text: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pending = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("OnionRoute")
            .setContentText(text)
            .setContentIntent(pending)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    companion object {
        const val ACTION_CONNECT = "org.onionroute.mobile.CONNECT"
        const val ACTION_DISCONNECT = "org.onionroute.mobile.DISCONNECT"
        const val ACTION_SOFT_ROTATE = "org.onionroute.mobile.SOFT_ROTATE"
        const val ACTION_HARD_ROTATE = "org.onionroute.mobile.HARD_ROTATE"
        const val EXTRA_COUNTRY = "country"
        const val EXTRA_MODE = "mode"
        const val EXTRA_EXCLUDED_PACKAGES = "excluded_packages"

        private const val CHANNEL_ID = "onionroute-tunnel"
        private const val NOTIFICATION_ID = 7701
        private const val EVENT_CAPACITY = 256
        private const val MEMORY_BUDGET_BYTES = 64L * 1024L * 1024L
        private const val MAX_PACKET_BYTES = 128 * 1024
        private const val MAX_SPLIT_APPS = 128
        private const val EVENT_STATE_CHANGED = 2

        fun start(context: Context, country: String = "US", mode: Int = 0) {
            val intent = Intent(context, OnionRouteVpnService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_COUNTRY, country)
                putExtra(EXTRA_MODE, mode)
            }
            context.startForegroundService(intent)
        }
    }
}
