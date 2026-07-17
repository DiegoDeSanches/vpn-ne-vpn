package org.onionroute.mobile.core

object NativeCore {
    const val OK = 0
    const val EMPTY = 1
    const val UNAVAILABLE = -8

    init {
        System.loadLibrary("onionroute_jni")
    }

    external fun nativeCreate(eventCapacity: Int, memoryBudgetBytes: Long): Long
    external fun nativeDestroy(handle: Long): Int
    external fun nativeConnect(handle: Long): Int
    external fun nativeDisconnect(handle: Long): Int
    external fun nativeSetTunnelReady(handle: Long, ready: Boolean): Int
    external fun nativeSetNetwork(
        handle: Long,
        available: Boolean,
        expensive: Boolean,
        constrained: Boolean,
        captive: Boolean,
    ): Int
    external fun nativeSetCountry(handle: Long, country: ByteArray): Int
    external fun nativeSetMode(handle: Long, mode: Int): Int
    external fun nativeRotate(handle: Long, hard: Boolean): Int
    external fun nativeRequestTokenRefresh(handle: Long): Int
    external fun nativeRequestConfigRefresh(handle: Long): Int
    external fun nativeSuspend(handle: Long, monotonicMs: Long): Int
    external fun nativeResume(handle: Long, monotonicMs: Long, healthy: Boolean): Int
    external fun nativeSubmitPacket(handle: Long, packet: ByteArray, length: Int): Int
    external fun nativePollEvent(handle: Long, fields: LongArray, data: ByteArray): Int

    data class Event(
        val kind: Int,
        val sequence: Long,
        val operationId: Long,
        val code: Int,
        val value: Long,
        val data: ByteArray,
    )

    fun pollEvent(handle: Long): Event? {
        val fields = LongArray(6)
        val data = ByteArray(64)
        return when (val status = nativePollEvent(handle, fields, data)) {
            OK -> Event(
                kind = fields[0].toInt(),
                sequence = fields[1],
                operationId = fields[2],
                code = fields[3].toInt(),
                value = fields[4],
                data = data.copyOf(fields[5].toInt()),
            )
            EMPTY -> null
            else -> throw NativeCoreException(status)
        }
    }
}

class NativeCoreException(val status: Int) : IllegalStateException("native status=$status")
