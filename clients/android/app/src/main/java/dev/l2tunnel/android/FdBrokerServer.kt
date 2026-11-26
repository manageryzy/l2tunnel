package dev.l2tunnel.android

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.ErrnoException
import android.system.Os
import android.util.Log
import java.io.Closeable
import java.io.FileDescriptor
import java.io.IOException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Abstract-Unix-socket FD broker matching `apps/l2tunnel-android/src/android.rs` (CL-29).
 *
 * Security & ownership contract:
 * - Every accepted peer is verified via `SO_PEERCRED` (`peerCredentials.uid == Process.myUid()`).
 * - `'M'` (monitor): held open for the lifetime of the service; closing it cleanly stops the Rust owner.
 * - `'P'` (protect): reads 1 `FileDescriptor` via `SCM_RIGHTS`, invokes `protectFd(fd)`
 *   (`VpnService.protect(fd)`), ALWAYS closes the dup'd `ParcelFileDescriptor` in `finally`,
 *   and replies `'1'` (ok) or `'0'` (refused).
 * - `'T'` (TUN handoff): invokes `establishTun()`, sends `'1'` + `SCM_RIGHTS(tunFd)`, and retains
 *   ownership of the `ParcelFileDescriptor` until replaced or closed.
 * - `'R'` (ready): signals that authentication, TUN attachment, and initial runtime readiness completed.
 */
class FdBrokerServer(
    val abstractName: String,
    private val protectFd: (Int) -> Boolean,
    private val establishTun: () -> ParcelFileDescriptor?,
    private val onReady: () -> Unit,
) : Closeable {
    private val closed = AtomicBoolean(false)
    private val server = LocalServerSocket(abstractName)
    private val executor: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(r, "l2tunnel-fd-broker").apply { isDaemon = true }
    }
    private val lock = Any()
    private var monitorSocket: LocalSocket? = null
    private var currentTun: ParcelFileDescriptor? = null

    fun start() {
        executor.execute { acceptLoop() }
    }

    private fun acceptLoop() {
        while (!closed.get()) {
            val client = try {
                server.accept()
            } catch (_: IOException) {
                if (closed.get()) return
                continue
            }
            executor.execute { handleClient(client) }
        }
    }

    private fun handleClient(client: LocalSocket) {
        var keepOpen = false
        try {
            client.soTimeout = 4000
            val cred = client.peerCredentials
            if (cred.uid != Process.myUid()) {
                Log.w(TAG, "Rejected FD broker connection from foreign UID ${cred.uid}")
                return
            }
            val cmd = client.inputStream.read()
            when (cmd) {
                'M'.code -> {
                    keepOpen = true
                    synchronized(lock) {
                        if (closed.get()) {
                            keepOpen = false
                        } else {
                            try {
                                monitorSocket?.close()
                            } catch (_: IOException) {
                            }
                            monitorSocket = client
                        }
                    }
                }
                'P'.code -> handleProtect(client)
                'T'.code -> handleTun(client)
                'R'.code -> onReady()
                else -> Log.w(TAG, "Unknown FD broker command: $cmd")
            }
        } catch (e: IOException) {
            if (!closed.get()) {
                Log.w(TAG, "FD broker I/O error: ${e.message}")
            }
        } finally {
            if (!keepOpen) {
                try {
                    client.close()
                } catch (_: IOException) {
                }
            }
        }
    }

    private fun closeQuietly(fd: FileDescriptor) {
        try {
            Os.close(fd)
        } catch (_: ErrnoException) {
        }
    }

    private fun handleProtect(client: LocalSocket) {
        val fds = client.ancillaryFileDescriptors
        if (fds == null || fds.size != 1) {
            Log.w(TAG, "protect: expected 1 ancillary FD, got ${fds?.size ?: 0}")
            fds?.forEach { closeQuietly(it) }
            client.outputStream.write('0'.code)
            client.outputStream.flush()
            return
        }
        val received = fds[0]
        val ok = try {
            // ParcelFileDescriptor.dup lets us safely read the integer FD for VpnService.protect(),
            // while Os.close(received) in finally guarantees the original SCM_RIGHTS FD never leaks.
            ParcelFileDescriptor.dup(received).use { pfd ->
                val result = protectFd(pfd.fd)
                Log.i(TAG, "protect(fd=${pfd.fd}) -> $result")
                result
            }
        } catch (e: IOException) {
            Log.w(TAG, "Failed to inspect protected socket FD: ${e.message}")
            false
        } finally {
            closeQuietly(received)
        }
        client.outputStream.write(if (ok) '1'.code else '0'.code)
        client.outputStream.flush()
    }

    private fun handleTun(client: LocalSocket) {
        val pfd = establishTun()
        Log.i(TAG, "establishTun() -> ${if (pfd != null) "fd=${pfd.fd}" else "null"}")
        if (pfd == null) {
            client.outputStream.write('0'.code)
            client.outputStream.flush()
            return
        }
        val oldTun: ParcelFileDescriptor?
        synchronized(lock) {
            if (closed.get()) {
                pfd.close()
                return
            }
            oldTun = currentTun
            currentTun = pfd
        }
        try {
            client.setFileDescriptorsForSend(arrayOf(pfd.fileDescriptor))
            client.outputStream.write('1'.code)
            client.outputStream.flush()
        } finally {
            try {
                oldTun?.close()
            } catch (_: IOException) {
            }
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        synchronized(lock) {
            try {
                monitorSocket?.close()
            } catch (_: IOException) {
            }
            monitorSocket = null
            try {
                currentTun?.close()
            } catch (_: IOException) {
            }
            currentTun = null
        }
        try {
            server.close()
        } catch (_: IOException) {
        }
        executor.shutdownNow()
    }

    companion object {
        private const val TAG = "L2TunnelFdBroker"
    }
}
