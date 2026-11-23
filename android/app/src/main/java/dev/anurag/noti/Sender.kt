package dev.anurag.noti

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

/** Seals notifications and delivers them to the relay, with a persisted retry queue. */
object Sender {
    private const val MAX_PENDING = 200
    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var backoffMs = 15_000L
    private var netCallbackRegistered = false

    fun enqueue(ctx: Context, n: JSONObject) {
        val app = ctx.applicationContext
        io.execute {
            val p = Store.loadPairing(app) ?: return@execute
            val sealed = Crypto.seal(p.keys.enc, p.keys.channel, n.toString().toByteArray())
            Store.setPending(app, (Store.pending(app) + sealed).takeLast(MAX_PENDING))
            flushLocked(app)
        }
        registerNetworkCallback(app)
    }

    fun flush(ctx: Context) {
        val app = ctx.applicationContext
        io.execute { flushLocked(app) }
    }

    private fun flushLocked(ctx: Context) {
        val p = Store.loadPairing(ctx) ?: return
        var queue = Store.pending(ctx)
        while (queue.isNotEmpty()) {
            when (post(p, queue.first())) {
                Result.OK, Result.DROP -> {
                    queue = queue.drop(1)
                    Store.setPending(ctx, queue)
                    backoffMs = 15_000L
                    Store.setStatus(ctx, "last sent ${java.text.DateFormat.getTimeInstance().format(java.util.Date())}")
                }
                Result.RETRY -> {
                    Store.setStatus(ctx, "relay unreachable, ${queue.size} queued")
                    main.postDelayed({ flush(ctx) }, backoffMs)
                    backoffMs = (backoffMs * 2).coerceAtMost(300_000L)
                    return
                }
            }
        }
    }

    private enum class Result { OK, DROP, RETRY }

    private fun post(p: Pairing, sealed: String): Result {
        return try {
            val body = sealed.toByteArray()
            val ts = System.currentTimeMillis() / 1000
            val nonce = Crypto.newNonce()
            val sig = Crypto.sign(p.keys.authPhone, Crypto.signingInput("POST", "/v1/send", ts, nonce, body))
            val c = URL(p.relay.trimEnd('/') + "/v1/send").openConnection() as HttpURLConnection
            c.requestMethod = "POST"
            c.connectTimeout = 10_000
            c.readTimeout = 15_000
            c.doOutput = true
            c.setRequestProperty("x-chan", p.keys.channelHex)
            c.setRequestProperty("x-ts", ts.toString())
            c.setRequestProperty("x-nonce", nonce)
            c.setRequestProperty("x-sig", sig)
            c.outputStream.use { it.write(body) }
            val code = c.responseCode
            c.disconnect()
            when {
                code in 200..299 -> Result.OK
                code == 429 || code >= 500 -> Result.RETRY
                code == 401 -> Result.RETRY // clock skew or relay not registered yet; keep the message
                else -> Result.DROP
            }
        } catch (e: Exception) {
            Result.RETRY
        }
    }

    private fun registerNetworkCallback(ctx: Context) {
        if (netCallbackRegistered) return
        netCallbackRegistered = true
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        cm.registerDefaultNetworkCallback(object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                backoffMs = 15_000L
                flush(ctx)
            }
        })
    }

    fun ensureNetworkCallback(ctx: Context) = registerNetworkCallback(ctx.applicationContext)
}
