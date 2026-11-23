package dev.anurag.noti

import org.json.JSONObject
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

class ApiException(val code: Int, message: String) : Exception(message)

/** Signed requests to the relay's phone-role file API. */
object Api {
    private val EMPTY_SHA = Crypto.hex(MessageDigest.getInstance("SHA-256").digest(ByteArray(0)))

    private fun open(p: Pairing, method: String, path: String, bodySha: String): HttpURLConnection {
        val ts = System.currentTimeMillis() / 1000
        val nonce = Crypto.newNonce()
        val sig = Crypto.sign(p.keys.authPhone, Crypto.signingInputHashed(method, path, ts, nonce, bodySha))
        return (URL(p.relay.trimEnd('/') + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 10_000
            readTimeout = 30_000
            setRequestProperty("x-chan", p.keys.channelHex)
            setRequestProperty("x-ts", ts.toString())
            setRequestProperty("x-nonce", nonce)
            setRequestProperty("x-sig", sig)
        }
    }

    private fun read(c: HttpURLConnection): String {
        val code = c.responseCode
        val body = (if (code in 200..299) c.inputStream else c.errorStream)?.bufferedReader()?.readText().orEmpty()
        c.disconnect()
        if (code !in 200..299) throw ApiException(code, errorText(code, body))
        return body
    }

    fun errorText(code: Int, body: String) = when {
        body.isNotBlank() -> body.trim().take(120)
        code == 401 -> "Not authorised (check pairing and the phone's clock)"
        code == 404 -> "Not found"
        code == 429 -> "Too many requests, try again shortly"
        else -> "Server error ($code)"
    }

    fun get(p: Pairing, path: String): JSONObject = JSONObject(read(open(p, "GET", path, EMPTY_SHA)))
    fun delete(p: Pairing, path: String) { read(open(p, "DELETE", path, EMPTY_SHA)) }
    fun post(p: Pairing, path: String): JSONObject = JSONObject(read(open(p, "POST", path, EMPTY_SHA).apply { doOutput = true; setFixedLengthStreamingMode(0) }))

    /** Streams [size] bytes from [input]; [sha256] must be the SHA-256 (hex) of exactly those bytes. */
    fun put(p: Pairing, name: String, sha256: String, size: Long, input: InputStream, onProgress: (Long) -> Unit): JSONObject {
        val c = open(p, "PUT", "/v1/files/$name", sha256).apply {
            doOutput = true
            setFixedLengthStreamingMode(size)
            readTimeout = 120_000
            setRequestProperty("x-body-sha256", sha256)
            setRequestProperty("content-type", "application/octet-stream")
        }
        try {
            c.outputStream.use { out ->
                val buf = ByteArray(64 * 1024)
                var sent = 0L
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    sent += n
                    onProgress(sent)
                }
            }
        } catch (e: RuntimeException) {
            c.disconnect()
            throw e
        } catch (e: java.io.IOException) {
            // The server may have rejected early (size, quota); surface its reason if there is one.
            val code = runCatching { c.responseCode }.getOrDefault(-1)
            if (code > 0 && code !in 200..299) {
                val body = c.errorStream?.bufferedReader()?.readText().orEmpty()
                throw ApiException(code, errorText(code, body))
            }
            throw e
        }
        return JSONObject(read(c))
    }
}
