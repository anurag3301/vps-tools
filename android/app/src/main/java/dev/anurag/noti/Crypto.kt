package dev.anurag.noti

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Mirrors crates/proto: HKDF-SHA256 key derivation, ChaCha20-Poly1305 sealing, HMAC request signing. */
object Crypto {
    private val rng = SecureRandom()

    class Keys(secret: ByteArray) {
        private val prk = hmac("noti-stuff/v1".toByteArray(), secret)
        private fun expand(info: String, len: Int) =
            hmac(prk, info.toByteArray() + byteArrayOf(1)).copyOf(len)

        val channel = expand("channel", 16)
        val enc = expand("enc", 32)
        val authPhone = expand("auth-phone", 32)
        val channelHex get() = hex(channel)
    }

    fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)

    fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    fun b64(b: ByteArray): String = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b)
    fun unb64(s: String): ByteArray = java.util.Base64.getUrlDecoder().decode(s)

    /** base64url(nonce || ciphertext || tag), channel id bound as AAD. */
    fun seal(enc: ByteArray, channel: ByteArray, plaintext: ByteArray, nonce: ByteArray = randomBytes(12)): String {
        val c = Cipher.getInstance("ChaCha20-Poly1305")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(enc, "ChaCha20"), IvParameterSpec(nonce))
        c.updateAAD(channel)
        return b64(nonce + c.doFinal(plaintext))
    }

    fun open(enc: ByteArray, channel: ByteArray, sealed: String): ByteArray {
        val raw = unb64(sealed)
        val c = Cipher.getInstance("ChaCha20-Poly1305")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(enc, "ChaCha20"), IvParameterSpec(raw.copyOfRange(0, 12)))
        c.updateAAD(channel)
        return c.doFinal(raw, 12, raw.size - 12)
    }

    fun signingInput(method: String, pathAndQuery: String, ts: Long, nonce: String, body: ByteArray): String =
        signingInputHashed(method, pathAndQuery, ts, nonce, hex(MessageDigest.getInstance("SHA-256").digest(body)))

    /** For large bodies: the SHA-256 (hex) is signed up front and verified by the relay while streaming. */
    fun signingInputHashed(method: String, pathAndQuery: String, ts: Long, nonce: String, bodySha256Hex: String): String =
        "v1\n${method.uppercase()}\n$pathAndQuery\n$ts\n$nonce\n$bodySha256Hex"

    fun sign(key: ByteArray, input: String): String = hex(hmac(key, input.toByteArray()))

    fun randomBytes(n: Int) = ByteArray(n).also { rng.nextBytes(it) }
    fun newNonce() = hex(randomBytes(12))
}
