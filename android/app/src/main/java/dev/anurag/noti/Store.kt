package dev.anurag.noti

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class Pairing(val relay: String, val secret: ByteArray) {
    val keys by lazy { Crypto.Keys(secret) }
}

/** Stores the pairing secret encrypted under a non-exportable Android Keystore key. */
object Store {
    private const val ALIAS = "noti_wrap_v1"
    private fun prefs(ctx: Context) = ctx.getSharedPreferences("noti", Context.MODE_PRIVATE)

    private fun wrapKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(
                KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
        }.generateKey()
    }

    fun savePairing(ctx: Context, relay: String, secret: ByteArray) {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, wrapKey()) }
        val blob = c.iv + c.doFinal(secret)
        prefs(ctx).edit().putString("relay", relay).putString("secret", Crypto.b64(blob)).apply()
    }

    fun loadPairing(ctx: Context): Pairing? {
        val p = prefs(ctx)
        val relay = p.getString("relay", null) ?: return null
        val blob = p.getString("secret", null)?.let { Crypto.unb64(it) } ?: return null
        return try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, wrapKey(), GCMParameterSpec(128, blob, 0, 12))
            Pairing(relay, c.doFinal(blob, 12, blob.size - 12))
        } catch (e: Exception) {
            null
        }
    }

    fun clear(ctx: Context) {
        prefs(ctx).edit().clear().apply()
        ctx.getSharedPreferences("icons", Context.MODE_PRIVATE).edit().clear().apply()
    }

    fun blocked(ctx: Context): Set<String> = prefs(ctx).getStringSet("blocked", emptySet()) ?: emptySet()

    fun setBlocked(ctx: Context, pkgs: Set<String>) {
        prefs(ctx).edit().putStringSet("blocked", pkgs).apply()
    }

    fun pending(ctx: Context): List<String> =
        prefs(ctx).getString("pending", "")!!.split('\n').filter { it.isNotEmpty() }

    fun setPending(ctx: Context, items: List<String>) {
        prefs(ctx).edit().putString("pending", items.joinToString("\n")).apply()
    }

    /** Per-app record of the last icon send: "sentAtMs:appLastUpdateMs". */
    fun iconSent(ctx: Context, pkg: String): Pair<Long, Long>? =
        ctx.getSharedPreferences("icons", Context.MODE_PRIVATE).getString(pkg, null)?.split(':')
            ?.let { (it.getOrNull(0)?.toLongOrNull() ?: return null) to (it.getOrNull(1)?.toLongOrNull() ?: return null) }

    fun setIconSent(ctx: Context, pkg: String, sentAt: Long, appUpdated: Long) {
        ctx.getSharedPreferences("icons", Context.MODE_PRIVATE).edit().putString(pkg, "$sentAt:$appUpdated").apply()
    }

    fun setStatus(ctx: Context, s: String) {
        prefs(ctx).edit().putString("status", s).apply()
    }

    fun status(ctx: Context): String = prefs(ctx).getString("status", "—")!!
}
