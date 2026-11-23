package dev.anurag.noti

import org.junit.Assert.assertEquals
import org.junit.Test

/** Vectors produced by crates/proto (see `print_interop_vector`). Secret = 32 bytes of 0x07. */
class CryptoInteropTest {
    private val keys = Crypto.Keys(ByteArray(32) { 7 })
    private val sealed = "fVhLEUhEAjY5uB7IjIGWko43MqGh0hmG-VJOT7qbxcRBsO0p1HuPjTLXmCDzqAo"

    @Test fun channelMatchesRust() = assertEquals("bfa49189117c2627ad4fb6c66ae12c29", keys.channelHex)

    @Test fun opensRustCiphertext() =
        assertEquals("{\"hello\":\"interop\"}", String(Crypto.open(keys.enc, keys.channel, sealed)))

    @Test fun signatureMatchesRust() = assertEquals(
        "78b44d0c5cc9e8e9eb9a3c874dbd0641858f9ef84d080cb67f29bbbc9f7af249",
        Crypto.sign(keys.authPhone, Crypto.signingInput("POST", "/v1/send", 1700000000, "abc", sealed.toByteArray()))
    )

    @Test fun roundTrip() {
        val s = Crypto.seal(keys.enc, keys.channel, "x".toByteArray())
        assertEquals("x", String(Crypto.open(keys.enc, keys.channel, s)))
    }
}
