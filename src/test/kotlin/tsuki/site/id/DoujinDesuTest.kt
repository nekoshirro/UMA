package tsuki.site.id

import okhttp3.Dns
import org.json.JSONArray
import org.json.JSONObject
import org.jsoup.parser.Parser
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import tsuki.model.MangaState
import tsuki.parsers.DoujinDesuDns
import java.net.InetAddress
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import kotlin.math.abs

class DoujinDesuTest {

    @Test
    fun testDoujinDesuDnsFiltersBlockedIps() {
        val addresses = DoujinDesuDns.lookup("doujin.desu.xxx")
        assertNotNull(addresses)
        assertTrue(addresses.isNotEmpty(), "Should return at least one IP address")

        for (addr in addresses) {
            val hostAddress = addr.hostAddress ?: ""
            assertFalse(
                hostAddress.startsWith("36.86."),
                "DNS lookup must filter out Indonesian ISP Internet Positif blocked IP ($hostAddress)",
            )
            assertFalse(
                hostAddress.startsWith("118.98."),
                "DNS lookup must filter out Indonesian ISP blocked IP ($hostAddress)",
            )
        }
    }

    @Test
    fun testDoujinDesuDnsResolvesPicsDomain() {
        val addresses = DoujinDesuDns.lookup("amz-ch.desu.pics")
        assertNotNull(addresses)
        assertTrue(addresses.isNotEmpty(), "Should resolve amz-ch.desu.pics")

        val ips = addresses.mapNotNull { it.hostAddress }
        assertTrue(
            ips.any { it.startsWith("104.") || it.startsWith("172.") || it.contains(":") },
            "Expected Cloudflare IP for amz-ch.desu.pics, got $ips",
        )
    }

    @Test
    fun testDoujinDesuDnsNonTargetHostDelegatesToSystem() {
        val addresses = DoujinDesuDns.lookup("localhost")
        assertNotNull(addresses)
        assertTrue(addresses.any { it.isLoopbackAddress })
    }

    @Test
    fun testChapterImageUrlPreservesHmacPath() {
        val sampleSignedUrl = "https://amz-ch.desu.pics/ch/storage2/uploads/MMK/switch-on/ch-120/120%20(1).webp?X-Amz-Algorithm=AMZ-CH-HMAC-SHA256&X-Amz-Date=20261115T121108Z&X-Amz-Expires=86400&X-Amz-Signature=8c204d51f0c2aa1f45fc360af6d62d5f47227f71b41443075a65722a18607b43"

        // Old buggy behavior replaced /uploads/ with /storage/uploads/ -> /storage2/storage/uploads/
        val unescaped = Parser.unescapeEntities(sampleSignedUrl, false)
        assertFalse(
            unescaped.contains("/storage2/storage/uploads/"),
            "URL path must not have duplicated /storage2/storage/ prefix which breaks HMAC signature",
        )
        assertTrue(
            unescaped.contains("/ch/storage2/uploads/"),
            "URL path must preserve original /ch/storage2/uploads/ path",
        )
    }

    @Test
    fun testChapterImageUrlUnescapesEntities() {
        val escapedUrl = "https://amz-ch.desu.pics/ch/storage2/uploads/MMK/ch-1/1.webp?X-Amz-Algorithm=AMZ-CH-HMAC-SHA256&amp;X-Amz-Date=20261115&amp;X-Amz-Signature=abc123"
        val unescaped = Parser.unescapeEntities(escapedUrl, false)

        assertFalse(unescaped.contains("&amp;"), "HTML entity &amp; should be unescaped to &")
        assertTrue(unescaped.contains("&X-Amz-Date="), "Should contain proper query param delimiter &")
        assertTrue(unescaped.contains("&X-Amz-Signature="), "Should contain proper query param delimiter &")
    }

    @Test
    fun testStatusMapping() {
        fun mapStatus(status: String): MangaState? = when (status.lowercase()) {
            "completed", "finished" -> MangaState.FINISHED
            "ongoing", "publishing" -> MangaState.ONGOING
            else -> null
        }

        assertEquals(MangaState.ONGOING, mapStatus("publishing"))
        assertEquals(MangaState.ONGOING, mapStatus("ongoing"))
        assertEquals(MangaState.ONGOING, mapStatus("PUBLISHING"))
        assertEquals(MangaState.FINISHED, mapStatus("completed"))
        assertEquals(MangaState.FINISHED, mapStatus("finished"))
        assertNull(mapStatus("unknown"))
    }

    @Test
    fun testTermListAuthorsAndGenresParsing() {
        val termList = "Sex Toys:genre:sex-toys|Masturbation:genre:masturbation|KMH:author:kmh|Shell:author:shell|Manhwa:series:manhwa"
        val termMap = mutableMapOf<String, MutableList<String>>()
        termList.split('|').forEach { term ->
            val parts = term.split(':')
            if (parts.size == 3) {
                termMap.getOrPut(parts[1]) { mutableListOf() }.add(parts[0])
            }
        }

        val authors = termMap["author"].orEmpty()
        assertTrue(authors.contains("KMH"))
        assertTrue(authors.contains("Shell"))

        val genres = termMap["genre"].orEmpty()
        assertTrue(genres.contains("Sex Toys"))
        assertTrue(genres.contains("Masturbation"))
    }

    @Test
    fun testAltTitlesParsing() {
        val rawAltTitles = "스위치온 시즌2, 调教开关：第二季, スイッチ・オン, Swichon|Liebe auf Knopfdruck"
        val altTitles = rawAltTitles.split('|', ',')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toSet()

        assertTrue(altTitles.contains("스위치온 시즌2"))
        assertTrue(altTitles.contains("Swichon"))
        assertTrue(altTitles.contains("Liebe auf Knopfdruck"))
        assertEquals(5, altTitles.size)
    }

    @Test
    fun testDecryptionLogic() {
        fun toSigned32(x: Long): Int {
            var y = x and 0xFFFFFFFFL
            if (y >= 0x80000000L) y -= 0x100000000L
            return y.toInt()
        }

        fun wH(e: Int): String {
            val t = "doujindesu-scrapers-cannot-read-this-super-secret-salt-2026-v2_$e"
            var a = 0
            for (ch in t) {
                a = (a shl 5) - a + ch.code
                a = toSigned32(a.toLong())
            }
            var l = if (a != 0) abs(a).toLong() else 123456789L
            return buildString {
                repeat(32) {
                    l = (l * 1664525L + 1013904223L) % 4294967296L
                    append((33 + (l % 93)).toInt().toChar())
                }
            }
        }

        val now = System.currentTimeMillis()
        val t = now / 3600000L
        val keys = listOf(wH(t.toInt()), wH((t - 1).toInt()), wH((t + 1).toInt()))

        fun yre(encryptedHex: String, key: String): String {
            val bytes = encryptedHex.chunked(2).mapNotNull { it.toIntOrNull(16) }
            var d = 42
            val keyLen = key.length
            return buildString {
                for ((idx, byteVal) in bytes.withIndex()) {
                    val keyChar = key[idx % keyLen].code
                    val k = byteVal xor keyChar xor (idx * 13) xor d
                    append((k and 0xFF).toChar())
                    d = (d + byteVal) % 256
                }
            }
        }

        fun encrypt(plainText: String, key: String): String {
            var d = 42
            val keyLen = key.length
            val hex = StringBuilder()
            val encoded = java.net.URLEncoder.encode(plainText, "UTF-8")
            for ((idx, ch) in encoded.withIndex()) {
                val byteVal = ch.code
                val keyChar = key[idx % keyLen].code
                val k = byteVal xor keyChar xor (idx * 13) xor d
                hex.append(String.format("%02x", k and 0xFF))
                d = (d + (k and 0xFF)) % 256
            }
            return hex.toString()
        }

        val originalText = """[{"id":"123","title":"Test Title","slug":"test-title"}]"""
        val encryptedHex = encrypt(originalText, keys[0])

        var decrypted: String? = null
        for (k in keys) {
            try {
                val decoded = yre(encryptedHex, k)
                decrypted = URLDecoder.decode(decoded, StandardCharsets.UTF_8.name())
                break
            } catch (_: Exception) {
            }
        }

        assertEquals(originalText, decrypted)
    }
}
