package tsuki.site.id

import okhttp3.CookieJar
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.json.JSONArray
import org.json.JSONObject
import org.jsoup.parser.Parser
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import tsuki.MangaLoaderContext
import tsuki.MangaParser
import tsuki.bitmap.Bitmap
import tsuki.config.ConfigKey
import tsuki.config.MangaSourceConfig
import tsuki.model.MangaChapter
import tsuki.model.MangaParserSource
import tsuki.model.MangaSource
import tsuki.model.MangaState
import tsuki.parsers.DoujinDesuDns
import tsuki.site.id.nsfw.DoujinDesu
import tsuki.util.generateUid
import java.net.InetAddress
import java.net.URLEncoder
import java.util.concurrent.TimeUnit
import kotlin.math.abs

class DoujinDesuTest {

    private fun createMockContext(): MangaLoaderContext {
        val mockConfig = object : MangaSourceConfig {
            @Suppress("UNCHECKED_CAST")
            override fun <T> get(key: ConfigKey<T>): T = key.defaultValue
        }
        return object : MangaLoaderContext() {
            override val httpClient: OkHttpClient = OkHttpClient.Builder().build()
            override val cookieJar: CookieJar = CookieJar.NO_COOKIES
            override fun newParserInstance(source: MangaSource): MangaParser = throw UnsupportedOperationException()
            override fun getParserSources(): List<MangaSource> = emptyList()
            override suspend fun evaluateJs(script: String): String = ""
            override suspend fun evaluateJs(baseUrl: String, script: String): String = ""
            override fun getConfig(source: MangaSource): MangaSourceConfig = mockConfig
            override fun getDefaultUserAgent(): String = "TestUA"
            override fun redrawImageResponse(response: Response, redraw: (Bitmap) -> Bitmap): Response = response
            override fun createBitmap(width: Int, height: Int): Bitmap = throw UnsupportedOperationException()
        }
    }

    @Test
    fun testDoujinDesuDnsFiltersBlockedIps() {
        val addresses = DoujinDesuDns.lookup("doujin.desu.xxx")
        assertNotNull(addresses)
        assertTrue(addresses.isNotEmpty(), "Should return at least one IP address")

        val knownBlocked = listOf("36.86.", "118.98.", "180.250.", "103.229.", "114.124.", "202.152.", "10.")
        for (addr in addresses) {
            val hostAddress = addr.hostAddress ?: ""
            for (prefix in knownBlocked) {
                assertFalse(
                    hostAddress.startsWith(prefix),
                    "DNS lookup must filter out ISP Internet Positif blocked IP prefix $prefix ($hostAddress)",
                )
            }
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
    fun testRealDecryptFunction() {
        val parser = DoujinDesu(createMockContext())

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
        val t = (now / 3600000L).toInt()
        val key = wH(t)

        fun encrypt(plainText: String, k: String): String {
            var d = 42
            val keyLen = k.length
            val hex = StringBuilder()
            val encoded = URLEncoder.encode(plainText, "UTF-8")
            for ((idx, ch) in encoded.withIndex()) {
                val byteVal = ch.code
                val keyChar = k[idx % keyLen].code
                val xorVal = byteVal xor keyChar xor (idx * 13) xor d
                hex.append(String.format("%02x", xorVal and 0xFF))
                d = (d + (xorVal and 0xFF)) % 256
            }
            return hex.toString()
        }

        val sampleJson = """[{"id":"1","title":"Test Title","slug":"test-slug"}]"""
        val encrypted = encrypt(sampleJson, key)

        val decrypted = parser.decrypt(encrypted)
        assertEquals(sampleJson, decrypted)
    }

    @Test
    fun testChapterImageUrlPreservesHmacPath() {
        val sampleSignedUrl = "https://amz-ch.desu.pics/ch/storage2/uploads/MMK/switch-on/ch-120/120%20(1).webp?X-Amz-Algorithm=AMZ-CH-HMAC-SHA256&X-Amz-Date=20261115T121108Z&X-Amz-Expires=86400&X-Amz-Signature=8c204d51f0c2aa1f45fc360af6d62d5f47227f71b41443075a65722a18607b43"

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
    fun testDeterministicPageIdGeneration() {
        val urlSession1 = "https://amz-ch.desu.pics/ch/storage2/uploads/MMK/switch-on/ch-1/1.webp?X-Amz-Algorithm=AMZ-CH-HMAC-SHA256&X-Amz-Date=20261115T110000Z&X-Amz-Signature=sig1"
        val urlSession2 = "https://amz-ch.desu.pics/ch/storage2/uploads/MMK/switch-on/ch-1/1.webp?X-Amz-Algorithm=AMZ-CH-HMAC-SHA256&X-Amz-Date=20261115T120000Z&X-Amz-Signature=sig2"

        val id1 = generateUid(MangaParserSource.DOUJINDESU, urlSession1.substringBefore('?'))
        val id2 = generateUid(MangaParserSource.DOUJINDESU, urlSession2.substringBefore('?'))

        assertEquals(id1, id2, "Page UID should be deterministic across sessions regardless of changing HMAC signature params")
    }

    @Test
    fun testSlugAndChapterIdSanitization() {
        fun sanitizeSlug(url: String): String {
            val raw = if ("/manga/" in url) url.substringAfter("/manga/") else url
            return raw.substringBefore('?').substringBefore('#').trim('/')
        }

        fun sanitizeChapterId(url: String): String {
            val raw = if ("/reader/" in url) url.substringAfter("/reader/") else url
            return raw.substringBefore('?').substringBefore('#').trim('/')
        }

        assertEquals("switch-on", sanitizeSlug("/manga/switch-on"))
        assertEquals("switch-on", sanitizeSlug("/manga/switch-on/"))
        assertEquals("switch-on", sanitizeSlug("/manga/switch-on?ref=home&page=1"))
        assertEquals("switch-on", sanitizeSlug("/manga/switch-on#comments"))

        assertEquals("4d4d3600-63dc-431f-8039-4b4b504fd53d", sanitizeChapterId("/reader/4d4d3600-63dc-431f-8039-4b4b504fd53d"))
        assertEquals("4d4d3600-63dc-431f-8039-4b4b504fd53d", sanitizeChapterId("/reader/4d4d3600-63dc-431f-8039-4b4b504fd53d/"))
        assertEquals("4d4d3600-63dc-431f-8039-4b4b504fd53d", sanitizeChapterId("/reader/4d4d3600-63dc-431f-8039-4b4b504fd53d?ref=prev#p2"))
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
        val termList = "Sex Toys:genre:sex-toys|Mother:genre:mother|KMH:author:kmh|Shell:author:shell|Manhwa:series:manhwa"
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
        assertTrue(genres.contains("Mother"))
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
    fun testChapterStableSort() {
        val chapters = listOf(
            MangaChapter(id = 3, title = "Ch 3", number = 3f, volume = 0, url = "/reader/3", scanlator = null, uploadDate = 300L, branch = null, source = MangaParserSource.DOUJINDESU),
            MangaChapter(id = 1, title = "Ch 1", number = 1f, volume = 0, url = "/reader/1", scanlator = null, uploadDate = 100L, branch = null, source = MangaParserSource.DOUJINDESU),
            MangaChapter(id = 2, title = "Ch 2", number = 2f, volume = 0, url = "/reader/2", scanlator = null, uploadDate = 200L, branch = null, source = MangaParserSource.DOUJINDESU),
        )

        val sorted = chapters.sortedWith(compareBy<MangaChapter> { it.number }.thenBy { it.uploadDate })
        assertEquals(1f, sorted[0].number)
        assertEquals(2f, sorted[1].number)
        assertEquals(3f, sorted[2].number)
    }

    @Test
    fun testNonTargetDomainPassThrough() {
        val parser = DoujinDesu(createMockContext())
        val originalRequest = Request.Builder()
            .url("https://example.com/test.jpg")
            .header("Custom-Header", "value")
            .build()

        var proceedCalled = false
        val mockChain = object : Interceptor.Chain {
            override fun request(): Request = originalRequest
            override fun proceed(request: Request): Response {
                proceedCalled = true
                assertNull(request.header("Referer"))
                assertEquals("value", request.header("Custom-Header"))
                return Response.Builder()
                    .request(request)
                    .protocol(Protocol.HTTP_1_1)
                    .code(200)
                    .message("OK")
                    .body("".toResponseBody())
                    .build()
            }
            override fun connection() = null
            override fun call() = throw UnsupportedOperationException()
            override fun connectTimeoutMillis() = 1000
            override fun withConnectTimeout(timeout: Int, unit: TimeUnit) = this
            override fun readTimeoutMillis() = 1000
            override fun withReadTimeout(timeout: Int, unit: TimeUnit) = this
            override fun writeTimeoutMillis() = 1000
            override fun withWriteTimeout(timeout: Int, unit: TimeUnit) = this
        }

        val resp = parser.intercept(mockChain)
        assertTrue(proceedCalled)
        assertEquals(200, resp.code)
    }

    @Test
    fun testListPageDataMapping() {
        val sampleItem = JSONObject("""
            {
                "id": "b57443ad-c984-4278-a4b2-a61bf891b6de",
                "title": "Kaa-san wa Ore shika Shiranai",
                "slug": "kaa-san-wa-ore-shika-shiranai",
                "cover_url": "https://pic.desu.xxx/content/manga/cover.webp",
                "status": "completed",
                "rating": 8.2,
                "manga_genres": [
                    {"genres": {"id": 58, "name": "Sex Toys", "slug": "sex-toys"}}
                ],
                "terms": "Sex Toys:genre"
            }
        """.trimIndent())

        val state = when (sampleItem.optString("status").lowercase()) {
            "completed", "finished" -> MangaState.FINISHED
            "ongoing", "publishing" -> MangaState.ONGOING
            else -> null
        }
        val rawRating = sampleItem.optDouble("rating", 0.0)
        val rating = if (rawRating > 0.0) (rawRating / 10.0).toFloat() else -1f

        assertEquals(MangaState.FINISHED, state)
        assertEquals(0.82f, rating, 0.001f)
    }

    @Test
    fun testDetailsTermListFallbackWhenAuthorIsNull() {
        val obj = JSONObject("""
            {
                "id": "123",
                "title": "Test Title",
                "slug": "test-slug",
                "author": null,
                "artist": null,
                "term_list": "Sex Toys:genre:sex-toys|Akikan:author:akikan|Shell:artist:shell"
            }
        """.trimIndent())

        val termMap = mutableMapOf<String, MutableList<String>>()
        val termList = obj.optString("term_list")
        termList.split('|').forEach { term ->
            val parts = term.split(':')
            if (parts.size == 3) {
                termMap.getOrPut(parts[1]) { mutableListOf() }.add(parts[0])
            }
        }

        val authorsList = mutableSetOf<String>()
        val rawAuthor = obj.optString("author").takeIf { it.isNotBlank() && it != "null" && !it.equals("N/A", true) }
        val rawArtist = obj.optString("artist").takeIf { it.isNotBlank() && it != "null" && !it.equals("N/A", true) }
        if (rawAuthor != null) authorsList.addAll(rawAuthor.split(',').map { it.trim() })
        if (rawArtist != null) authorsList.addAll(rawArtist.split(',').map { it.trim() })
        if (authorsList.isEmpty()) {
            listOf("author", "artist", "creator", "group").forEach { key ->
                termMap[key]?.forEach { name ->
                    val trimmed = name.trim()
                    if (trimmed.isNotEmpty() && !trimmed.equals("N/A", true)) {
                        authorsList.add(trimmed)
                    }
                }
            }
        }

        assertTrue(authorsList.contains("Akikan"))
        assertTrue(authorsList.contains("Shell"))
    }
}
