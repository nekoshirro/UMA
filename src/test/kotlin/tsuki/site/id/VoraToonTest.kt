package tsuki.site.id

import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import tsuki.util.NextJsData

class VoraToonTest {

    @Test
    fun testTicketRegexMatchesFullMultiSegmentToken() {
        val ticketRegex = Regex("""p1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+""")
        val sampleToken = "p1.zMihf5d016bhxZhL.xJ9x9O2-BU1kIT07cE3NE95saORugOPGDbZk8zCG.mjgCDsnkQsp141N9vuwRzw"

        val match = ticketRegex.find(sampleToken)
        assertNotNull(match, "Regex should match the token")
        assertEquals(sampleToken, match?.value, "Regex should capture the entire token without truncating at intermediate dots")
    }

    @Test
    fun testTicketRegexInHtmlPayload() {
        val ticketRegex = Regex("""p1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+""")
        val htmlPayload = """{"chapter":{"id":440695,"data":{"images":[]},"pagesTicket":"p1.abc-123_xyz.def-456_uvw.ghi-789_rst"}}"""

        val match = ticketRegex.find(htmlPayload)
        assertNotNull(match)
        assertEquals("p1.abc-123_xyz.def-456_uvw.ghi-789_rst", match?.value)
    }

    @Test
    fun testFlightPageResolvesPagesTicketWhenTextRowFollowsJsonRow() {
        // Text row 1a is located AFTER row 0 in the flight stream (exact Voratoon scenario)
        val html = """
            <!DOCTYPE html><html><head></head><body>
            <script>self.__next_f.push([1,"0:{\"chapter\":{\"id\":12345,\"pagesTicket\":\"$1a\",\"data\":{\"images\":[]}}}\n1a:T15,p1.sample.token.part3\n"])</script>
            </body></html>
        """.trimIndent()

        val page = NextJsData.findPage(html, "chapter")
        assertNotNull(page, "findPage should find the chapter object")

        val chapterObj = page!!.data.optJSONObject("chapter")
        assertNotNull(chapterObj)

        val resolvedTicket = page.text(chapterObj!!, "pagesTicket")
        assertEquals("p1.sample.token.part3", resolvedTicket)
    }

    @Test
    fun testFlightPageResolvesPagesTicketWhenTextRowPrecedesJsonRow() {
        // Text row 1a is located BEFORE row 0 in the flight stream
        val html = """
            <!DOCTYPE html><html><head></head><body>
            <script>self.__next_f.push([1,"1a:T15,p1.sample.token.part3\n0:{\"chapter\":{\"id\":12345,\"pagesTicket\":\"$1a\",\"data\":{\"images\":[]}}}\n"])</script>
            </body></html>
        """.trimIndent()

        val page = NextJsData.findPage(html, "chapter")
        assertNotNull(page)

        val chapterObj = page!!.data.optJSONObject("chapter")
        assertNotNull(chapterObj)

        val resolvedTicket = page.text(chapterObj!!, "pagesTicket")
        assertEquals("p1.sample.token.part3", resolvedTicket)
    }

    @Test
    fun testFlightPageDirectStringPagesTicket() {
        val html = """
            <!DOCTYPE html><html><head></head><body>
            <script>self.__next_f.push([1,"0:{\"chapter\":{\"id\":12345,\"pagesTicket\":\"p1.direct.token.here\",\"data\":{\"images\":[]}}}\n"])</script>
            </body></html>
        """.trimIndent()

        val page = NextJsData.findPage(html, "chapter")
        assertNotNull(page)

        val chapterObj = page!!.data.optJSONObject("chapter")
        assertNotNull(chapterObj)

        val resolvedTicket = page.text(chapterObj!!, "pagesTicket")
        assertEquals("p1.direct.token.here", resolvedTicket)
    }

    @Test
    fun testParseActionImagesFormats() {
        val jsonRowResponse = """
            0:{"a":"$@1","f":"","q":"","i":false}
            1:{"ok":true,"images":["https://cvr.voratoon.id/img1.webp","https://cvr.voratoon.id/img2.webp"],"chapterId":123}
        """.trimIndent()

        var imagesFound: List<String>? = null
        for (line in jsonRowResponse.lineSequence()) {
            val trimmed = line.trim()
            val colon = trimmed.indexOf(':')
            if (colon in 0..5) {
                val jsonStr = trimmed.substring(colon + 1)
                val json = runCatching { JSONObject(jsonStr) }.getOrNull() ?: continue
                val images = json.optJSONArray("images")
                if (images != null && images.length() > 0) {
                    imagesFound = (0 until images.length()).map { images.getString(it) }
                    break
                }
            }
        }

        assertNotNull(imagesFound)
        assertEquals(2, imagesFound?.size)
        assertEquals("https://cvr.voratoon.id/img1.webp", imagesFound?.get(0))
        assertEquals("https://cvr.voratoon.id/img2.webp", imagesFound?.get(1))
    }

    @Test
    fun testParseActionImagesRscFallback() {
        val rscBody = """
            0:{"a":"$@1"}
            1:{"images":["https://cdn.voratoon.com/page1.jpg","https://cdn.voratoon.com/page2.jpg"]}
        """.trimIndent()

        val payloads = NextJsData.extractRscPayloads(rscBody)
        val obj = NextJsData.findObjectInPayloads(payloads, "images")
        assertNotNull(obj)

        val images = obj?.optJSONArray("images")
        assertNotNull(images)
        assertEquals(2, images?.length())
        assertEquals("https://cdn.voratoon.com/page1.jpg", images?.optString(0))
        assertEquals("https://cdn.voratoon.com/page2.jpg", images?.optString(1))
    }
}
