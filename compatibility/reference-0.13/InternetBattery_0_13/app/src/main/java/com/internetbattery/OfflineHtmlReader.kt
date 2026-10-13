package com.internetbattery

import org.jsoup.Jsoup

/**
 * Extracts readable text from the saved *response* without running scripts or reaching the network.
 * This is deliberately NOT an offline browser, form replay or full website archive.
 */
data class OfflineHtmlPreview(
    val title: String,
    val text: String,
    val hasJavaScript: Boolean,
    val hasExternalAssets: Boolean,
    val likelyDynamicShell: Boolean,
)

object OfflineHtmlReader {
    fun inspect(html: String): OfflineHtmlPreview {
        val doc = Jsoup.parse(html)
        val title = doc.title().trim().take(160)
        val hadScripts = doc.select("script").isNotEmpty()
        val hadExternalAssets = doc.select("link[href], img[src], script[src], iframe[src], source[src], video[src]").isNotEmpty()
        // Strip executable and non-reader parts *before* converting to plain text.
        doc.select("script, style, noscript, template, svg, iframe, canvas, head").remove()
        val body = doc.body()
        // A plain text snapshot works even for pages whose scripts/CSS cannot be replayed offline.
        body.select("br").forEach { it.appendText("\n") }
        body.select("p, h1, h2, h3, h4, h5, h6, li, section, article, div, header, footer").forEach { it.prependText("\n") }
        val raw = body.wholeText().replace('\u00a0', ' ')
        val normalized = raw.lines().map { it.trim() }.filter { it.isNotBlank() }
            .joinToString("\n").replace(Regex("\\n{3,}"), "\n\n").take(40_000)
        val text = normalized.ifBlank { body.text().trim().take(40_000) }
        return OfflineHtmlPreview(
            title = title,
            text = text,
            hasJavaScript = hadScripts,
            hasExternalAssets = hadExternalAssets,
            likelyDynamicShell = hadScripts && text.length < 80,
        )
    }
}
