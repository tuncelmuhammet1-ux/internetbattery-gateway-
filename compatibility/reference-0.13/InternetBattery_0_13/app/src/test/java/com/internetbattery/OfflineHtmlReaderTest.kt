package com.internetbattery

import org.junit.Assert.*
import org.junit.Test

class OfflineHtmlReaderTest {
    @Test fun staticPageProducesReadableText() {
        val preview = OfflineHtmlReader.inspect("""
            <!doctype html><html><head><title>Deneme Sayfası</title></head>
            <body><h1>Merhaba dünya</h1><p>Çevrimdışı okunabilen içerik.</p></body></html>
        """.trimIndent())
        assertEquals("Deneme Sayfası", preview.title)
        assertTrue(preview.text.contains("Merhaba dünya"))
        assertTrue(preview.text.contains("Çevrimdışı okunabilen içerik."))
        assertFalse(preview.likelyDynamicShell)
        assertFalse(preview.hasJavaScript)
    }

    @Test fun scriptOnlyWebsiteIsRecognizedAsIncomplete() {
        val preview = OfflineHtmlReader.inspect("""
            <html><head><title>Hesap formu</title><script src="https://cdn.test/app.js"></script></head>
            <body><div id="root"></div><script>document.getElementById('root').textContent = 'Gizli gösterim';</script></body></html>
        """.trimIndent())
        assertTrue(preview.likelyDynamicShell)
        assertTrue(preview.hasExternalAssets)
        assertFalse(preview.text.contains("Gizli gösterim"))
    }

    @Test fun scriptsAreNeverShownAsSavedPageText() {
        val preview = OfflineHtmlReader.inspect("<html><body><p>Güvenli metin.</p><script>let token='12345';</script></body></html>")
        assertTrue(preview.text.contains("Güvenli metin."))
        assertFalse(preview.text.contains("12345"))
    }

    @Test fun externalImagesAreFlaggedAndTextPreserved() {
        val preview = OfflineHtmlReader.inspect("<html><body><h2>Başlık</h2><img src='https://example.com/image.png'><p>İçerik</p></body></html>")
        assertTrue(preview.hasExternalAssets)
        assertTrue(preview.text.contains("Başlık"))
        assertTrue(preview.text.contains("İçerik"))
    }

    @Test fun blankDocumentProducesNoFalseContent() {
        val preview = OfflineHtmlReader.inspect("<html><head><title>Boş</title></head><body> </body></html>")
        assertTrue(preview.text.isBlank())
        assertEquals("Boş", preview.title)
    }
}
