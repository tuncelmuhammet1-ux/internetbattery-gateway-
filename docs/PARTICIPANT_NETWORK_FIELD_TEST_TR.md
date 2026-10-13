# Internet Battery: Katılımcı ağ saha kabul testi (TR)

## Gereken gerçek altyapı

Birinci konum (ev): Ölçülebilir gerçek Wi-Fi/İnternet bağlantısı, sağlayıcının açık katılım rızası ve deneme kayıtları.
İkinci konum (ev dışında): İnternete bağlı, sahibi tarafından yetkilendirilmiş katılımcı Wi-Fi/mesh erişim noktası. Telefonun bu ağın Wi-Fi bağlantısını kullanabilmesi gerekir.
Render gateway: WSS `/tunnel`, aynı holder ID + ayrı cihaz anahtarı, postgres research-credit ledger. Bu WSS bağlantısı **katılımcı fiziksel ağın yerini tutmaz**.

## Kontrollü deney akışı

1. Android 0.13 APK kurulumu, VPN izni, boş IB1 alanıyla WSS/DNS ön denemesi ve internetin **gerçek Wi-Fi üzerinden** çalışması.
2. Yetkili laboratuvar cüzdanında 1, 5 veya 10 GB **simüle hak** paketi; Ed25519 IB1 belgesi; `wallet/balance` ve Postgres satırlarının eşleşmesi.
3. Android uygulamasına IB1 kopyalama. WSS ön testinde voucher ID ve remaining bytes pozitif olmalı; yanlış imza, yanlış holder veya bitmiş belge reddedilmeli.
4. Android VPN aktifken `https://example.com/` üzerinden **VPN Network** ile başarılı TLS/HTTPS ölçümü. Android ve gateway çift yönlü sayaçlarındaki artışı karşılaştırma; kötü VPN başarısızlığında otomatik güvenli kapanma.
5. Render yeniden başlatıldıktan sonra POST `/v1/wallet/balance` ve yeni WSS `balance` sorgularında önceki harcamanın korunması. Eşzamanlı oturumlarda kota aşımı/negatif bakiye olmamalı.
6. Ev Wi-Fi menzili dışında mobil veriyi KAPAT, yalnızca izinli katılımcı Wi-Fi'ye bağlan, aynı VPN/TLS testi tekrarla. Katılımcı ağ olmadan trafik olmaması normaldir.
7. Video/QUIC/görüntülü görüşme/oyunlar test kapsamı DIŞINDA (bu deneyin UDP desteği sadece DNS port 53'tür). IPv6 genel trafik desteği de henüz yok.

## Kabul kriterleri ve dürüst sonuç

- Ölçüm günlüklerinde gerçek cihaz, ağ arabirimi, IP düzeyi, hedef, zaman, çift yönlü aktarılan bayt ve harcama kayıtları bulunmalı; özel anahtar veya voucher gibi sırlar loglanmamalı.
- HTTPS yanıtı gerçek VPN ağından gelmeli; sadece DNS veya WebSocket 101 bağlantısı "VPN çalıştı" kanıtı değildir.
- Katılımcı Wi-Fi ve veri kaynağına ilişkin haklar anlaşma/izin ile doğrulanmalıdır.
- Evde Wi-Fi ile büyük bir veri indirip bağlantı olmayan dış ortamda **canlı interaktif interneti fiziksel olarak depolamış olmazsınız**. Bu araştırmanın denenebilir konusu tüketim hakkının başka erişim noktasında kullanımıdır.

## Şu an gerçekleştirilemeyenler

Bu sohbete bağlı Desktop Commander cihazı çevrimdışı. Android telefonun sistem ekranına, WSS ayarına, mobil veri anahtarına veya ikinci konumdaki Wi-Fi altyapısına uzaktan erişim yok. Dolayısıyla fiziksel saha testi ve partner erişim noktası kurulmuş olarak raporlanamaz.
