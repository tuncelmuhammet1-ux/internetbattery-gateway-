# INTERNET BATTERY 0.13 — imzalı kullanım hakkının gerçek ağ aktarımında harcanması

Tarih: 13 Ekim 2026. **Araştırma prototipi; tamamlanmış internet aküsü değildir.**

## Teknik kazanımlar

- Android 0.13: WSS istemcisine IB1 imzalı kullanım belgesi gönderme, VPN başlamadan önce sunucudan kalan kota ve DNS doğrulaması alma (henüz fiziksel cihazda doğrulanmadı).
- Uzak Node.js WSS ağ geçidi: isteğe bağlı Ed25519 IB1 imzalı bilet kapısı, bileti cihaza ve belirli ağ geçidine bağlama.
- Başka kullanıcıya/başka ağ geçidine ait, süresi geçmiş, kota alanı değiştirilmiş veya imzası hatalı biletleri reddetme.
- Gerçek TCP aktarımından önce bayt tahsisini atomik ve doğrulanmış yerel harcama defterine yazma.
- Sunucu yeniden açıldığında kayıtlı tüketim devam eder; yerel harcama dosyası değiştirilirse servis fail-closed.
- Node sunucusundaki gerçek /balance çerçevesi; Android istemci olumlu kota kanıtını bekler.
- Kotlin CapacityLedger ve MutualReceiptBroker üzerinden iki tarafça imzalanmış deneysel katkı kaydından Ed25519 voucher çıkarma; aynı IB1 belgesinin Node ağ geçidinde doğrulanması ve gerçek HTTPS bağlantısında kullanılması.

## Doğrulanmış testler

Android SDK 35 + Gradle 8.9: `assembleDebug testDebugUnitTest` **başarılı**.
Android/JVM: **30/30** birim testi, 0 hata.
Node voucher doğrulayıcı: **17** başarılı kontrol.
Node gerçek WSS voucher entegrasyonu: **15** başarılı kontrol.
Kotlin/JVM broker -> IB1 voucher -> Node WSS -> gerçek TLS/HTTPS veri akışı: **5** başarılı kontrol.
Örnek çapraz dil testinde 31.000 deneysel hesap birimi kazanıldı; 20.000 baytlık hak ayrıldı; gerçek HTTPS/TLS akışı sırasında 8.293 bayt harcandı. Gerçek dış HTTPS yanıtı başarılıydı.
Kota sınırının aşılması, voucher ID çakışması, yeniden başlatma sonrası harcamanın korunması ve kayıt manipülasyonu test edildi.
Önceki WSS gerçek TCP/UDP DNS/HTTPS regresyon sonuçları ayrıca vardır.

**Sınavın anlamı:** Katılımcı bir ağın sunduğu gerçek bağlantı üzerinde imzalı kullanım hakkı harcanabilir. Ancak başlangıç kredisi test amaçlı sağlandı; trafik katkısı imzalı makbuzlardan hesaplandı, evde gerçek bağımsız kapasite ölçümü veya fiziksel Wi-Fi roaming testi yapılmadı.

## Sınırlamalar ve güvenlik

- Android 0.13 APK **gerçek Android telefonda uzaktan WSS/VPN trafiğiyle test edilmedi**. Android sistem görüntüsü kuruldu, emülatör hızlandırmasız başladı ancak ilk denemede sistem açılışını tamamlayamadı. Bu test raporunda AVD başarılı denmiyor.
- Node ağ geçidi hâlâ bir araştırma sunucusu; yaygın mobil internet erişimi veya operatör GB paketi üretmez.
- Varsayılan WSS prototipi sadece TCP 80/443 ve sınırlı UDP/53 içeriyor; QUIC/UDP443, oyunlar, görüntülü görüşmeler ve genel IPv6/UDP taşıma henüz tamam değil.
- Signed voucher tek bir gateway'e özeldir; çapraz ağ geçidi kullanım hakkı için ayrı broker mahsuplaşması ve katılımcı ağ güven ilişkisi gerekir.
- Node voucher defteri tek süreçte işlenen ve HMAC ile korunan bir yerel dosyadır. Güvenli operasyon için kalıcı bağımsız veritabanı, monotonic anchor, anahtar yönetimi, sunucu erişim kontrolü ve ödeme/işletim anlaşmaları gerekir.
- Ana sunucu anahtarı, özel Ed25519 anahtarı, gerçek biletler ve kota günlükleri **ZIP'te yoktur**. Gerçek banka/özel hesap trafiğini deneysel VPN'den geçirmeyin.
- Android IB1 şema: `IB1.` + base64url(`voucherId|holderId|targetGateway|quotaBytes|issuedAtMs|expiresAtMs|signatureBase64url`). İmza, ilk 6 alanın UTF‑8 metni üzerinde Ed25519'dur.
- Çok önemli: Bu model **canlı internet bağlantısını depolamak** yerine **önceden kazanılmış ve başka bir erişim noktasında harcanabilen hizmet hakkını** taşır. Telefonun o noktaya ulaşması için gerçek radyo/optik/kablolu bağlantı gerekir.

## Sonraki gerçek test

1. Android 0.13 kurulumu ve VPN kapalıyken sunucuda kimlik/IB1 kota doğrulaması.
2. Yetkili kalıcı katılımcı ağ geçidine WSS ile bağlanarak Android TUN üzerinden gerçek HTTPS aktarımı; paket sayaçları.
3. Wi-Fi ev katkısının fiziksel bağımsız ölçümü ve doğrulanması.
4. Ev dışındaki katılımcı Wi-Fi/mesh ağında, telefon mobil verisi kapalıyken tüm uygulamaların HTTPS+DNS+QUIC/UDP dahil çalışması.
5. Erişim hakkının transfer güvenliği, hız, pil, gecikme, gizlilik, hata toparlama ve üretim denetimleri.

**Sonuç:** 0.13 laboratuvarında kullanım hakkı ve gerçek ağ trafiğinin birleştirilmesi kanıtlandı. Tüketici için kullanılabilir, sıradan internetin depolandığı bir ürün henüz tamamlanmadı.
