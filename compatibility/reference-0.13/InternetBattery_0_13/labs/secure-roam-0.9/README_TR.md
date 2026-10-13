# INTERNET BATTERY 0.9 — Secure Roaming Lab
Araştırma prototipi, 12.10.2026. Bu kaynaklar Android VPN'in tamamlandığını kanıtlamaz.

## Amaç
Wi-Fi üzerinden sağlanan gerçek ağ kapasitesine katkı ölçülerek imzalı, başka bir katılımcı ağ geçidinde kullanılabilecek erişim hakkı üretmek. Bunun için taşınabilir kullanım hakkı, fiziksel Wi-Fi/mesh erişim ağı ve telefonun tüm IP trafiğini taşıyan VPN gerekir. Bu laboratuvar bu zincirdeki dış ağ geçidi veri aktarımını test eder; internet sinyali depolandığını iddia etmez.

## Test edilen prototip
gateway.js: kimlik doğrulamalı WSS ağ geçidi, per-device hesap, TCP/80/443, UDP/53.
local-socks.js: localhost SOCKS5 ile uzak WSS arasında gerçek TCP taşıma.
test.js: kimlik doğrulama, DNS, TCP, TLS, HTTPS, UDP testleri.

## Kurulum
Node 22+, internet erişimi, openssl.
npm ci
mkdir -p proofs
openssl rand -hex 32 > proofs/secret.txt
chmod 600 proofs/secret.txt
node gateway.js
Başka terminal: node test.js
Başka terminal: node local-socks.js
curl --socks5-hostname 127.0.0.1:1099 --proxy-user ib-pilot:ib-test-only-password-not-for-production https://example.com/

Uzak bağlantı için güvenli TLS/WSS reverse proxy ve IB_WSS / IB_TEST_WSS ortam değişkenleri gerekir.

## Güvenlik ve sınırlar
Cihaz ID + HMAC + zaman damgası + nonce, replay reddi. Master anahtar ve defter ZIP'e KONMADI. Test araçları yerel master anahtarını okur; üretim APK'sına bu anahtarı eklemek güvenli değildir. Gerçek istemciye yalnızca cihaza özgü türetilmiş token verilmeli. Özel IP/loopback hedefleri ve pilot dışı portlar bloklanır; kullanım hakkı sunucuda gerçek baytlar üzerinden eksilir. Varsayılan yerel SOCKS parolası yalnızca test içindir. JSON ledger üretim dayanıklılığına sahip değildir. UDP/53 ve TCP/80/443 sınırlaması bütün uygulamalara internet sağlamak anlamına gelmez. Android VPN, fiziksel kapsama, başka erişim noktasında kredi kullanma ve operatörsüz saha deneyleri henüz eksiktir.

Nihai hedef: Ev Wi-Fi kapsaması dışında, mobil veri kapalı, katılımcı bir Wi-Fi/mesh yolu üzerinden telefonun bütün uygulamalarına canlı internet, hak bakiyesinden doğrulanmış tüketim.