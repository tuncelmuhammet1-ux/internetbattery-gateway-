# 0.9 Deney Kayıtları — 2026-10-12
WSS dış HTTPS route üzerinden test.js exit 0.
Başarılı: kimliksiz reddi; nonce replay reddi; sahte cihaz ID reddi; eski imza reddi; localhost/IP reddi; kapalı TCP/22 reddi; DNS; WSS->TCP/443; WSS içinden gerçek TLS sertifikası; example.com HTTP 200 (931 yanıt baytı); UDP/53 DNS 61 yanıt baytı.
Standart curl komutu localhost SOCKS5 -> dış WSS -> example.com üzerinden HTTP 200 ve Example Domain metnini aldı.
Kota deneyi: 25.7MB dosya indirimi 5 MiB hesap sınırında kesildi (beklenen curl exit 56). İndirilen 5.209.871 bayt; sunucuda faturalandırılan 5.240.662 bayt; limit 5.242.880 bayt. Her iki trafik yönü sayıldı.
Bu, gerçek bağlantı aktarımı kanıtıdır; Android uygulama testi değildir. Geçici WSS alan adı kalıcı ürün değildir.