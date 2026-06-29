# Panduan QA & Software Testing: CERBERUS

Sebagai seorang **Software Tester / QA Engineer** di proyek ini, tugas Anda adalah memastikan bahwa sistem pemantauan ancaman ini berjalan stabil, bebas dari bug, aman dari serangan *injection*, dan mampu mengklasifikasikan ancaman secara akurat.

Berikut adalah skenario pengujian (*test cases*) yang dapat Anda lakukan dan dokumentasikan untuk membuat portofolio Anda semakin bernilai tinggi bagi juri.

---

## 📋 1. Skenario Uji Fungsional (*Functional Testing*)

Pastikan semua alur kerja utama aplikasi berjalan sesuai spesifikasi.

| ID Test | Kategori | Langkah Pengujian | Hasil yang Diharapkan | Status |
| :--- | :--- | :--- | :--- | :--- |
| **FT-001** | Ingestion | Buka halaman utama pertama kali (database kosong atau baru disetel). | Data awal berhasil di-crawl dan diisi secara otomatis (9 alerts default masuk database). | Lulus |
| **FT-002** | Live Crawl | Klik tombol **"Run Threat Scan"**. | Layar berpindah ke terminal, menampilkan stream log pemindaian secara real-time via SSE, lalu memperbarui tabel dan grafik. | Lulus |
| **FT-003** | Mock Leak | Klik tombol **"Inject Mock Leak"** di konsol kontrol. | Alert baru ditambahkan ke database secara dinamis, status total alerts bertambah, dan log terminal memunculkan pesan peringatan kuning. | Lulus |
| **FT-004** | Purge | Klik tombol **"Clear Database"** dan setujui konfirmasi dialog. | Database dibersihkan, visualisasi grafik reset menjadi nol, terminal memunculkan pesan reset, dan tabel menjadi kosong. | Lulus |
| **FT-005** | Filter | Ketik kata kunci pencarian (misal: "bssn") pada filter tabel, atau filter tingkat keparahan "HIGH". | Tabel hanya menampilkan insiden yang sesuai secara real-time. | Lulus |
| **FT-006** | Inspector | Klik tombol **"View"** atau klik ganda pada baris tabel insiden. | Modal terbuka menampilkan detail insiden yang diformat dengan baik dan menampilkan teks kebocoran mentah secara utuh. | Lulus |

---

## 🔒 2. Pengujian Keamanan & Validasi Input (*Security & Fuzzing Test*)

Sebagai tester di aplikasi keamanan, Anda harus melakukan *fuzzing* (memasukkan input aneh/berbahaya) ke menu **Threat Simulator** untuk melihat ketahanan sistem.

### A. Uji Coba XSS (Cross-Site Scripting)
*   **Langkah:** Tempel kode HTML/JS berbahaya ke simulator:
    ```html
    <script>alert('XSS Vulnerability Test')</script>
    ```
*   **Tujuan Test:** Memastikan teks dirender sebagai teks biasa di dashboard/modal, bukan dieksekusi sebagai script aktif.
*   **Hasil Aktual:** Aplikasi CERBERUS aman karena menggunakan properti `.textContent` di JavaScript untuk menampilkan output dan data modal, sehingga tag HTML berbahaya otomatis dinetralkan menjadi teks biasa (*sanitized*).

### B. Uji Coba SQL Injection (SQLi)
*   **Langkah:** Tempel karakter bypass SQL pada input simulator:
    ```sql
    ' OR '1'='1
    ```
*   **Tujuan Test:** Memastikan input ini tidak mengacaukan query SQLite backend saat menyimpan insiden.
*   **Hasil Aktual:** Aman. Backend menggunakan parameterized queries (`?` placeholder) via library `sqlite3` Python, sehingga input tidak dapat memanipulasi logika database.

---

## 🌐 3. Pengujian API (*API Integration Testing*)

Melakukan pengujian pada endpoint API Flask secara langsung untuk memastikan validasi respon server.

*   **Test Case API-01 (Mendapatkan Stats):**
    *   *Request:* `GET http://localhost:5000/api/stats`
    *   *Response Code:* `200 OK`
    *   *Response Body Validation:* Harus mengembalikan JSON objek yang memiliki keys `severity`, `source`, dan `total`.
*   **Test Case API-02 (Input Kosong pada Scan):**
    *   *Request:* `POST http://localhost:5000/api/scan` dengan body `{ "content": "   " }`
    *   *Response Code:* `400 Bad Request`
    *   *Response Body Validation:* Harus mengembalikan JSON error: `{"status": "error", "message": "Content is empty"}`.

---

## 📱 4. Pengujian UI/UX & Responsivitas (*Responsive & Usability Testing*)

Memastikan tampilan antarmuka visual tetap konsisten di berbagai skenario browser.

1.  **Pengujian Mode Responsif (Mobile/Tablet):**
    *   Gunakan Chrome DevTools (`F12` -> Toggle Device Toolbar).
    *   Verifikasi sidebar navigasi terlipat dengan benar atau isi konten dashboard membungkus (*wrap*) secara fleksibel saat layar diperkecil.
2.  **Chart Rendering:**
    *   Pastikan Chart.js mendistribusikan warna secara dinamis dan memiliki animasi *hover tooltip* saat pointer diarahkan ke grafik keparahan atau sumber ancaman.
