# Diptera

Halaman web statis (tanpa backend) untuk mengirim **banyak form sekaligus** ke workflow n8n
**Charlie Reporter**, memantau setiap eksekusi, lalu membaca hasil tiap form (case name, severity,
markdown) langsung di kartunya — seperti halaman akhir form n8n, tapi untuk banyak form sekaligus.

Cocok dipakai saat workflow-nya lambat (AI lokal): isi 10 alert dulu, klik **Kirim Semua**, lalu
tinggalkan halaman. Setiap kartu memberi tahu sendiri kapan selesai.

### Konfigurasi Environment (`.env`)

Semua data yang bisa dianggap sensitif (alamat n8n, path form, dan **daftar tenant**) dibaca dari
environment — tidak ditanam di kode. `server.js` memuat file `.env` secara otomatis saat `npm start`.

1. Salin `.env.example` menjadi `.env`:
   ```bash
   cp .env.example .env
   ```
2. Sesuaikan isinya:
   - `N8N_BASE_URL` — alamat n8n Anda.
   - `DIPTERA_FORM_PATH` — path node form n8n.
   - `TENANT_OPTIONS` — **daftar tenant** (JSON array). Wajib diisi; dropdown tenant kosong tanpa ini.
   - `INITIAL_CASE_ID`, `INITIAL_TICKETS` — opsional untuk penomoran awal.

> File `.env` sudah dimasukkan ke `.gitignore`, jadi isinya tidak ikut ter-commit ke GitHub.
> Sebelum push, pastikan **tidak ada** data internal (nama tenant, IP, path) yang masih tertulis di kode.

> Untuk Docker, nilai yang sama dilewatkan lewat variabel environment container
> (lihat `docker-compose.yml`), bukan lewat file `.env` di dalam image.

## Menjalankan

```bash
cd diptera
npm install               # memasang dependencies (jsdom untuk test)
npm start                 # server.js, listen 0.0.0.0:8787
```

Buka <http://localhost:8787>. Saat start, server mencetak alamat **Jaringan**, mis.:

```
  Lokal     : http://localhost:8787
  Jaringan  : http://192.168.1.10:8787
```

Buka alamat **Jaringan** itu dari PC/HP lain di Wi-Fi/LAN yang sama.

> Jangan buka `index.html` lewat `file://` — clipboard, notifikasi desktop, dan penyimpanan
> lebih andal saat halaman disajikan lewat http.

### Diakses lewat IP tapi halaman tidak muncul?

Urutan pemeriksaan:

1. **Pastikan server hidup dari PC lain**: buka `http://<IP-PC>:8787/healthz`. Kalau muncul `ok`,
   server & jaringan sudah benar; kalau tidak, lanjut ke poin berikut.
2. **Jangan pakai `localhost` dari PC/HP lain.** `localhost` selalu menunjuk ke perangkat yang
   sedang dipakai. Gunakan IP PC tempat `npm start` dijalankan.
3. **Izinkan port 8787 di firewall PC server**:
   - Windows: Windows Defender Firewall → Advanced settings → Inbound Rules → New Rule → Port →
     TCP `8787` → Allow. Saat pertama `npm start`, biasanya muncul pop-up; pilih **Allow** untuk
     Private networks.
   - Linux (ufw): `sudo ufw allow 8787/tcp`.
4. **Satu jaringan.** HP/PC lain harus di Wi-Fi/LAN yang sama; jaringan tamu atau VPN kantor
   kadang memblokir antar-perangkat.
5. **Server jangan di-bind ke localhost.** Default `server.js` memakai `HOST=0.0.0.0`. Kalau
   sengaja memakai `HOST=127.0.0.1`, hanya PC itu yang bisa mengakses.
6. **Jangan cuma menyalin `index.html`.** Halaman butuh `styles.css`, `app.js`, `extract.js`,
   `numbering.js`, dan `config.js` di folder yang sama. Paling aman pakai container (lihat bawah).

Kalau halaman terbuka tetapi pengiriman ke n8n gagal saat diakses lewat IP, **Base URL n8n juga
tidak boleh `localhost`**. Buka **Pengaturan → Pakai IP halaman ini**, lalu **Simpan pengaturan**.
Aplikasi otomatis menebak `http://<IP-halaman>:5678` untuk pengaturan baru.

Jika n8n berjalan di PC yang sama, port n8n juga harus diizinkan di firewall — misalnya:

```bash
sudo ufw allow 8787/tcp   # halaman IRIS
sudo ufw allow 5678/tcp   # n8n (sesuaikan kalau port-nya lain)
```

Cek dari HP/PC lain: `http://<IP-PC>:8787/healthz` harus menampilkan `ok`, dan
`http://<IP-PC>:5678` harus bisa dibuka.

### Container (pindah ke PC lain)

Container hanya menyajikan file statis; n8n tetap dipanggil langsung oleh browser. Cocok untuk
menyalin aplikasi ke PC lain tanpa memasang Node/npm.

```bash
# Di PC ini: build image
docker compose up -d --build          # atau: docker build -t diptera:latest .

# Buka http://localhost:8787 atau http://<IP-PC>:8787
```

Ganti port host kalau 8787 sudah dipakai:

```bash
APP_PORT=9080 docker compose up -d --build
```

Menyiapkan Base URL n8n default untuk browser yang belum punya pengaturan (opsional):

```bash
N8N_BASE_URL=http://192.168.1.10:5678 docker compose up -d --build
```

**Pindah ke PC lain tanpa internet** (image di-save lalu di-load):

```bash
# Di PC asal
docker save diptera:latest -o diptera.tar

# Salin diptera.tar ke PC tujuan, lalu:
docker load -i diptera.tar
docker run -d --name diptera --restart unless-stopped -p 8787:8787 diptera:latest
```

Atau salin seluruh folder proyek (tanpa `node_modules`) ke PC tujuan yang punya Docker, lalu
`docker compose up -d --build` di sana. Pastikan port 8787 diizinkan firewall seperti di atas.


## Cara pakai

1. Sudah tersedia **Form #1**. Klik **Tambah Form** kalau perlu banyak; klik **Duplikat** untuk
   menyalin isi form yang mirip (nomornya otomatis dimajukan).
2. Isi **IRIS Case ID** (wajib) dan **Raw Alert JSON** (wajib). Field lain opsional. Nomor tiket &
   case ID terisi otomatis — lihat [Penomoran otomatis](#penomoran-otomatis).
   **Raw Alert JSON tidak harus JSON yang sempurna**: n8n menerima teks apa adanya, jadi aplikasi
   juga tidak memblokir. Satu objek/array JSON, NDJSON (beberapa alert satu per baris), beberapa
   objek yang ditempel berdempetan, atau log dengan baris baru di dalam teks semuanya diterima.
   Kalau teks benar-benar tidak terbaca sebagai JSON, muncul peringatan kuning — tetapi form tetap
   bisa dikirim.
3. Klik **Kirim Semua** (atau <kbd>Ctrl</kbd>/<kbd>⌘</kbd> + <kbd>Enter</kbd>).
   Kartu otomatis tertutup dan statusnya berjalan.
4. **Notifikasi per kartu**: saat satu workflow selesai, kartu yang masih tertutup menampilkan
   chip **Selesai**, ringkasan `[SEVERITY] Case Name`, durasi, dan toast “Form #n selesai · HIGH”.
   (Notifikasi desktop bisa diaktifkan di pengaturan.)
5. Klik kepala kartu untuk membukanya. Kalau sudah **Selesai**, yang tampil hanya panel **hasil**
   (case name, severity, tombol **Salin Markdown** / **Salin Case Name**, tautan ke eksekusi n8n) —
   isian form disembunyikan supaya daftar banyak case tetap ringkas.
6. **Hapus dari header**: tombol tempat sampah di sebelah chip status langsung menghapus case tanpa
   perlu membuka dropdown. Kalau case sedang diproses, prosesnya ikut dibatalkan.
7. Kalau gagal, kartu berwarna merah dengan pesan + detail dari n8n, plus tombol **Coba Lagi**
   dan **Periksa Hasil Lagi** (melanjutkan memantau kalau workflow-nya sebenarnya masih jalan).
   Isian tetap tampil saat gagal supaya bisa diperbaiki lalu dikirim ulang.

Statistik di kanan atas (`selesai / diproses / menunggu / gagal`) dan judul tab `(n)` membantu
memantau dari jauh.

## Penomoran otomatis

Supaya tidak perlu mengetik nomor satu per satu, aplikasi mengingat nomor terakhir dan
mengisi form berikutnya:

- **Nomor Tiket IRIS — satu urutan per tenant.** Isi form pertama, mis. tenant `tenant-a` dengan tiket
  `10010`; begitu form berikutnya memilih tenant `tenant-a`, tiketnya terisi `10011`. Tenant `tenant-b`
  punya urutannya sendiri: `20021` → berikutnya `20022`, dst. Tenant baru dimulai dari angka yang
  kamu ketik sendiri (aplikasi tidak menebak awalan tiap tenant).
- **IRIS Case ID — satu urutan global.** Form #1 diisi `#1001`, form #2 otomatis `#1002`, dst.
- **Selalu bisa diedit.** Begitu kamu mengetik nilai sendiri di field itu, nilainya tidak akan
  ditimpa lagi dan menjadi acuan nomor berikutnya. Field yang sedang terisi otomatis diberi
  penanda biru + catatan “otomatis: lanjutan tenant … — bisa diubah”.
- **Duplikat** menaikkan tiket (per tenant) dan case ID satu langkah supaya tidak dobel.
- Acuan nomor disimpan di `localStorage`, jadi lanjut terus walau halaman ditutup. Panel pengaturan
  menampilkan **nomor berikutnya** per tenant + case ID, dan tombol **Lupakan acuan nomor** kalau
  kamu ingin memulai urutan dari nol (nilai yang sudah terisi di form tidak dihapus).
- Bisa dimatikan lewat **Pengaturan → Isi nomor otomatis**.

Angka yang dimajukan adalah **angka terakhir** di dalam nilai, jadi awalan/akhiran ikut terjaga:
`#1001` → `#1002`, `ASOC-2026-30073` → `ASOC-2026-30074`, `007` → `008`.

## Pengaturan (ikon gerigi)

| Pengaturan | Default | Keterangan |
| --- | --- | --- |
| n8n Base URL | otomatis | `http://localhost:5678` saat halaman dibuka dari localhost; `http://<IP-halaman>:5678` saat dibuka lewat IP. Bisa juga lewat reverse proxy (mis. nginx `:8080`). Tombol **Pakai IP halaman ini** mengisi host halaman saat ini. |
| Form path | dari env (`DIPTERA_FORM_PATH`) | Diambil dari node **Alert Intake Form** di workflow. |
| Mode pengiriman | Berurutan | **Berurutan** = form berikutnya dikirim setelah yang sebelumnya selesai (aman untuk AI lokal). **Paralel** = semua sekaligus. |
| Batas tunggu hasil | 30 menit | Lewat batas ini kartu ditandai gagal (masih bisa “Periksa Hasil Lagi”). |
| Isi nomor otomatis | aktif | Tiket per tenant + IRIS Case ID berurutan (lihat [Penomoran otomatis](#penomoran-otomatis)). |
| Tutup kartu otomatis saat dikirim | aktif | Membuat kartu ringkas; hasil tetap bisa dibuka kapan saja. |
| Tandai selesai di n8n setelah hasil diambil | aktif | Mengirim POST ke `form-waiting` supaya eksekusi tidak menggantung di status *waiting*. |
| Sesuaikan host URL hasil dengan Base URL | aktif | Perlu kalau n8n membalas `localhost:5678` padahal diakses dari host/port lain. |
| Notifikasi desktop saat form selesai | nonaktif | Muncul hanya saat tab tidak aktif. |
| Penomoran berikutnya | — | Ringkasan nomor berikutnya per tenant + case ID, dan tombol **Lupakan acuan nomor**. |
| Definisi field form (JSON) | 4 field di bawah | Daftar field yang ditampilkan **dan** urutan pengirimannya. |

### Definisi field (penting)

n8n menerima data form dengan kunci **posisional**: `field-0`, `field-1`, … sesuai urutan field di
node **Form Trigger**. Karena itu daftar field di pengaturan mengikuti urutan tersebut:

| Kunci | Label di aplikasi | Field di workflow |
| --- | --- | --- |
| `field-0` | Nomor Tiket IRIS (opsional) | `reportNumber` |
| `field-1` | Tenant / Organisasi (opsional) | `Tenant` |
| `field-2` | IRIS Case ID (wajib) | `irisId` |
| `field-3` | Raw Alert JSON (wajib) | `Raw Alert JSON` |

Kalau form di n8n diubah (field ditambah/diurutkan ulang), sesuaikan JSON ini. Contoh:

```json
[
  { "key": "field-0", "label": "Nomor Tiket IRIS (Opsional)", "type": "text", "role": "ticket" },
  { "key": "field-1", "label": "Tenant", "type": "select", "options": ["tenant-a", "tenant-b"], "role": "tenant" },
  { "key": "field-2", "label": "IRIS Case ID", "type": "text", "required": true, "role": "caseId" },
  { "key": "field-3", "label": "Raw Alert JSON", "type": "textarea", "required": true, "json": true, "role": "alert" }
]
```

`role` hanya untuk ringkasan di kepala kartu (`caseId`, `tenant`, `ticket`); `json: true` menyalakan
pemeriksaan JSON yang bersifat petunjuk (bukan syarat kirim).

## Bagaimana aplikasi bicara dengan n8n

Protokolnya sudah diuji langsung ke n8n 2.40.7:

```
POST {base}/form/{path}                       (multipart/form-data: field-0 … field-N)
  → 200 { "formWaitingUrl": "{base}/form-waiting/<id>?signature=…" }
GET  {formWaitingUrl}/n8n-execution-status    → running | form-waiting | success | error | …
GET  {formWaitingUrl}                         → halaman hasil (HTML berisi responseHtml workflow)
POST {formWaitingUrl}                         → menandai eksekusi selesai di n8n (autoResume)
```

Catatan:

- **Workflow harus aktif/published**, kalau tidak `POST /form/<path>` membalas 404.
- Tanpa node **Form** (Form Ending) di hilir workflow, POST membalas `{"status":200}`; kartu tetap
  ditandai **Selesai** dengan catatan “tidak ada halaman hasil”.
- Status `running` **tidak** di-GET halaman hasilnya (permintaan akan menggantung di n8n); aplikasi
  menunggu `form-waiting`/`success` dulu.
- CORS: rute form n8n membalas `Access-Control-Allow-Origin` sesuai origin pemanggil, jadi halaman
  ini bisa memanggil n8n langsung dari browser tanpa proxy.
- Aplikasi hanya memakai endpoint form. Workflow-nya tidak perlu diubah.

## Log panjang & performa

- Textarea **Raw Alert JSON** tidak membungkus baris (`wrap="off"`). Log JSON panjang biasanya
  satu baris raksasa; tanpa word-wrap browser tidak perlu menghitung ulang layout seluruh teks di
  setiap ketikan.
- Saat kartu ditutup, isi textarea dilepas dari DOM (nilainya tetap aman di state dan diisi lagi
  saat kartu dibuka, kecuali kartu sudah selesai). Ini menjaga halaman tetap ringan walau ada
  banyak log besar.
- Begitu case **selesai**, isian form disembunyikan dan textarea log dilepas dari DOM; kartu hanya
  menampilkan hasil. Nilainya tetap tersimpan di state, jadi **Duplikat** masih membawa isi lengkap.
  Ini membuat puluhan case selesai tidak membebani halaman.
- Tombol hapus ada di header kartu (sebelah status), jadi case bisa dibersihkan tanpa membuka
  dropdown. Menghapus case yang sedang berjalan juga membatalkan request-nya.
- Tambah/duplikat/hapus/tutup-semua kartu tidak lagi membangun ulang seluruh daftar; hanya kartu
  yang berubah yang disentuh.
- Penyimpanan ke `localStorage` ditunda saat masih mengetik, lalu disimpan setelah blur / berhenti
  sejenak, dan langsung di-flush saat tab disembunyikan/ditutup. Status polling yang tidak berubah
  tidak ditulis ulang. Kalau penyimpanan penuh, hasil dibuang lebih dulu dan aplikasi berhenti
  mencoba ulang terus-menerus (ada peringatan sekali).
- Pemeriksaan JSON saat mengetik memakai debounce; pemeriksaan hanya untuk memberi info, bukan
  syarat pengiriman.

## Data yang disimpan

Semua keadaan (nilai form, status, hasil, `waitingUrl`, **acuan nomor otomatis**) disimpan di
`localStorage` dengan kunci `iris-multi-form.v1`. Kalau halaman di-reload saat masih memproses,
pemantauan **dilanjutkan otomatis**. Kartu yang belum sempat dikirim (halaman ditutup saat mengirim) ditandai “Terputus”
dan bisa dikirim ulang dengan **Coba Lagi**. Tombol **Hapus semua form** membersihkan semuanya.

> `localStorage` terpisah per alamat. Pengaturan yang disimpan di `http://localhost:8787` tidak
> otomatis terbawa ke `http://192.168.1.10:8787`. Itulah sebabnya Base URL default menyesuaikan
> host halaman, dan ada tombol **Pakai IP halaman ini** di Pengaturan.

## Tes

```bash
npm install     # sekali: memasang jsdom untuk uji e2e
npm test        # unit + server + e2e
npm run test:unit   # parser halaman hasil + uji server (tanpa jsdom)
npm run test:e2e    # aplikasi sungguhan di jsdom + server n8n tiruan
```

- `test/numbering.test.js` — 7 uji penomoran (`numbering.js`): prefiks `#`, lebar nol (`007` → `008`),
  angka terakhir pada `ASOC-2026-30073`, nilai tanpa angka, dsb.
- `test/server.test.js` — 7 uji `server.js`: halaman & aset dilayani, `/healthz`, `config.js`,
  `N8N_BASE_URL`, whitelist file/path traversal, method GET/HEAD, dan filter interface virtual
  (docker/bridge tidak dicetak sebagai alamat LAN).
- `test/extract.test.js` — 12 uji parser, memakai halaman hasil **nyata** yang direkam dari n8n
  2.40.7 (`test/fixtures/`): format normal, format ter-escape, halaman error, sanitasi HTML.
- `test/e2e.test.js` — menjalankan `index.html` + `app.js` asli di jsdom dengan **mock n8n** yang
  meniru protokol di atas, mencakup: tambah/hapus form, hapus langsung dari header (termasuk saat
  case masih antre), isian form yang disembunyikan setelah selesai, JSON panjang/NDJSON/teks bebas
  yang tetap terkirim utuh, peringatan JSON tanpa memblokir, kirim berurutan (form ke-2
  baru mulai setelah form ke-1 selesai), kirim paralel, hasil per kartu, notifikasi kartu tertutup,
  penulisan ulang host URL hasil, autoResume, gagal HTTP + “Coba Lagi”, respons `{"status":200}`,
  halaman error n8n, penomoran otomatis (tiket per tenant, case ID berurutan, isian manual tidak
  ditimpa, nomor ikut terkirim ke n8n), dan melanjutkan polling setelah halaman di-reload.
  Kalau ada container n8n uji di `127.0.0.1:5679`, satu skenario tambahan dijalankan terhadap n8n
  **asli** (matikan dengan `IRIS_E2E_SKIP_REAL=1`, ganti alamat dengan `IRIS_E2E_REAL_BASE=…`).

## Berkas

| Berkas | Isi |
| --- | --- |
| `index.html` | Struktur halaman (tanpa framework). |
| `styles.css` | Tema gelap, kartu, chip status, panel hasil. |
| `tenants.css` | Gaya daftar tenant di panel pengaturan (tabel `Tenant`/`Nomor`). |
| `app.js` | Keadaan & penyimpanan, render kartu, kirim/poll/resume, toast, pengaturan, penomoran otomatis. |
| `extract.js` | Parser halaman hasil n8n (`IrisExtract`) — murni string, dipakai juga oleh unit test. |
| `numbering.js` | Helper nomor berikutnya (`IrisNumbering`): `#1001` → `#1002`, `ASOC-2026-30073` → `ASOC-2026-30074`. |
| `server.js` | Server statis tanpa dependensi; listen `0.0.0.0`, whitelist file, `/healthz`, cetak alamat LAN. |
| `config.js` | Konfigurasi default (`window.DIPTERA_CONFIG`); diisi dari environment saat `npm start`. |
| `Dockerfile`, `docker-compose.yml`, `.dockerignore` | Paket container untuk dipindah ke PC lain. |
| `test/` | Uji unit, server, dan e2e beserta fixtures halaman hasil nyata. |
