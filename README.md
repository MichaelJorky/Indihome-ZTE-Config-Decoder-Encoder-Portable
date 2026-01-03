# 📦 Indihome / ZTE Config Decoder & Encoder (Portable)

Versi **portable & siap pakai** dari **Indihome / ZTE Config Decoder & Encoder Utility**.
Tidak perlu install Python atau modul tambahan **cukup extract dan jalankan**.

Project ini ditujukan untuk **pemula maupun advanced user** yang ingin:

* Decode file konfigurasi router ZTE (`config.bin` → `output.xml`)
* Encode kembali file XML menjadi BIN (payload type 0–6)
* Digunakan di **Windows**, serta bisa dijalankan di **Linux / Termux** (manual)

---

## ✨ Fitur Utama

* ✅ **Python Portable (Embeddable)**
* ✅ Tanpa install Python / pip
* ✅ Menu interaktif (CMD)
* ✅ Support payload **Type 0 – 6**
* ✅ Advanced mode (full argumen via `--help`)
* ✅ Output otomatis & aman
* ✅ Cocok untuk router ZTE Indihome / OEM

---

## 🧩 Struktur Folder

```
pyruntime_64/
│
├─ run_decoder.cmd      ← jalankan decoder
├─ run_encoder.cmd      ← jalankan encoder
│
├─ decoder.py
├─ encoder.py
├─ zcu/                 ← modul internal (jangan diubah)
│
├─ config/
│   ├─ config.bin       ← INPUT (file config router)
│   ├─ output.xml       ← OUTPUT decoder
│   └─ config_new.bin   ← OUTPUT encoder
│
├─ python.exe           ← runtime python portable
├─ cmd.exe              ← command prompt portable
└─ README.md
```

> ⚠️ Gunakan `pyruntime_32` untuk sistem 32-bit dan `pyruntime_64` untuk 64-bit.

---

## 🔓 Cara Pakai – Decoder

### 1️⃣ Siapkan File Config

* Backup config router (`config.bin`)
* Copy ke folder:

```
pyruntime_xx/config/config.bin
```

---

### 2️⃣ Jalankan Decoder

* Double-click **`run_decoder.cmd`**
* Pilih mode:

  * Auto (default)
  * Normal
  * Skip145
  * Trykeys
  * Check Login
  * **Advanced Mode**

---

### 3️⃣ Advanced Mode (Opsional)

Digunakan untuk router ZTE tertentu (misalnya F670L, F679L).

Contoh argumen yang sering digunakan:

```
--model F670L
--serial ZTE123456789
--mac 44:59:43:02:7D:68
--signature "ZXHN F670L"
```

Contoh kombinasi:

```
--serial ZTE123456789 --mac AA:BB:CC:11:22:33
```

Untuk melihat semua opsi lengkap:

```
python.exe decoder.py --help
```

---

## 🔐 Cara Pakai – Encoder

### 1️⃣ Pastikan `output.xml` tersedia

File ini otomatis dihasilkan dari proses decoder:

```
config/output.xml
```

---

### 2️⃣ Jalankan Encoder

* Double-click **`run_encoder.cmd`**
* Pilih payload type:

  * Type 0 – RAW
  * Type 1 – Compressed
  * Type 2 – AES ECB
  * Type 3 – AES CBC (KP Variant)
  * Type 4 – AES CBC (GPON Lama)
  * Type 5 – AES CBC (Manual)
  * Type 6 – AES CBC + Template

---

### 3️⃣ Advanced Encoder Mode

Pada **Advanced Mode**:

* `--xml` otomatis → `config/output.xml`
* `--out` otomatis → `config/config_new.bin`

Contoh argumen:

```
--payload-type 0
```

```
--payload-type 4 --serial ZTE123456789 --mac AA:BB:CC:11:22:33
```

```
--payload-type 6 --template config/config.bin --serial ZTE123456789 --mac AA:BB:CC:11:22:33
```

Melihat semua opsi encoder:

```
python.exe encoder.py --help
```

---

## 🌐 Platform Support

| Platform         | Status          |
| ---------------- | --------------- |
| Windows          | ✅ Full Support  |
| Linux / Kali     | ⚠️ Manual (CLI) |
| Android (Termux) | ⚠️ Manual (CLI) |

> Versi portable ini **dioptimalkan untuk Windows**.
> Linux / Termux dapat menjalankan script secara manual.

---

## 🔧 Versi Manual (Source & Developer)

Project ini juga tersedia dalam **versi manual / source code**, ditujukan untuk:
- Developer
- User advanced
- Pengguna yang ingin memodifikasi kode Python
- Penggunaan di Linux / Termux secara penuh

➡️ Versi manual dapat diakses di:
https://github.com/MichaelJorky/Indihome-Decoder-Encoder-Utility

Perbedaan utama:
- **Versi manual** → install Python & dependency secara manual
- **Versi portable (repo ini)** → siap pakai, tanpa install Python

---

## 🔗 Catatan Penting

* Versi ini **dipisahkan dari versi manual/source** untuk menjaga kerapihan kode.
* Repo ini fokus pada **kemudahan penggunaan (end-user)**.
* Untuk pengembangan & source asli, silakan lihat repo manual.

---

## ⚠️ Disclaimer

Project ini dibuat **untuk edukasi, riset, dan pemulihan konfigurasi perangkat milik sendiri**.
Penulis tidak bertanggung jawab atas penyalahgunaan.

---

## 🙌 Kredit

* Original Decoder & Encoder: **MichaelJorky**
* Portable & UX Wrapper: **TeknoXpert**

---

## ⭐ Penutup

Jika project ini membantu:

* ⭐ Star repo ini
* 🐞 Laporkan bug
* 💡 Kirim saran / improvement

---
