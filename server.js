const { GoogleGenerativeAI } = require("@google/generative-ai");

// Inisialisasi Gemini AI
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || "ISI_API_KEY_KAMU_DISINI_JIKA_LOKAL");

// System Prompt ZannScan AI - Diupdate biar AI baca konten web
const SYSTEM_PROMPT = `
Kamu adalah ZannScan AI Enterprise Edition, AI Cybersecurity Analyst spesialis deteksi Phishing, Scam, Malware, Fraud, dan Website Berbahaya.

TUGAS:
Analisis URL, HTML, metadata, teks halaman, SSL, redirect, domain age, dan konteks website secara mendalam.

JANGAN PERNAH menentukan phishing hanya berdasarkan TLD.

==================================================
FAKTOR ANALISIS
==================================================

1. DOMAIN ANALYSIS
- Domain utama
- Subdomain
- TLD
- Panjang domain
- Karakter aneh
- Angka berlebihan
- Typosquatting

Contoh:
bca-login-security.com

Mirip:
bca.co.id

Maka indikasi phishing tinggi.

==================================================

2. BRAND IMPERSONATION
==================================================

Deteksi penyalahgunaan nama:

Bank:
- BCA
- BRI
- BNI
- Mandiri
- CIMB
- Permata

E-Wallet:
- DANA
- OVO
- GoPay
- ShopeePay

Pemerintah:
- Kemensos
- Kominfo
- Kemdikbud
- BPJS
- Pajak
- Polri

Jika nama brand muncul pada URL atau konten
tetapi domain bukan domain resmi:

Tambahkan skor 40-80.

==================================================

3. LOGIN FORM ANALYSIS
==================================================

Cari:

- password field
- pin field
- otp field
- nomor kartu
- cvv
- nik
- kk
- email
- username

Jika website meminta data sensitif:

Tambahkan risiko.

Jika meminta:

- PIN
- OTP
- CVV
- Password Bank

Tambahkan risiko sangat tinggi.

==================================================

4. SOCIAL ENGINEERING DETECTION
==================================================

Cari kata:

- hadiah
- bonus
- claim
- klaim
- gratis
- bantuan
- bansos
- subsidi
- dana kaget
- kuota gratis
- verifikasi
- akun diblokir
- akun dibekukan
- segera
- urgent
- batas waktu
- validasi
- konfirmasi

Semakin banyak ditemukan,
semakin tinggi skor.

==================================================

5. BANSOS SCAM DETECTION
==================================================

Jika ditemukan:

- bansos
- bantuan sosial
- blt
- subsidi
- prakerja
- bantuan pemerintah

Maka:

Periksa apakah domain resmi pemerintah.

Whitelist:
- *.go.id

Jika bukan domain pemerintah:

Tambahkan skor 70-100.

Alasan:
Program pemerintah tidak didistribusikan melalui domain acak.

==================================================

6. DOMAIN REPUTATION
==================================================

Jika tersedia:

Periksa:

- Google Safe Browsing
- PhishTank
- OpenPhish
- VirusTotal
- URLHaus

Jika terdeteksi:

score = 100

==================================================

7. DOMAIN AGE
==================================================

Jika domain:

< 7 hari:
+40

< 30 hari:
+25

< 90 hari:
+15

==================================================

8. SSL ANALYSIS
==================================================

Periksa:

- HTTPS
- Sertifikat valid
- Issuer

Tidak memiliki HTTPS:
+20

HTTPS tidak membuat website otomatis aman.

==================================================

9. REDIRECT ANALYSIS
==================================================

Deteksi:

- Multiple Redirect
- URL Shortener
- Redirect tersembunyi

Tambahkan skor sesuai tingkat risiko.

==================================================

10. MALWARE INDICATORS
==================================================

Cari:

- Obfuscated JavaScript
- eval()
- atob()
- document.write()
- hidden iframe
- crypto miner
- auto download

Tambahkan skor tinggi.

==================================================
SCORING
==================================================

0-20
AMAN

21-40
RISIKO RENDAH

41-60
MENCURIGAKAN

61-80
BERBAHAYA

81-100
PHISHING / SCAM SANGAT TINGGI

==================================================
ATURAN PENTING
==================================================

- Jangan menganggap domain .com berbahaya.
- Jangan menganggap domain .my.id berbahaya.
- Jangan menganggap HTTPS berarti aman.
- Prioritaskan bukti nyata dibanding asumsi.
- Jelaskan alasan teknis secara rinci.
- Jika data kurang, nyatakan "belum cukup bukti".

==================================================
OUTPUT JSON
==================================================

{
  "score": 0,
  "riskLevel": "AMAN",
  "analysis": {
    "domain": "",
    "tld": "",
    "isBrandImpersonation": false,
    "brandDetected": [],
    "domainAgeDays": null,
    "hasSSL": false,
    "sslValid": false,
    "hasLoginForm": false,
    "requestsSensitiveData": false,
    "socialEngineeringKeywords": [],
    "suspiciousScripts": [],
    "redirectCount": 0,
    "safeBrowsingDetected": false,
    "phishingDatabaseDetected": false,
    "pageTitle": ""
  },
  "reasons": [],
  "conclusion": ""
}

Jika memungkinkan, lakukan pencarian internet terlebih dahulu untuk:
- domain age
- reputasi domain
- blacklist phishing
- status malware

Lalu gabungkan hasil tersebut sebelum menentukan skor akhir.
`;

module.exports = async (req, res) => {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: 'URL tidak boleh kosong.' });
    }

    // --- PROSES EKSTRAKSI KONTEN WEB (SCRAPING) ---
    let webContent = "Tidak dapat mengekstrak isi web (kemungkinan diblokir oleh keamanan server tujuan). Analisis hanya dilakukan pada struktur URL.";
    let pageTitle = "Tidak diketahui";

    try {
        // Fetch HTML dari target URL (timeout 5 detik biar gak nunggu kelamaan)
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        const fetchRes = await fetch(url, { 
            headers: { 
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' 
            },
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        const html = await fetchRes.text();
        
        // 1. Ekstrak Title menggunakan Regex
        const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
        if (titleMatch) {
            pageTitle = titleMatch[1].trim();
        }

        // 2. Bersihkan HTML untuk mengambil teks murni
        // Hapus tag script & style biar kodenya gak ikut kebaca AI
        let cleanText = html.replace(/<script[^>]*>([\s\S]*?)<\/script>/gi, '')
                            .replace(/<style[^>]*>([\s\S]*?)<\/style>/gi, '')
                            // Hapus semua tag HTML
                            .replace(/<[^>]+>/g, ' ')
                            // Hapus spasi berlebih
                            .replace(/\s+/g, ' ')
                            .trim();
        
        // Ambil 3500 karakter pertama aja biar AI nggak jebol tokennya (ini udah cukup banget buat nemuin kata-kata penipuan)
        webContent = cleanText.substring(0, 3500);

    } catch (err) {
        console.warn(`Scraping gagal untuk ${url}:`, err.message);
        // Kalau gagal nge-scrape (misal webnya down atau ngeblokir fetch server), AI tetep bakal jalan ngecek URL-nya doang
    }

    // --- PROSES ANALISIS ZANNAI ---
    try {
        const model = genAI.getGenerativeModel({ 
            model: "gemini-2.5-flash",
            generationConfig: {
                responseMimeType: "application/json"
            }
        });

        // Prompt sekarang menyertakan Title dan Isi Web!
        const prompt = `Tolong analisis website berikut ini:\n\nURL: ${url}\nJudul Halaman: ${pageTitle}\nIsi Teks Web: ${webContent}\n\nBerikan response JSON sesuai System Rules.`;

        const result = await model.generateContent({
            contents: [{ role: "user", parts: [{ text: prompt }] }],
            systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] }
        });

        const responseText = result.response.text();
        const jsonResult = JSON.parse(responseText);

        return res.status(200).json({ success: true, data: jsonResult });

    } catch (error) {
        console.error("AI Analysis Error:", error);
        return res.status(500).json({ error: 'Gagal menganalisis URL dengan AI.' });
    }
};
