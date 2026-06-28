const express = require("express");
const axios = require("axios");
const cors = require("cors");
const cheerio = require("cheerio");
const path = require("path");
const fs = require("fs"); // Tambahkan modul fs untuk membaca letak file

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
// Setup agar file statis bisa diakses dari folder public atau folder utama
app.use(express.static(path.join(__dirname, "public")));
app.use(express.static(__dirname)); 

// ===== FIX NOT FOUND: Endpoint untuk menampilkan UI Frontend =====
app.get("/", (req, res) => {
    const publicPath = path.join(__dirname, "public", "index.html");
    const rootPath = path.join(__dirname, "index.html");
    
    // Cek apakah file index.html ada di dalam folder 'public'
    if (fs.existsSync(publicPath)) {
        res.sendFile(publicPath);
    } 
    // Jika tidak ada di folder 'public', cek apakah ada di luar (sejajar dengan index.js)
    else if (fs.existsSync(rootPath)) {
        res.sendFile(rootPath);
    } 
    // Jika masih tidak ada, beri peringatan
    else {
        res.status(404).send("<h2>Error 404: File index.html tidak ditemukan!</h2><p>Pastikan kamu sudah menyimpan kode frontend ke dalam file bernama <b>index.html</b>.</p>");
    }
});

// ===== SYSTEM PROMPT ZANNSCAN AI =====
// Prompt ini dimodifikasi dari versi kamu agar fokus ke analisis HTML dan Source Code
const SYSTEM_PROMPT = `
Kamu adalah ZannScan AI Enterprise Edition, AI Cybersecurity Analyst spesialis deteksi Phishing, Scam, Malware, Fraud, dan Website Berbahaya buatan ZannMods.

TUGAS UTAMA:
Kamu akan diberikan URL target, Judul Halaman, dan KUTIPAN SOURCE CODE HTML (khususnya elemen form, input, dan teks penting).
Lakukan analisis mendalam layaknya analis keamanan senior. Pahami konteks dari source code tersebut.

FAKTOR ANALISIS:
1. DOMAIN & URL: Apakah URL mencoba meniru brand terkenal (BCA, BRI, DANA, dll) tapi menggunakan ekstensi aneh?
2. FORM SENSITIF: Analisis tag <input> dalam HTML. Apakah meminta password, PIN, OTP, NIK, atau CVV kartu kredit di luar konteks yang wajar?
3. SOCIAL ENGINEERING: Cari kata-kata seperti "klaim bonus", "bansos", "kuota gratis", "segera verifikasi".
4. MALWARE / SKRIP: Apakah ada indikasi skrip tersembunyi, iframe mencurigakan, atau metode obfuscation?

SKALA SKOR (0-100):
0-20  : AMAN (Website normal)
21-40 : RISIKO RENDAH (Sedikit mencurigakan tapi mungkin aman)
41-60 : MENCURIGAKAN (Harus waspada)
61-80 : BERBAHAYA (Indikasi kuat penipuan)
81-100: PHISHING / SCAM (Sangat berbahaya, mencuri data)

ATURAN WAJIB:
- JANGAN PERNAH menganggap domain .com atau .my.id otomatis berbahaya.
- Prioritaskan BUKTI NYATA dari source code HTML yang diberikan (misal: "Ditemukan form meminta OTP").
- KAMU WAJIB MEMBALAS HANYA DENGAN FORMAT JSON VALID. Jangan tambahkan teks apapun di luar JSON, jangan gunakan markdown \`\`\`json.

FORMAT OUTPUT JSON YANG DIHARAPKAN:
{
  "score": 0,
  "riskLevel": "AMAN",
  "analysis": {
    "domain": "nama-domain",
    "isBrandImpersonation": false,
    "hasLoginForm": false,
    "requestsSensitiveData": false,
    "suspiciousKeywordsFound": []
  },
  "reasons": [
    "Penjelasan 1 berdasarkan analisis HTML",
    "Penjelasan 2 berdasarkan analisis URL"
  ],
  "conclusion": "Kesimpulan akhir yang mudah dipahami orang awam."
}
`;

// ===== FUNGSI API ZANNAI =====
async function analyzeWithAI(promptText) {
    try {
        let response = await axios.post("https://chateverywhere.app/api/chat/", {
            "model": {
                "id": "gpt-4",
                "name": "GPT-4",
                "maxLength": 32000,
                "tokenLimit": 8000,
                "completionTokenLimit": 5000,
                "deploymentName": "gpt-4"
            },
            "messages": [
                { "pluginId": null, "content": SYSTEM_PROMPT, "role": "system" },
                { "pluginId": null, "content": promptText, "role": "user" }
            ],
            "prompt": "",  
            "temperature": 0.3 // Temperature direndahkan agar analisis lebih logis dan konsisten
        }, { 
            headers: {
                "Accept": "/*/",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
            }
        });
        return response.data;
    } catch (error) {
        console.error("AI Error:", error.message);
        throw new Error("Waduh, server ZannScan AI lagi sibuk nih bree. Coba lagi bentar ya! 🛠️");
    }
}

// ===== ENDPOINT SCANNER =====
app.post("/api/scan", async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ success: false, error: 'URL target tidak boleh kosong.' });
    }

    let hostname;
    try {
        hostname = new URL(url).hostname.toLowerCase();
    } catch (e) {
        return res.status(400).json({ success: false, error: 'Format URL tidak valid. Sertakan http:// atau https://' });
    }

    console.log(`🔍 [ZannScan] Memulai pemindaian untuk: ${url}`);

    let pageTitle = "Tidak diketahui";
    let extractedHTML = "Gagal mengambil source code.";
    let visibleText = "";

    // 1. PROSES SCRAPING & EKSTRAKSI SOURCE CODE
    try {
        const fetchRes = await axios.get(url, {
            headers: { 
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            },
            timeout: 8000 // Maksimal 8 detik nunggu webnya
        });

        const $ = cheerio.load(fetchRes.data);
        
        // Ambil Judul
        pageTitle = $('title').text().trim() || "Tidak ada judul";

        // Ekstrak elemen-elemen penting (Form, Input, Button) untuk dianalisis AI
        // Kita tidak mengirim seluruh HTML agar tidak kena limit token, tapi kita kirim struktur intinya
        let formHTML = "";
        $('form').each((i, el) => {
            // Hapus atribut yang ga penting biar bersih
            $(el).find('*').removeAttr('style').removeAttr('class');
            formHTML += $.html(el) + "\n\n";
        });

        // Ambil teks yang terlihat oleh user (berguna untuk deteksi social engineering)
        $('script, style, nav, footer, iframe, svg, img').remove();
        visibleText = $('body').text().replace(/\s+/g, ' ').trim().substring(0, 1500);

        extractedHTML = formHTML.trim() ? formHTML.substring(0, 2000) : "Tidak ditemukan tag <form> pada halaman ini.";

    } catch (err) {
        console.warn(`[Scraping Warning] Gagal fetch HTML untuk ${url}. Alasan: ${err.message}`);
        extractedHTML = `Gagal diakses secara publik (Error: ${err.message}). Analisis hanya akan bergantung pada struktur URL dan Domain.`;
    }

    // 2. SUSUN PROMPT UNTUK AI
    const aiPrompt = `
Tolong analisis website berikut secara detail:

URL TARGET: ${url}
HOSTNAME: ${hostname}
JUDUL HALAMAN: ${pageTitle}

--- TEKS TERLIHAT DI WEBSITE ---
${visibleText || "Tidak ada teks yang dapat dibaca."}

--- SOURCE CODE HTML (Elemen Form & Input) ---
${extractedHTML}

Lakukan analisis berdasarkan data di atas. Apakah ada form yang meminta data sensitif? Apakah ada indikasi penipuan dari teksnya?
Ingat, balas HANYA dengan JSON valid!
`;

    // 3. KIRIM KE AI DAN PARSING HASILNYA
    try {
        console.log(`🧠 [ZannScan] Menganalisis data dengan AI...`);
        const aiResponseText = await analyzeWithAI(aiPrompt);
        
        // Membersihkan jika AI masih ngeyel ngasih markdown ```json
        let cleanJsonText = aiResponseText;
        if (cleanJsonText.startsWith("```")) {
            cleanJsonText = cleanJsonText.replace(/^```(json)?|```$/gi, '').trim();
        }

        const jsonResult = JSON.parse(cleanJsonText);

        return res.status(200).json({
            success: true,
            data: jsonResult
        });

    } catch (error) {
        console.error("🚨 ZannScan AI Parsing Error:", error);
        return res.status(500).json({ 
            success: false, 
            error: 'Gagal memproses analisis AI. Mungkin AI membalas dengan format yang salah.',
            details: error.message
        });
    }
});

if (process.env.NODE_ENV !== "production") {
    app.listen(PORT, () => console.log(`🚀 ZannScan AI Server berjalan di http://localhost:${PORT}`));
}

module.exports = app;
