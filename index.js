const express = require("express");
const axios = require("axios");
const cors = require("cors");
const cheerio = require("cheerio");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Route Utama untuk membaca index.html dengan baik di server/Vercel
app.get('/', (req, res) => {
    let indexPath = path.join(__dirname, "public", "index.html");
    if (!fs.existsSync(indexPath)) {
        indexPath = path.join(__dirname, "index.html");
    }
    res.sendFile(indexPath);
});

// ===== SYSTEM PROMPT ZANNSCAN AI (DIPERBARUI AGAR LEBIH PINTAR & BERVARIASI) =====
const SYSTEM_PROMPT = `
Kamu adalah ZannScan AI Enterprise Edition, AI Cybersecurity Analyst spesialis deteksi Phishing, Scam, Malware, Fraud, dan Website Berbahaya buatan ZannMods.

TUGAS UTAMA:
Kamu akan diberikan URL target, Judul Halaman, dan KUTIPAN SOURCE CODE HTML. Pahami konteks dari web tersebut dan berikan analisis layaknya pakar keamanan siber senior yang memiliki pemikiran analitis tajam.

FAKTOR ANALISIS:
1. DOMAIN & URL: Ekstensi TLD, panjang domain, taktik penyamaran brand.
2. FORM SENSITIF: Apakah web meminta OTP, PIN, Password, NIK secara mencurigakan?
3. SOCIAL ENGINEERING: Deteksi manipulasi kata (bansos, dana kaget, klaim pulsa, dll).
4. SOURCE CODE: Deteksi elemen form atau struktur yang tidak wajar.

ATURAN SKORING & VARIASI (SANGAT PENTING):
- SKOR HARUS SPESIFIK & DINAMIS: JANGAN PERNAH memberikan skor bulat yang berulang-ulang (seperti 20, 30, 40). Berikan angka yang spesifik dan rasional dari hasil perhitunganmu (misal: 12, 17, 26, 33, 48, 62, 79, 94).
- 0-20  : AMAN (Website normal, berikan skor spesifik antara 1-20)
- 21-40 : RISIKO RENDAH (Mungkin web pribadi/blog biasa tanpa form aneh)
- 41-60 : MENCURIGAKAN (Ada indikasi aneh tapi belum pasti phising)
- 61-80 : BERBAHAYA (Kuat dugaan penipuan)
- 81-100: PHISHING / SCAM (Berbahaya mencuri data sensitif)
- JANGAN menganggap domain .com atau .my.id otomatis berbahaya. Nilai dari keseluruhan konteks HTML dan Teksnya!
- PENJELASAN (REASONS): Buatlah alasan dengan gaya bahasa yang profesional, tajam, natural, dan BERVARIASI. Jangan gunakan template kalimat yang sama terus-menerus. Buktikan bahwa kamu sedang "berpikir".
- KESIMPULAN (CONCLUSION): Rangkum dalam kalimat yang fresh, edukatif, dan tidak kaku layaknya robot.

KAMU WAJIB MEMBALAS HANYA DENGAN FORMAT JSON VALID. JANGAN GUNAKAN MARKDOWN \`\`\`json.

FORMAT OUTPUT:
{
  "score": (angka spesifik 0-100),
  "riskLevel": "AMAN / RISIKO RENDAH / MENCURIGAKAN / BERBAHAYA / PHISHING",
  "analysis": {
    "domain": "nama-domain",
    "isBrandImpersonation": false,
    "hasLoginForm": false,
    "requestsSensitiveData": false,
    "suspiciousKeywordsFound": []
  },
  "reasons": [
    "Penjelasan analitis dan unik pertama...",
    "Penjelasan analitis dan unik kedua..."
  ],
  "conclusion": "Kesimpulan akhir yang natural dan bervariasi."
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
            "temperature": 0.7 // Ditingkatkan agar AI lebih kreatif, bervariasi, dan tidak statis
        }, { 
            headers: {
                "Accept": "/*/",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
            }
        });
        return response.data;
    } catch (error) {
        console.error("AI Error:", error.message);
        throw new Error("Server ZannScan AI sedang sibuk. Coba lagi!");
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

    // PROSES SCRAPING
    try {
        const fetchRes = await axios.get(url, {
            headers: { 
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            },
            timeout: 8000
        });

        const $ = cheerio.load(fetchRes.data);
        pageTitle = $('title').text().trim() || "Tidak ada judul";

        let formHTML = "";
        $('form').each((i, el) => {
            $(el).find('*').removeAttr('style').removeAttr('class');
            formHTML += $.html(el) + "\n\n";
        });

        $('script, style, nav, footer, iframe, svg, img').remove();
        visibleText = $('body').text().replace(/\s+/g, ' ').trim().substring(0, 1500);

        extractedHTML = formHTML.trim() ? formHTML.substring(0, 2000) : "Tidak ditemukan form login/input pada halaman.";

    } catch (err) {
        console.warn(`[Scraping Warning] Gagal fetch HTML. Error: ${err.message}`);
        extractedHTML = `Gagal memuat source code web. AI hanya akan menilai berdasarkan struktur domain dan TLD. Error: ${err.message}`;
    }

    // SUSUN PROMPT
    const aiPrompt = `
Tolong evaluasi website ini secara kritis dan dinamis!

URL TARGET: ${url}
HOSTNAME: ${hostname}
JUDUL HALAMAN: ${pageTitle}

--- TEKS TERLIHAT ---
${visibleText || "Tidak ada teks yang dapat dibaca."}

--- SOURCE CODE (Form & Input) ---
${extractedHTML}

Berikan skor analisis keamanan yang sangat spesifik (hindari skor puluhan pas seperti 20, 30) serta alasan yang unik dan tidak kaku! Ingat, HANYA balas JSON!
`;

    // KIRIM KE AI
    try {
        console.log(`🧠 [ZannScan] AI sedang berpikir...`);
        const aiResponseText = await analyzeWithAI(aiPrompt);
        
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
            error: 'Gagal memproses hasil AI.',
        });
    }
});

if (process.env.NODE_ENV !== "production") {
    app.listen(PORT, () => console.log(`🚀 ZannScan AI Server berjalan di http://localhost:${PORT}`));
}

module.exports = app;
