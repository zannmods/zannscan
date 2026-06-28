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

// ===== SYSTEM PROMPT ZANNSCAN AI (OTAK UTAMA - STRICT JSON) =====
const SYSTEM_PROMPT = `
Kamu adalah ZannScan AI Enterprise, AI Investigator Keamanan Siber tingkat lanjut.
Tugasmu adalah menganalisis URL dan Source Code HTML untuk mencari celah phishing, scam, atau penipuan.

ATURAN WAJIB (JIKA DILANGGAR SISTEM AKAN HANCUR):
1. KAMU HANYA BOLEH MENGELUARKAN OUTPUT BERUPA JSON MURNI. JANGAN ADA TEKS PEMBUKA/PENUTUP.
2. SKOR HARUS SANGAT BERVARIASI: Analisis dengan sangat kritis. Jangan pernah gunakan angka bulat seperti 20, 30, 40, atau 50. Gunakan angka probabilitas pasti seperti 11, 24, 37, 58, 63, 84, 91.
3. KESIMPULAN & ALASAN HARUS BERBEDA-BEDA: Gunakan gaya bahasa detektif siber. Jelaskan temuan teknis (misal: "Ditemukan form input tanpa SSL yang mencurigakan..." atau "Domain menggunakan ekstensi yang sering dipakai untuk bypass keamanan...").

SKALA RISIKO:
0-15  : AMAN (Situs wajar/terpercaya)
16-35 : RISIKO RENDAH (Minim ancaman, tapi bukan domain resmi besar)
36-60 : MENCURIGAKAN (Ada elemen form atau teks yang memicu peringatan)
61-80 : BERBAHAYA (Indikasi kuat manipulasi/scam)
81-100: PHISHING / SCAM (Situs pencuri data)

FORMAT JSON WAJIB (Tanpa \`\`\`json):
{
  "score": <angka_spesifik>,
  "riskLevel": "<kategori>",
  "analysis": {
    "domain": "<domain_target>",
    "isBrandImpersonation": <true/false>,
    "hasLoginForm": <true/false>,
    "requestsSensitiveData": <true/false>,
    "suspiciousKeywordsFound": ["kata1", "kata2"]
  },
  "reasons": [
    "<alasan_teknis_1_yang_sangat_spesifik_dan_panjang>",
    "<alasan_teknis_2_berdasarkan_source_code_atau_URL>"
  ],
  "conclusion": "<Kesimpulan_akhir_yang_tajam_dan_bervariasi>"
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
            "temperature": 0.8 // Ditingkatkan agar analisis tidak repetitif
        }, { 
            headers: {
                "Accept": "/*/",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            timeout: 15000 // Tambah waktu agar AI punya waktu berpikir lebih lama
        });
        return response.data;
    } catch (error) {
        console.error("AI API Error:", error.message);
        throw new Error("Server AI gagal merespons tepat waktu.");
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
        return res.status(400).json({ success: false, error: 'Format URL tidak valid.' });
    }

    console.log(`🔍 [ZannScan] Memulai pemindaian (AI Engine) untuk: ${url}`);

    let pageTitle = "Tidak diketahui";
    let extractedHTML = "Gagal mengambil source code.";
    let visibleText = "";

    // PROSES SCRAPING DENGAN CHEERIO
    try {
        const fetchRes = await axios.get(url, {
            headers: { 
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            timeout: 7000
        });

        const $ = cheerio.load(fetchRes.data);
        pageTitle = $('title').text().trim() || "Tidak ada judul";

        // Ambil elemen form
        let formHTML = "";
        $('form, input, button').each((i, el) => {
            $(el).find('*').removeAttr('style').removeAttr('class');
            formHTML += $.html(el) + "\n";
        });

        $('script, style, nav, footer, iframe, svg, img').remove();
        visibleText = $('body').text().replace(/\s+/g, ' ').trim().substring(0, 1000);

        extractedHTML = formHTML.trim() ? formHTML.substring(0, 1500) : "Tidak ditemukan form login/input pada halaman.";

    } catch (err) {
        console.warn(`[Scraping Warning] Gagal membaca isi web. Fokus ke analisis URL.`);
        extractedHTML = `Isi web disembunyikan/terblokir. Lakukan tebakan analitis tingkat lanjut berdasarkan nama URL, TLD, dan pola serangan umum.`;
    }

    // ANTI-CACHE SEED & DYNAMIC PROMPT
    const timestamp = new Date().toISOString();
    const dynamicSeed = Math.floor(Math.random() * 10000);
    
    const aiPrompt = `
[ID Analisis: ${dynamicSeed} | Waktu: ${timestamp}]
Tolong evaluasi website ini secara kritis! Lakukan analisis mendalam!

URL TARGET: ${url}
HOSTNAME: ${hostname}
JUDUL HALAMAN: ${pageTitle}

--- TEKS TERBACA DI WEB ---
${visibleText || "Tidak ada teks yang dapat dibaca."}

--- SOURCE CODE (Form & Input) ---
${extractedHTML}

INGAT:
1. Keluarkan HANYA JSON.
2. JANGAN gunakan skor 20, 30, 40. Gunakan skor yang dinamis (contoh: 18, 34, 57, 82).
3. Berikan alasan teknis yang komprehensif dan bervariasi!
`;

    // KIRIM KE AI & PROSES JSON
    try {
        console.log(`🧠 [ZannScan] Menunggu analisis mendalam dari AI...`);
        let aiResponseText = await analyzeWithAI(aiPrompt);
        let jsonResult;

        // 1. Cek apakah Axios sudah otomatis mem-parsing JSON menjadi Object
        if (typeof aiResponseText === 'object' && aiResponseText !== null) {
            // Validasi apakah object ini mengandung kerangka jawaban yang kita harapkan
            if (aiResponseText.score !== undefined) {
                jsonResult = aiResponseText;
            } else {
                // Jika terbungkus di dalam format API (misal: { response: "..." }), jadikan string lagi
                aiResponseText = JSON.stringify(aiResponseText);
            }
        }

        // 2. Jika masih berupa String (misal ada teks pengantar AI atau format Markdown)
        if (!jsonResult) {
            // Pastikan dia bertipe string sebelum memakai .match()
            if (typeof aiResponseText !== 'string') {
                aiResponseText = String(aiResponseText);
            }
            
            // BULLETPROOF JSON EXTRACTOR
            const jsonMatch = aiResponseText.match(/\{[\s\S]*\}/);
            
            if (jsonMatch) {
                jsonResult = JSON.parse(jsonMatch[0]);
            } else {
                throw new Error("JSON tidak ditemukan pada teks balasan AI.");
            }
        }

        return res.status(200).json({
            success: true,
            data: jsonResult
        });

    } catch (error) {
        console.error("🚨 ZannScan AI Parsing Error:", error.message);
        return res.status(500).json({ 
            success: false, 
            error: 'Gagal memproses hasil AI. Format tidak valid atau timeout.',
        });
    }
});

if (process.env.NODE_ENV !== "production") {
    app.listen(PORT, () => console.log(`🚀 ZannScan AI Server berjalan di http://localhost:${PORT}`));
}

module.exports = app;
