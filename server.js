const { GoogleGenerativeAI } = require("@google/generative-ai");

// Inisialisasi Gemini AI
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || "ISI_API_KEY_KAMU_DISINI_JIKA_LOKAL");

// System Prompt ZannScan AI - Diupdate biar AI baca konten web
const SYSTEM_PROMPT = `
Kamu adalah ZannScan AI, ahli Keamanan Siber spesialis pendeteksi Web Phishing di Indonesia. 
Tugasmu adalah menganalisis URL DAN KONTEN TEKS dari sebuah website, lalu merespons HANYA dalam format JSON.

ATURAN ANALISIS:
1. TLD TERPERCAYA: .id, .co.id, .ac.id, .sch.id, .go.id, .or.id
2. TLD BEBAS: .my.id, .web.id, .biz.id, .desa.id, .com, .xyz, .top, dll.
3. KATA KUNCI MENCURIGAKAN: login, verify, verification, gift, hadiah, claim, bonus, prize, akun, saldo, update, pembekuan, blokir, konfirmasi, otp, pin, sandi.
4. WHITELIST: go.id, kemdikbud.go.id, bpjs-kesehatan.go.id, bca.co.id, bni.co.id, bri.co.id, mandiri.co.id, telkom.co.id, kominfo.go.id, polri.go.id.
5. ANALISIS KONTEN: Jika teks halaman web (Title/Body) membahas perbankan, game, atau mengklaim hadiah dan meminta login, SEMENTARA URL-nya bukan domain resmi, itu pasti phishing.

SISTEM SKOR (0-100, 100 = Sangat Berbahaya):
- Base score: 10
- Jika TLD Bebas + URL ada kata phishing: +40
- Jika di DALAM KONTEN WEB terdapat kata kunci manipulatif (seperti "Masukkan PIN", "Klaim Hadiah"): +30
- Jika meniru merek/bank terkenal tapi pakai TLD bebas: +40
- JIKA MASUK WHITELIST (Domain asli): Score 0 - 10.

Format Response WAJIB JSON:
{
  "score": <angka 0-100>,
  "analysis": {
    "tld": "<ekstensi domain>",
    "isTrustedTld": <boolean>,
    "hasSuspiciousKeywords": <boolean>,
    "keywordsFound": ["<array kata kunci manipulatif yang ditemukan baik di URL maupun di dalam konten web>"],
    "isOnWhitelist": <boolean>,
    "pageTitle": "<judul halaman web jika terdeteksi>"
  },
  "reasons": [
    "<Penjelasan 1: Sebutkan jika menemukan kejanggalan pada struktur URL>",
    "<Penjelasan 2: Sebutkan jika menemukan kata-kata manipulatif atau indikasi penipuan DI DALAM konten webnya>"
  ],
  "conclusion": "<Satu paragraf kesimpulan tegas untuk pengguna>"
}
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
