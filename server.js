const { GoogleGenerativeAI } = require("@google/generative-ai");

// Inisialisasi Gemini AI. Pastikan GEMINI_API_KEY diset di Environment Variables Vercel
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || "ISI_API_KEY_KAMU_DISINI_JIKA_LOKAL");

// System Prompt ZannScan AI sesuai dengan aturan yang diberikan
const SYSTEM_PROMPT = `
Kamu adalah ZannScan AI, ahli Keamanan Siber spesialis pendeteksi Web Phishing di Indonesia. 
Tugasmu adalah menganalisis URL yang diberikan pengguna dan merespons HANYA dalam format JSON.

ATURAN ANALISIS:
1. TLD TERPERCAYA (Perlu KTP/Legalitas): .id, .co.id, .ac.id, .sch.id, .go.id, .or.id
2. TLD BEBAS (Rawan): .my.id, .web.id, .biz.id, .desa.id, .com, .xyz, .top, dll.
3. KATA KUNCI MENCURIGAKAN: login, verify, verification, gift, hadiah, claim, bonus, prize, akun, saldo, update.
4. WHITELIST (Pasti Aman): go.id, kemdikbud.go.id, bpjs-kesehatan.go.id, bca.co.id, bni.co.id, bri.co.id, mandiri.co.id, telkom.co.id, kominfo.go.id, polri.go.id.

SISTEM SKOR (0-100, di mana 100 = Sangat Berbahaya):
- Base score: 10
- Jika TLD Bebas: +30
- Jika ada kata kunci mencurigakan di domain/path: +40
- Jika banyak subdomain (contoh: bca.login.verifikasi.my.id): +20
- Jika URL shortener (bit.ly, s.id): +30
- JIKA MASUK WHITELIST: Score langsung 0 - 10.

Jika domain mencoba meniru Whitelist (misal: bca-login.my.id, mandiri-update.com), berikan skor sangat tinggi (80-100) karena ini adalah teknik Phishing Spoofing.

Format Response WAJIB JSON:
{
  "score": <angka 0-100>,
  "analysis": {
    "tld": "<ekstensi domain, misal: .my.id>",
    "isTrustedTld": <boolean>,
    "hasSuspiciousKeywords": <boolean>,
    "keywordsFound": [<array kata kunci jika ada>],
    "isOnWhitelist": <boolean>
  },
  "reasons": [
    "<Penjelasan 1 kenapa aman/bahaya (Bahasa Indonesia yang profesional)>",
    "<Penjelasan 2>"
  ],
  "conclusion": "<Satu paragraf kesimpulan untuk pengguna (Beri peringatan tegas jika bahaya)>"
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

    try {
        const model = genAI.getGenerativeModel({ 
            model: "gemini-2.5-flash",
            generationConfig: {
                responseMimeType: "application/json"
            }
        });

        const prompt = `Analisis URL berikut ini:\nURL: ${url}\n\nBerikan response JSON berdasarkan System Rules.`;

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
