import express from "express";
import cors from "cors";
import { runBulkVerify } from "./service/emailVerifyService"; // use your existing verifier

const app = express();
app.use(cors());
app.use(express.json());

// 🟢 Single API: verifyBulk
app.post("/verifyBulk", async (req, res) => {
  try {
    const { emails } = req.body;

    if (!emails || !Array.isArray(emails) || emails.length === 0) {
      return res.status(400).json({ error: "No emails provided" });
    }

    console.log(`🚀 Starting bulk verification for ${emails.length} emails...`);

    const results = [];
    await runBulkVerify(emails, {
      timeout: 10000,
      maxConcurrent: 100,
      perDomain: 3,
      onResult: (email, result) => {
        results.push({ email, ...result });
      },
    });

    console.log(`✅ Verification completed (${results.length} results)`);
    res.json({ success: true, total: results.length, data: results });
  } catch (err) {
    console.error("❌ Error in /verifyBulk:", err);
    res.status(500).json({ error: "Verification failed", details: err.message });
  }
});

// 🚀 Start server
const PORT = 5000;
app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`));
