const express = require('express');
const bodyParser = require('body-parser');
const { fastVerify } = require('./verifier');
const { enqueueEmail, dequeueResults } = require('./queue');

const app = express();
app.use(bodyParser.json());

app.post('/verify', async (req, res) => {
  const emails = req.body.emails || [];
  const queue = [];

  for (const email of emails) {
    const result = await fastVerify(email);
    if (result.status === 'queued') {
      await enqueueEmail(email);
    } else {
      queue.push({ email, result: result.status });
    }
  }

  setTimeout(async () => {
    const results = await dequeueResults();
    const merged = [];
    for (const email of emails) {
      const localResult =
        results.find(r => r.email === email)?.result ||
        queue.find(r => r.email === email)?.result ||
        'smtp';
      merged.push({ email, result: localResult });
    }
    res.json(merged);
  }, 3000); // small delay to allow worker processing
});

app.listen(3000, () => console.log('Node.js verifier running on port 3000'));
