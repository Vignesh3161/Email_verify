const { createClient } = require('redis');
const client = createClient({ url: 'redis://localhost:6379' });
client.connect();

async function enqueueEmail(email) {
  await client.rPush('smtp-verification', JSON.stringify({ email }));
}

async function dequeueResults() {
  const results = [];
  while (await client.lLen('verification-results') > 0) {
    const res = await client.lPop('verification-results');
    results.push(JSON.parse(res));
  }
  return results;
}

module.exports = { enqueueEmail, dequeueResults };
