const dns = require('dns').promises;
const validator = require('deep-email-validator');

const isDisposable = (domain) => {
  const disposableDomains = ['mailinator.com', 'tempmail.com', 'guerrillamail.com'];
  return disposableDomains.includes(domain.toLowerCase());
};

async function fastVerify(email) {
  if (!email || !email.includes('@')) return { email, status: 'syntax' };

  const [local, domain] = email.split('@');

  if (!local || !domain) return { email, status: 'syntax' };
  if (isDisposable(domain)) return { email, status: 'disposable' };

  try {
    await dns.resolveMx(domain);
  } catch {
    return { email, status: 'dns' };
  }

  const result = await validator.validate(email);
  if (!result.valid) return { email, status: result.reason || 'syntax' };

  return { email, status: 'queued' };
}

module.exports = { fastVerify };
