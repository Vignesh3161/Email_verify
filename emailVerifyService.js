/**
 * strongEmailVerifier.js
 *
 * - Bulk email verifier (single-file)
 * - Checks: Syntax, Domain DNS, MX, SMTP Connect (EHLO/STARTTLS), RCPT TO (mailbox),
 *           Catch-all detection, Disposable check (from GitHub list), DNSBL check (rudimentary).
 *
 * Usage:
 *   - Import runBulkVerify() from server and call it with an array of emails and options.
 *
 * IMPORTANT: Use responsibly. Many mail servers block or rate-limit SMTP probes.
 */

import fs from "fs";
import dns from "dns/promises";
import net from "net";
import tls from "tls";
import https from "https";
import { randomBytes } from "crypto";
import EventEmitter from "events";
import pLimit from "p-limit";

const DEFAULT_TIMEOUT = 15000; // ms for TCP operations
const SMTP_PORT = 25;
let MAX_CONCURRENT_CONNECTIONS = 200; // global concurrent socket connections (tune)
let PER_DOMAIN_CONCURRENCY = 3;     // simultaneous connections per domain
const RETRIES = 2;
const BACKOFF_BASE = 400; // ms
 
const BATCH_SIZE = 500;  
const SMTP_WORKER_LIMIT = 200;  
 
const disposableDomainsSample = new Set([
  "mailinator.com","10minutemail.com","temp-mail.org","trashmail.com","dispostable.com",
  "guerrillamail.com","yopmail.com","temp-mail.io","maildrop.cc","fakeinbox.com"
]);
 
let disposableDomains = new Set(disposableDomainsSample);
 
const dnsblProviders = [
  "zen.spamhaus.org",          
  "bl.spamcop.net",          
  "dnsbl.sorbs.net"         
];
 

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
 
function isValidSyntax(email) { 
  const re = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
  return re.test(email);
}

function randomMailbox(domain) {
  return `${randomBytes(6).toString("hex")}@${domain}`;
}

function backoffDelay(attempt) {
  return BACKOFF_BASE * Math.pow(2, attempt);
}

async function loadDisposableDomainsFromGitHub() {
  const url = "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt";
  return new Promise((resolve) => {
    try {
      https.get(url, (res) => {
        if (res.statusCode !== 200) {
          console.error(`⚠️ Disposable list fetch failed: HTTP ${res.statusCode}`);
          return resolve(false);
        }
        let data = "";
        res.on("data", (chunk) => data += chunk);
        res.on("end", () => {
          try {
            const domains = data
              .split("\n")
              .map(d => d.trim().toLowerCase())
              .filter(d => d && !d.startsWith("#"));
            if (domains.length > 0) {
              disposableDomains = new Set(domains);
              console.log(`✅ Loaded ${disposableDomains.size} disposable domains from GitHub`);
              return resolve(true);
            }
            console.error("⚠️ Disposable list empty after parsing");
            return resolve(false);
          } catch (e) {
            console.error("⚠️ Error parsing disposable list:", e.message || e);
            return resolve(false);
          }
        });
      }).on("error", (err) => {
        console.error("⚠️ Failed to load disposable list:", err.message || err);
        return resolve(false);
      });
    } catch (err) {
      console.error("⚠️ Exception while fetching disposable list:", err.message || err);
      return resolve(false);
    }
  });
}


const mxCache = new Map();  

async function lookupMX(domain) {
  if (mxCache.has(domain)) return mxCache.get(domain);
  try {
    const mxs = await dns.resolveMx(domain);
    if (!mxs || mxs.length === 0) throw new Error("no-mx");
    mxs.sort((a,b) => a.priority - b.priority);
    mxCache.set(domain, mxs);
    return mxs;
  } catch (err) {
    try {
      const a = await dns.resolve(domain, 'A').catch(()=>[]);
      const aaaa = await dns.resolve(domain, 'AAAA').catch(()=>[]);
      const records = [...a.map(ip=>({exchange: domain, priority: 0})), ...aaaa.map(ip=>({exchange: domain, priority: 0}))];
      if (records.length) {
        mxCache.set(domain, records);
        return records;
      }
    } catch(_) {}
    throw err;
  }
}

async function domainExists(domain) {
  try {
    const soa = await dns.resolveSoa(domain).catch(()=>null);
    if (soa) return true;
    const a = await dns.resolve(domain, 'A').catch(()=>null);
    const aaaa = await dns.resolve(domain, 'AAAA').catch(()=>null);
    return !!(a && a.length) || !!(aaaa && aaaa.length);
  } catch (err) {
    return false;
  }
}

async function checkDnsbl(ip) {
  if (!ip || ip.split('.').length !== 4) return {listed: false, providers: []};
  const octets = ip.split('.').reverse().join('.');
  const listedProviders = [];
  for (const prov of dnsblProviders) {
    const query = `${octets}.${prov}`;
    try {
      const res = await dns.resolve4(query).catch(()=>null);
      if (res && res.length) listedProviders.push(prov);
    } catch (_) {}
  }
  return { listed: listedProviders.length>0, providers: listedProviders };
}


async function probeMailbox(mxHost, fromAddress, toAddress, timeout = DEFAULT_TIMEOUT) {
  return new Promise((resolve) => {
    const result = {
      host: mxHost,
      connected: false,
      supportsStartTLS: false,
      banner: null,
      ehlo: null,
      tls: false,
      mailFromOk: false,
      rcptToOk: false,
      rcptCode: null,
      rcptResponse: null,
      rawTranscript: [],
      ip: null,
      error: null
    };

    const socket = net.createConnection({ host: mxHost, port: SMTP_PORT, timeout }, async () => {
      result.connected = true;
    });

    let dataBuf = "";
    let step = 0;
    let stream = socket;
    let closed = false;

    const writeLine = (line) => {
      if (closed) return;
      result.rawTranscript.push(`C: ${line}`);
      stream.write(line + "\r\n");
    };

    const cleanup = (err) => {
      if (closed) return;
      closed = true;
      try { socket.end(); socket.destroy(); } catch(_) {}
      if (err) result.error = err.message || String(err);
      resolve(result);
    };

    const onData = (chunk) => {
      const s = chunk.toString();
      result.rawTranscript.push(`S: ${s.trim()}`);
      dataBuf += s;
      if (!dataBuf.includes("\r\n")) return;
      const lines = dataBuf.split("\r\n");
      dataBuf = lines.pop();
      for (const line of lines) {
        if (!result.banner) result.banner = line;
        try {
          if (step === 0) {
            writeLine(`EHLO localhost`);
            step = 1;
          } else if (step === 1) {
            result.ehlo = result.ehlo ? result.ehlo + "\n" + line : line;
            if (/^[0-9]{3} /.test(line)) {
              if (result.ehlo.toUpperCase().includes("STARTTLS")) {
                result.supportsStartTLS = true;
              }
              if (result.supportsStartTLS) {
                writeLine("STARTTLS");
                step = 2;
              } else {
                writeLine(`MAIL FROM:<${fromAddress}>`);
                step = 4;
              }
            }
          } else if (step === 2) {
            if (!/^[0-9]{3}/.test(line)) { cleanup(new Error("unexpected-starttls-response")); return; }
            if (line.startsWith("220")) {
              stream.removeListener("data", onData);
              socket.removeAllListeners("error");
              socket.removeAllListeners("timeout");
              const secure = tls.connect({
                socket,
                servername: mxHost,
                rejectUnauthorized: false,
                timeout
              }, () => {
                result.tls = true;
                stream = secure;
                stream.on("data", onData);
                stream.on("error", e => cleanup(e));
                writeLine(`EHLO localhost`);
                step = 3;
              });
              secure.on("error", (e) => cleanup(e));
            } else {
              writeLine(`MAIL FROM:<${fromAddress}>`);
              step = 4;
            }
          } else if (step === 3) {
            result.ehlo = result.ehlo ? result.ehlo + "\n" + line : line;
            if (/^[0-9]{3} /.test(line)) {
              writeLine(`MAIL FROM:<${fromAddress}>`);
              step = 4;
            }
          } else if (step === 4) {
            if (/^[0-9]{3}/.test(line)) {
              if (line.startsWith("250")) result.mailFromOk = true;
              writeLine(`RCPT TO:<${toAddress}>`);
              step = 5;
            } else {
              cleanup(new Error("MAIL_FROM_failed"));
              return;
            }
          } else if (step === 5) {
            if (/^[0-9]{3}/.test(line)) {
              const code = parseInt(line.slice(0,3),10);
              result.rcptCode = code;
              result.rcptResponse = line;
              if (code >= 200 && code < 300) {
                result.rcptToOk = true;
              } else {
                result.rcptToOk = false;
              }
              writeLine("RSET");
              writeLine("QUIT");
              step = 6;
            } else {
              cleanup(new Error("unexpected-rcpt-response"));
              return;
            }
          } else if (step === 6) {
            if (/^[0-9]{3} /.test(line) && line.startsWith("221")) {
              cleanup();
              return;
            }
          }
        } catch (err) {
          cleanup(err);
          return;
        }
      }
    };

    socket.setTimeout(timeout, () => cleanup(new Error("timeout")));
    socket.on("data", onData);
    socket.on("error", (err) => cleanup(err));
    socket.on("end", () => cleanup());
    socket.on("close", () => cleanup());
  });
}


async function verifyEmail(email, opts = {}) {
  const report = {
    email,
    syntax: false,
    domainExists: false,
    mxRecords: null,
    smtpProbe: null,
    mailbox: "unknown", 
    catchAll: false,
    disposable: false,
    dnsbl: { listed: false, providers: [] },
    timestamp: new Date().toISOString(),
    notes: []
  };

  if (!isValidSyntax(email)) {
    report.syntax = false;
    report.mailbox = "invalid";
    report.notes.push("invalid-syntax");
    return report;
  }
  report.syntax = true;

  const [localPart, domain] = email.split("@");

  const domainOk = await domainExists(domain).catch(()=>false);
  report.domainExists = !!domainOk;
  if (!domainOk) {
    report.mailbox = "invalid";
    report.notes.push("domain-not-resolving");
    return report;
  }

  let mxs;
  try {
    mxs = await lookupMX(domain);
    report.mxRecords = mxs.map(m=>({exchange: m.exchange, priority: m.priority}));
  } catch (err) {
    report.mxRecords = null;
    report.notes.push("mx-lookup-failed:" + (err && err.code ? err.code : err.message || err));
    report.mailbox = "unknown";
    return report;
  }

  if (disposableDomains.has(domain)) {
    report.disposable = true;
    report.notes.push("disposable-domain");
  }

  try {
    const mxHost = mxs[0].exchange;
    const addresses = await dns.resolve(mxHost, 'A').catch(()=>[]);
    const aaaaa = await dns.resolve(mxHost, 'AAAA').catch(()=>[]);
    const ips = [...addresses||[], ...aaaaa||[]];
    for (const ip of ips) {
      const dres = await checkDnsbl(ip);
      if (dres.listed) {
        report.dnsbl = dres;
        report.notes.push("mx-listed-on-dnsbl");
        break;
      }
    }
  } catch(_) {}

  const fromAddress = `probe@${(process.env.PROBE_DOMAIN || "example.com")}`;
  let probeRes = null;
  let lastErr = null;
  for (let attempt=0; attempt<=RETRIES; attempt++) {
    for (const mx of mxs) {
      try {
        const ips = await dns.resolve(mx.exchange, 'A').catch(()=>[]);
        const aaaa = await dns.resolve(mx.exchange, 'AAAA').catch(()=>[]);
        if ((!ips || ips.length === 0) && (!aaaa || aaaa.length === 0)) {
          continue;
        }
        probeRes = await probeMailbox(mx.exchange, fromAddress, email, opts.timeout || DEFAULT_TIMEOUT);
        if (probeRes && (probeRes.rcptToOk || probeRes.rcptCode)) break;
      } catch (err) {
        lastErr = err;
      }
    }
    if (probeRes) break;
    await sleep(backoffDelay(attempt));
  }

  report.smtpProbe = probeRes || null;
  if (probeRes) {
    if (probeRes.rcptToOk) {
      report.mailbox = "valid";
    } else if (probeRes.rcptCode && (probeRes.rcptCode >=400 && probeRes.rcptCode < 500)) {
      report.mailbox = "unknown";
    } else if (probeRes.rcptCode && (probeRes.rcptCode >=500 && probeRes.rcptCode < 600)) {
      report.mailbox = "invalid";
    } else {
      report.mailbox = "unknown";
    }
  } else {
    report.notes.push("smtp-probe-failed");
  }

  try {
    if (report.mailbox === "valid" || report.mailbox === "unknown") {
      const testAddress = randomMailbox(domain);
      const topMx = mxs[0].exchange;
      const probeForRandom = await probeMailbox(topMx, fromAddress, testAddress, opts.timeout || DEFAULT_TIMEOUT);
      if (probeForRandom && probeForRandom.rcptToOk) {
        report.catchAll = true;
        report.mailbox = "accept-all";
        report.notes.push("catch-all-detected");
      }
    }
  } catch (_) {}

  return report;
}


const domainLimits = new Map();

function getDomainLimit(domain) {
  if (!domainLimits.has(domain)) {
    domainLimits.set(domain, pLimit(PER_DOMAIN_CONCURRENCY));
  }
  return domainLimits.get(domain);
}

async function runBulkVerify(emails, opts = {}) {
  if (opts.maxConcurrent) MAX_CONCURRENT_CONNECTIONS = opts.maxConcurrent;
  if (opts.perDomain) PER_DOMAIN_CONCURRENCY = opts.perDomain;

  await loadDisposableDomainsFromGitHub().catch(()=>null);

  const globalLimiter = pLimit(MAX_CONCURRENT_CONNECTIONS);
  const smtpLimiter = pLimit(typeof opts.smtpWorkers === "number" ? opts.smtpWorkers : SMTP_WORKER_LIMIT);

  const outFile = opts.outputFile || "results.jsonl";
  const outStream = fs.createWriteStream(outFile, { flags: "w" });

  const emitter = new EventEmitter();
  let processed = 0;
  const total = emails.length;

  emitter.on("done", (r) => {
    processed++;
    if (opts.onProgress) opts.onProgress(processed);
    if (processed % Math.max(1, Math.floor(total/100)) === 0 || processed < 20) {
      console.error(`[${new Date().toISOString()}] processed ${processed}/${total}`);
    }
    outStream.write(JSON.stringify(r) + "\n");
  });

  for (let i = 0; i < emails.length; i += BATCH_SIZE) {
    const batch = emails.slice(i, i + BATCH_SIZE);
    const tasks = batch.map(email => globalLimiter(async () => {
      const domain = (email.split("@")[1] || "unknown").toLowerCase();
      const domainLimiter = getDomainLimit(domain);
      return domainLimiter(async () => {
        try {
          const res = await smtpLimiter(() => verifyEmail(email, opts));
          emitter.emit("done", res);
        } catch (err) {
          const res = { email, error: err.message || String(err) };
          emitter.emit("done", res);
        }
      });
    }));

    await Promise.all(tasks);
    await sleep(200);
  }

  outStream.end();
  console.error("All done. Results in", outFile);
  if (opts.onComplete) opts.onComplete();
}

export { runBulkVerify };
