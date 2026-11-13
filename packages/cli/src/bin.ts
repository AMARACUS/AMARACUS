#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import os from 'os';
import { Amaracus, AmaracusError } from '@amaracus/sdk';

const CONFIG_DIR = path.join(os.homedir(), '.amaracus');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

interface CliConfig {
  apiKey?: string;
  baseUrl?: string;
}

function loadConfig(): CliConfig {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
    }
  } catch {}
  return {};
}

function saveConfig(cfg: CliConfig) {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), { mode: 0o600 });
}

function printHelp() {
  console.log(`
AMARACUS CLI - Production Cryptographic Developer Platform

Usage:
  amaracus [command] [options]

Core Commands:
  auth login --key <key>             Save API key to local profile (~/.amaracus/config.json)
  auth whoami                        Verify and inspect active identity context
  auth logout                        Remove local saved credentials

  keys list                          List cryptographic keys
  keys create --name <n> --alg <a>   Create a new managed cryptographic key
  keys show <keyId>                  Show details of a cryptographic key
  keys rotate <keyId>                Rotate a cryptographic key to a new version

  crypto encrypt --key-id <k> --pt <t>       Encrypt with a managed key (prints the envelope)
  crypto decrypt --key-id <k> --envelope <e> Decrypt an envelope from 'crypto encrypt'
  crypto digest --alg <a> --data <d>         Hash data (SHA-256, SHA-384, SHA-512, SHA3-*)

  pqc keypair --alg <alg>            Generate Post-Quantum keypair (ML_KEM_768, ML_DSA_65)
  pqc encapsulate --pubkey <key>     Encapsulate shared secret using ML-KEM
  pqc decapsulate --ct <c> --priv <k>Decapsulate shared secret using ML-KEM

  certs list                         List issued X.509 certificates
  certs issue --ca <id> --cn <name> --project <id> --env <id>
                                     Issue a new X.509 certificate

  cbom export [--format cyclonedx]   Export Cryptographic Bill of Materials (CBOM)
  cbom scan                          Trigger cryptographic compliance scan

  webhooks list                      List registered webhook endpoints
  webhooks test <webhookId>          Dispatch a test ping to a webhook

Global Options:
  --api-key <key>                    Override API key (or use AMARACUS_API_KEY env)
  --base-url <url>                   Override Base URL (default: https://api.amaracus.tech/api/v1)
  --json                             Format output as raw JSON
  -v, --version                      Show version
  -h, --help                         Show help documentation
`);
}

function getArgValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx !== -1 && idx + 1 < args.length) {
    return args[idx + 1];
  }
  return undefined;
}

function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || hasFlag(args, '-h') || hasFlag(args, '--help')) {
    printHelp();
    process.exit(0);
  }

  if (hasFlag(args, '-v') || hasFlag(args, '--version')) {
    console.log('amaracus-cli/1.0.0 (AMARACUS Developer Platform)');
    process.exit(0);
  }

  const isJson = hasFlag(args, '--json');
  const config = loadConfig();

  const apiKey = getArgValue(args, '--api-key') || process.env.AMARACUS_API_KEY || config.apiKey;
  const baseUrl = getArgValue(args, '--base-url') || process.env.AMARACUS_BASE_URL || config.baseUrl || 'https://api.amaracus.tech/api/v1';

  const command = args[0];
  const subcommand = args[1];

  // Auth commands (local profile)
  if (command === 'auth') {
    if (subcommand === 'login') {
      const key = getArgValue(args, '--key');
      if (!key) {
        console.error('Error: --key <api_key> is required for login.');
        process.exit(1);
      }
      saveConfig({ ...config, apiKey: key, baseUrl });
      console.log('✓ API Key saved securely to ~/.amaracus/config.json');
      process.exit(0);
    }

    if (subcommand === 'logout') {
      saveConfig({ ...config, apiKey: undefined });
      console.log('✓ API key removed from local configuration.');
      process.exit(0);
    }
  }

  if (!apiKey && !(command === 'auth' && subcommand === 'login')) {
    console.error('Error: No API key found. Pass --api-key <key>, set AMARACUS_API_KEY, or run `amaracus auth login --key <key>`.');
    process.exit(1);
  }

  const client = new Amaracus({ apiKey, baseUrl });

  try {
    if (command === 'auth' && subcommand === 'whoami') {
      const http = (client as any).http;
      const res = await http.request('GET', '/auth/me');
      if (isJson) {
        console.log(JSON.stringify(res.data, null, 2));
      } else {
        console.log('--- AMARACUS Principal Identity ---');
        console.log(`Type:            ${res.data.type}`);
        console.log(`ID:              ${res.data.id || (res.data.user && res.data.user.id)}`);
        console.log(`Organization ID: ${res.data.organizationId}`);
        if (res.data.scopes) console.log(`Granted Scopes:  [${res.data.scopes.join(', ')}]`);
        if (res.data.status) console.log(`Status:          ${res.data.status}`);
      }
      return;
    }

    // Keys commands
    if (command === 'keys') {
      if (subcommand === 'list') {
        const keys = await client.keys.list();
        if (isJson) {
          console.log(JSON.stringify(keys, null, 2));
        } else {
          console.log(`Found ${keys.length} cryptographic keys:`);
          for (const k of keys) {
            console.log(` • [${k.id}] ${k.name} | ${k.algorithm} | ${k.purpose} | Status: ${k.status} | v${k.currentVersion}`);
          }
        }
        return;
      }

      if (subcommand === 'create') {
        const name = getArgValue(args, '--name');
        const algorithm = getArgValue(args, '--alg') || 'AES_256_GCM';
        const purpose = getArgValue(args, '--purpose') || 'ENCRYPT_DECRYPT';
        const projectId = getArgValue(args, '--project') || 'proj_default';
        const environmentId = getArgValue(args, '--env') || 'env_prod';
        const provider = getArgValue(args, '--provider') || 'LOCAL_DEV';

        if (!name) {
          console.error('Error: --name <name> is required.');
          process.exit(1);
        }

        const key = await client.keys.create({
          name,
          algorithm,
          purpose,
          projectId,
          environmentId,
          provider,
        });

        if (isJson) {
          console.log(JSON.stringify(key, null, 2));
        } else {
          console.log(`✓ Created key '${key.name}' (ID: ${key.id}, Algorithm: ${key.algorithm}, Version: ${key.currentVersion})`);
        }
        return;
      }

      if (subcommand === 'rotate') {
        const keyId = args[2];
        if (!keyId) {
          console.error('Error: keyId argument is required. Usage: amaracus keys rotate <keyId>');
          process.exit(1);
        }
        const rotated = await client.keys.rotate(keyId);
        if (isJson) {
          console.log(JSON.stringify(rotated, null, 2));
        } else {
          console.log(`✓ Rotated key '${rotated.id}' to version ${rotated.currentVersion}`);
        }
        return;
      }

      if (subcommand === 'show') {
        const keyId = args[2];
        if (!keyId) {
          console.error('Error: keyId argument is required. Usage: amaracus keys show <keyId>');
          process.exit(1);
        }
        const key = await client.keys.get(keyId);
        console.log(JSON.stringify(key, null, 2));
        return;
      }
    }

    // Cryptography commands
    if (command === 'crypto' || command === 'cryptography') {
      if (subcommand === 'encrypt') {
        const plaintext = getArgValue(args, '--pt') || getArgValue(args, '--plaintext');
        const keyId = getArgValue(args, '--key-id');
        const aad = getArgValue(args, '--aad');

        if (!plaintext || !keyId) {
          console.error('Error: --key-id <managedKeyId> and --pt <plaintext> are required.');
          process.exit(1);
        }

        const result = await client.encrypt({ key: keyId, data: plaintext, aad });

        if (isJson) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          console.log(`✓ Envelope (pass to 'crypto decrypt --envelope'): ${result.envelope}`);
          console.log(`  Key version: ${result.keyVersion ?? 'n/a'}`);
        }
        return;
      }

      if (subcommand === 'decrypt') {
        const keyId = getArgValue(args, '--key-id');
        const envelope = getArgValue(args, '--envelope');
        const ciphertext = getArgValue(args, '--ct') || getArgValue(args, '--ciphertext');
        const iv = getArgValue(args, '--iv');
        const tag = getArgValue(args, '--tag');
        const aad = getArgValue(args, '--aad');

        if (!keyId || (!envelope && !ciphertext)) {
          console.error('Error: --key-id <managedKeyId> and --envelope <envelope> (or --ct/--iv/--tag) are required.');
          process.exit(1);
        }

        const result = await client.decrypt({ key: keyId, envelope, ciphertext, iv, tag, aad });

        if (isJson) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          console.log(`✓ Plaintext (${(result as any).encoding || 'utf8'}): ${result.plaintext}`);
        }
        return;
      }

      if (subcommand === 'digest') {
        const algorithm = getArgValue(args, '--alg') || 'SHA-256';
        const data = getArgValue(args, '--data');
        if (!data) {
          console.error('Error: --data <string> is required.');
          process.exit(1);
        }
        const result = await client.hash({ algorithm, data });
        if (isJson) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          console.log(`✓ Digest (${result.algorithm || algorithm}): ${result.digest}`);
        }
        return;
      }
    }

    // PQC commands
    if (command === 'pqc') {
      if (subcommand === 'keypair') {
        const alg = (getArgValue(args, '--alg') || 'ML_KEM_768') as 'ML_KEM_768' | 'ML_DSA_65';
        const kp = await client.pqc.keypair({ algorithm: alg });
        if (isJson) {
          console.log(JSON.stringify(kp, null, 2));
        } else {
          console.log(`✓ Generated ${kp.algorithm} Keypair:`);
          console.log(`Public Key:  ${kp.publicKey}`);
          console.log(`Private Key: ${kp.privateKey.substring(0, 32)}... [TRUNCATED]`);
        }
        return;
      }

      if (subcommand === 'encapsulate') {
        const pubkey = getArgValue(args, '--pubkey');
        if (!pubkey) {
          console.error('Error: --pubkey <base64> is required.');
          process.exit(1);
        }
        const result = await client.pqc.encapsulate({ algorithm: 'ML_KEM_768', publicKey: pubkey });
        if (isJson) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          console.log(`✓ ML-KEM Encapsulation Succeeded:`);
          console.log(`Ciphertext:   ${result.cipherText}`);
          console.log(`SharedSecret: ${result.sharedSecret}`);
        }
        return;
      }
    }

    // Certificates commands
    if (command === 'certs') {
      if (subcommand === 'list') {
        const certs = await client.certificates.list();
        if (isJson) {
          console.log(JSON.stringify(certs, null, 2));
        } else {
          console.log(`Found ${certs.length} certificates:`);
          for (const c of certs) {
            console.log(` • [${c.id}] ${c.subject} | Status: ${c.status} | Serial: ${c.serialNumber}`);
          }
        }
        return;
      }

      if (subcommand === 'issue') {
        const authorityId = getArgValue(args, '--ca');
        const cn = getArgValue(args, '--cn');
        const projectId = getArgValue(args, '--project');
        const environmentId = getArgValue(args, '--env');
        if (!authorityId || !cn || !projectId || !environmentId) {
          console.error('Error: --ca <caId>, --cn <commonName>, --project <projectId> and --env <environmentId> are required.');
          process.exit(1);
        }
        const cert = await client.certificates.issue({
          authorityId,
          projectId,
          environmentId,
          subject: `CN=${cn}`,
          san: { dns: [cn] },
        });
        if (isJson) {
          console.log(JSON.stringify(cert, null, 2));
        } else {
          console.log(`✓ Issued certificate '${cert.subject}' (Serial: ${cert.serialNumber})`);
        }
        return;
      }
    }

    // CBOM commands
    if (command === 'cbom') {
      if (subcommand === 'export') {
        const format = (getArgValue(args, '--format') || 'cyclonedx') as 'cyclonedx' | 'json';
        const cbom = await client.intelligence.exportCbom(format);
        console.log(JSON.stringify(cbom, null, 2));
        return;
      }

      if (subcommand === 'scan') {
        const scan = await client.intelligence.scan();
        if (isJson) {
          console.log(JSON.stringify(scan, null, 2));
        } else {
          console.log(`✓ Dispatched CBOM discovery scan. Scan ID: ${scan.scanId || scan.id || 'scan_active'}`);
        }
        return;
      }
    }

    // Webhooks commands
    if (command === 'webhooks') {
      if (subcommand === 'list') {
        const whs = await client.webhooks.list();
        if (isJson) {
          console.log(JSON.stringify(whs, null, 2));
        } else {
          console.log(`Found ${whs.length} registered webhooks:`);
          for (const w of whs) {
            console.log(` • [${w.id}] ${w.url} (${w.events.join(', ')}) Status: ${w.status}`);
          }
        }
        return;
      }

      if (subcommand === 'test') {
        const webhookId = args[2];
        if (!webhookId) {
          console.error('Error: webhookId argument is required. Usage: amaracus webhooks test <webhookId>');
          process.exit(1);
        }
        const ping = await client.webhooks.testPing(webhookId);
        console.log(`✓ Dispatched test ping to webhook ${webhookId}. HTTP Status: ${ping.delivery?.statusCode || 200}`);
        return;
      }
    }

    console.error(`Unknown command: ${command} ${subcommand || ''}. Run 'amaracus --help' for usage.`);
    process.exit(1);
  } catch (err: any) {
    if (err instanceof AmaracusError) {
      console.error(`Error [${err.code} ${err.status}]: ${err.message}`);
      if (err.requestId) console.error(`Request ID: ${err.requestId}`);
    } else {
      console.error('Unexpected Error:', err.message || err);
    }
    process.exit(1);
  }
}

main();
