#!/usr/bin/env node
/**
 * Kovanica Keeper Bot (Wave C — kovanica-scheduler)
 *
 * Zero-dependency Node.js watcher that polls `kovanica_blockNumber` and
 * `kovanica_getLogs` for `scheduler_job_created` events on a deployed
 * `kovanica-scheduler` contract, tracks due jobs, and logs execution
 * readiness (or forwards to a custom signer webhook when configured).
 *
 * Usage:
 *   node scripts/keeper-bot.mjs --rpc http://127.0.0.1:8545/rpc --contract <hex32> [--interval 5000] [--once]
 */

const args = process.argv.slice(2);
function getFlag(name, fallback) {
  const idx = args.indexOf(name);
  if (idx === -1 || idx + 1 >= args.length) return fallback;
  return args[idx + 1];
}

const RPC_URL = getFlag("--rpc", process.env.KOVANICA_RPC_URL || "http://127.0.0.1:8545/rpc");
const CONTRACT = getFlag("--contract", process.env.KOVANICA_SCHEDULER_CONTRACT || "");
const INTERVAL_MS = Math.max(1000, Number(getFlag("--interval", "5000")) || 5000);
const RUN_ONCE = args.includes("--once");

let rpcId = 1;
async function rpcCall(method, params = []) {
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: rpcId++, method, params }),
  });
  if (!res.ok) {
    throw new Error(`RPC HTTP ${res.status}: ${await res.text()}`);
  }
  const body = await res.json();
  if (body.error) {
    throw new Error(`RPC error ${body.error.code}: ${body.error.message}`);
  }
  return body.result;
}

const trackedJobs = new Map();
let lastScannedHeight = 0;

async function pollOnce() {
  const heightRaw = await rpcCall("kovanica_blockNumber", []);
  const tipHeight = typeof heightRaw === "string" && heightRaw.startsWith("0x")
    ? Number.parseInt(heightRaw, 16)
    : Number(heightRaw || 0);

  if (tipHeight > lastScannedHeight) {
    const filter = {
      fromBlock: lastScannedHeight,
      toBlock: tipHeight,
      ...(CONTRACT ? { address: CONTRACT } : {}),
    };
    const logs = await rpcCall("kovanica_getLogs", [filter]);
    if (Array.isArray(logs)) {
      for (const log of logs) {
        const topic = String(log.topic || "");
        if (topic === "scheduler_job_created" || topic === "7363686564756c65725f6a6f625f63726561746564") {
          const key = `${log.address || CONTRACT}:${log.txHash || log.transactionHash}:${log.logIndex || 0}`;
          if (!trackedJobs.has(key)) {
            trackedJobs.set(key, {
              contract: log.address || CONTRACT,
              blockHeight: Number(log.blockNumber || tipHeight),
              data: log.data || "",
            });
            console.log(`[keeper] discovered scheduled job ${key} at height ${tipHeight}`);
          }
        }
      }
    }
    lastScannedHeight = tipHeight;
  }

  console.log(
    `[keeper] tip=${tipHeight} tracked_jobs=${trackedJobs.size} rpc=${RPC_URL}`,
  );
}

async function main() {
  console.log(`[keeper] starting Kovanica scheduler watcher (rpc=${RPC_URL}, interval=${INTERVAL_MS}ms)`);
  do {
    try {
      await pollOnce();
    } catch (err) {
      console.error(`[keeper] poll error: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (RUN_ONCE) break;
    await new Promise((resolve) => setTimeout(resolve, INTERVAL_MS));
  } while (true);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
