#!/usr/bin/env node
/**
 * Kovanica Multi-Chain Bridge Relayer Demo (Wave D — kovanica-bridge)
 *
 * Supports Bitcoin (chain_id=0), Solana (chain_id=501), and all EVM chains
 * (Ethereum 1, Optimism 10, BNB 56, Polygon 137, Base 8453, Arbitrum 42161,
 * Avalanche 43114, Linea 59144, Blast 81457, Scroll 534352, or any EIP-155 ID).
 *
 * Polls `kovanica_getLogs` for `bridge_withdraw_requested` events and prints
 * relayer release actions per external chain family.
 *
 * Usage:
 *   node scripts/bridge-relayer-demo.mjs --rpc http://127.0.0.1:8545/rpc [--contract <hex32>] [--once]
 */

const SUPPORTED_CHAINS = new Map([
  [0, { family: "bitcoin", name: "Bitcoin", asset: "wBTC", confirmations: 6 }],
  [1, { family: "evm", name: "Ethereum", asset: "wETH", confirmations: 12 }],
  [10, { family: "evm", name: "Optimism", asset: "wETH", confirmations: 20 }],
  [56, { family: "evm", name: "BNB Smart Chain", asset: "wBNB", confirmations: 15 }],
  [137, { family: "evm", name: "Polygon PoS", asset: "wPOL", confirmations: 64 }],
  [501, { family: "solana", name: "Solana", asset: "wSOL", confirmations: 32 }],
  [8453, { family: "evm", name: "Base", asset: "wETH", confirmations: 20 }],
  [42161, { family: "evm", name: "Arbitrum One", asset: "wETH", confirmations: 20 }],
  [43114, { family: "evm", name: "Avalanche C-Chain", asset: "wAVAX", confirmations: 12 }],
  [59144, { family: "evm", name: "Linea", asset: "wETH", confirmations: 20 }],
  [81457, { family: "evm", name: "Blast", asset: "wETH", confirmations: 20 }],
  [534352, { family: "evm", name: "Scroll", asset: "wETH", confirmations: 20 }],
]);

const args = process.argv.slice(2);
const flag = (k, def) => {
  const i = args.indexOf(k);
  return i !== -1 && i + 1 < args.length ? args[i + 1] : def;
};
const RPC_URL = flag("--rpc", process.env.KOVANICA_RPC_URL || "http://127.0.0.1:8545/rpc");
const CONTRACT = flag("--contract", process.env.KOVANICA_BRIDGE_CONTRACT || "");
const INTERVAL_MS = Math.max(2000, Number(flag("--interval", "5000")) || 5000);
const RUN_ONCE = args.includes("--once");

let id = 1;
async function rpc(method, params = []) {
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: id++, method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(`${body.error.code}: ${body.error.message}`);
  return body.result;
}

let lastHeight = 0;
async function poll() {
  const raw = await rpc("kovanica_blockNumber", []);
  const tip = typeof raw === "string" && raw.startsWith("0x") ? Number.parseInt(raw, 16) : Number(raw || 0);
  if (tip > lastHeight) {
    const logs = await rpc("kovanica_getLogs", [
      { fromBlock: lastHeight, toBlock: tip, ...(CONTRACT ? { address: CONTRACT } : {}) },
    ]);
    if (Array.isArray(logs)) {
      for (const l of logs) {
        if (String(l.topic || "").includes("bridge_withdraw")) {
          console.log(`[relayer] outbound withdrawal event at height ${tip}: tx=${l.txHash || l.transactionHash}`);
        }
      }
    }
    lastHeight = tip;
  }
  console.log(
    `[relayer] tip=${tip} chains=${SUPPORTED_CHAINS.size} (+custom EVM) rpc=${RPC_URL}`,
  );
}

async function main() {
  console.log("[relayer] Kovanica Multi-Chain Bridge Relayer (BTC + Solana + All EVM chains)");
  do {
    try {
      await poll();
    } catch (e) {
      console.error(`[relayer] error: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (RUN_ONCE) break;
    await new Promise((r) => setTimeout(r, INTERVAL_MS));
  } while (true);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
