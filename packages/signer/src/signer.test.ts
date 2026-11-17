import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  ADDRESS_LENGTH,
  decodeAddress,
  encodeAddress,
  encodeLegacyAddress,
  parseAddress,
} from "./address.js";
import { formatKuna, parseKuna } from "./amount.js";
import { bytesToHex, hexToBytes } from "./bytes.js";
import "./ed25519.js";
import { keyFromMnemonic, seedToMnemonic } from "./keys.js";
import { encodeRawTransaction, rawTransactionSize, signTransaction, signingHash } from "./tx.js";
import type { TxKind, UnsignedTx } from "./tx.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  readFileSync(join(here, "../fixtures/wire.json"), "utf8"),
) as {
  chainId: number;
  seedHex: string;
  publicKeyHex: string;
  senderAddress: string;
  senderAddressLegacy: string;
  recipientAddress: string;
  recipientAddressLegacy: string;
  mnemonic: string;
  transactions: Array<{
    name: string;
    nonce: number;
    fee: number;
    signingHash: string;
    signature: string;
    rawHex: string;
  }>;
};

const seed = hexToBytes(fixture.seedHex);
const sender = hexToBytes(fixture.publicKeyHex);
const recipient = hexToBytes("22".repeat(32));

function unsigned(name: string): UnsignedTx {
  const row = fixture.transactions.find((entry) => entry.name === name);
  if (!row) throw new Error(name);
  const kind = kindFor(name);
  return {
    sender,
    nonce: BigInt(row.nonce),
    fee: BigInt(row.fee),
    kind,
  };
}

function kindFor(name: string): TxKind {
  switch (name) {
    case "transfer":
      return { type: "transfer", to: recipient, amount: 1_000_000n };
    case "stake":
      return { type: "stake", amount: 77n };
    case "unstake":
      return { type: "unstake", amount: 78n };
    case "delegate":
      return { type: "delegate", validator: recipient, amount: 79n };
    case "claimNone":
      return { type: "claimRewards", validator: null };
    case "claimSome":
      return { type: "claimRewards", validator: recipient };
    case "call-value-zero":
      return {
        type: "call",
        contract: hexToBytes("33".repeat(32)),
        value: 0n,
        method: "transfer",
        args: hexToBytes("010203"),
        gasLimit: 100_000n,
      };
    case "call-value-500":
      return {
        type: "call",
        contract: hexToBytes("33".repeat(32)),
        value: 500n,
        method: "transfer",
        args: hexToBytes("010203"),
        gasLimit: 100_000n,
      };
    default:
      throw new Error(name);
  }
}

describe("signature format v1", () => {
  it("reproduces the spec transfer, call, and valued-call vectors", async () => {
    const transfer = unsigned("transfer");
    expect(bytesToHex(signingHash(transfer, 2))).toBe(
      "0aae8c1832e09bf7da6f897d20b8bc6a017aaeefd50ea10015218a5c4a54c21d",
    );
    const signed = await signTransaction(transfer, 2, seed);
    expect(bytesToHex(signed.signature)).toBe(
      "c24cd02ec98045a34e4b3102a1cafe70883a83763d5915528554b54797b139df1768cad71220e78bcb6702b109f37bb79513c1f768bacab4bf6e96f4e16cdf06",
    );

    const call = {
      sender,
      nonce: 6n,
      fee: 10n,
      kind: {
        type: "call" as const,
        contract: hexToBytes("33".repeat(32)),
        value: 0n,
        method: "transfer",
        args: hexToBytes("010203"),
        gasLimit: 100_000n,
      },
    };
    expect(bytesToHex(signingHash(call, 2))).toBe(
      "e6ee05c494bc9197cdbf32f02558a36c0bf9f9ce92d7aceff99b65fa7ee3df92",
    );
    expect(bytesToHex((await signTransaction(call, 2, seed)).signature)).toBe(
      "938f46f0d12493a4a9f6b12b6b2270d519b3704006db70f1406f844d51d79a9e89169816863e2c9d3a86680a01ca09593ca63d53c350b133156e3c5a73f2b904",
    );

    const valued = {
      ...call,
      kind: { ...call.kind, value: 500n },
    };
    expect(bytesToHex(signingHash(valued, 2))).toBe(
      "616a96c5e4568b1e165670cd9c4afb4c8d2dd603dbf5b61142f7187a93d29df7",
    );
    expect(bytesToHex((await signTransaction(valued, 2, seed)).signature)).toBe(
      "48b532f19c6867e21907f829614864ca5cc54baf0177eab1dc4bbbc48b192d48507acdbd97731621c76498e33fb68ccfc37979cd0f17a959a14b94d159606c0b",
    );
  });

  it("matches the node bincode for every console transaction kind", async () => {
    for (const row of fixture.transactions) {
      const signed = await signTransaction(unsigned(row.name), fixture.chainId, seed);
      expect(bytesToHex(signed.hash), row.name).toBe(row.signingHash);
      expect(bytesToHex(signed.signature), row.name).toBe(row.signature);
      expect(encodeRawTransaction(signed), row.name).toBe(row.rawHex);
    }
  });
});

describe("addresses and amounts", () => {
  it("uses the checksum form the node prints", () => {
    expect(encodeAddress(sender)).toBe(fixture.senderAddress);
    expect(encodeAddress(recipient)).toBe(fixture.recipientAddress);
    expect(bytesToHex(decodeAddress(fixture.senderAddress))).toBe(fixture.publicKeyHex);
    expect(fixture.senderAddress.length).toBe(ADDRESS_LENGTH);
    expect(ADDRESS_LENGTH).toBe(64);
    const body = fixture.senderAddress.slice(0, -3);
    const flipped = body.slice(0, -1) + (body.endsWith("q") ? "p" : "q");
    expect(() => decodeAddress(`${flipped}dag`)).toThrow(/checksum/);
    expect(() => decodeAddress(`${body.slice(0, -1)}bdag`)).toThrow(/alphabet/);
    expect(() => decodeAddress(`${body.slice(0, -1)}dag`)).toThrow(/64 characters/);
    expect(() => decodeAddress(`kvnx${fixture.senderAddress.slice(4)}`)).toThrow(/start with kvnc/);
  });

  it("accepts legacy hex on the devnet (3), and refuses it elsewhere (PRO-21)", () => {
    expect(encodeLegacyAddress(sender)).toBe(fixture.senderAddressLegacy);
    expect(encodeLegacyAddress(recipient)).toBe(fixture.recipientAddressLegacy);
    for (const legacy of [fixture.senderAddressLegacy, fixture.publicKeyHex, `0x${fixture.publicKeyHex}`]) {
      expect(bytesToHex(parseAddress(legacy, 3))).toBe(fixture.publicKeyHex);
      expect(() => parseAddress(legacy)).toThrow(/chain id is omitted/);
      expect(() => parseAddress(legacy, 1)).toThrow(/not accepted on chain 1/);
      expect(() => parseAddress(legacy, 2)).toThrow(/not accepted on chain 2/);
      expect(() => parseAddress(legacy, 1337)).toThrow(/not accepted on chain 1337/);
      expect(() => parseAddress(legacy, 99)).toThrow(/not accepted on chain 99/);
    }
    for (const chain of [1, 2, 3, 1337]) {
      expect(bytesToHex(parseAddress(fixture.senderAddress, chain))).toBe(fixture.publicKeyHex);
    }
  });

  it("treats legacy hex digits as case-insensitive and base32 as lowercase (PRO-21)", () => {
    const upperHex = fixture.publicKeyHex.toUpperCase();
    expect(bytesToHex(parseAddress(upperHex, 3))).toBe(fixture.publicKeyHex);
    expect(() => parseAddress(upperHex, 2)).toThrow(/not accepted on chain 2/);
    expect(bytesToHex(parseAddress(`0x${upperHex}`, 3))).toBe(fixture.publicKeyHex);
    expect(() => parseAddress(`0x${upperHex}`, 1337)).toThrow(/not accepted on chain 1337/);
    const legacy = fixture.senderAddressLegacy;
    const upperLegacy = `kvnc${legacy.slice(4, -3).toUpperCase()}dag`;
    expect(bytesToHex(parseAddress(upperLegacy, 3))).toBe(fixture.publicKeyHex);
    expect(() => parseAddress(upperLegacy, 1)).toThrow(/not accepted/);
    const letter = [...fixture.senderAddress].findIndex(
      (c, i) => i > 3 && i < 61 && c >= "a" && c <= "z",
    );
    expect(letter).toBeGreaterThan(3);
    const upperBody =
      fixture.senderAddress.slice(0, letter) +
      fixture.senderAddress[letter].toUpperCase() +
      fixture.senderAddress.slice(letter + 1);
    expect(() => parseAddress(upperBody, 2)).toThrow(/alphabet/);
  });

  it("refuses an omitted chain id, 0X, and kvnc0x (PRO-21)", () => {
    expect(bytesToHex(parseAddress(fixture.senderAddress))).toBe(fixture.publicKeyHex);
    expect(bytesToHex(hexToBytes(`0x${fixture.publicKeyHex}`))).toBe(fixture.publicKeyHex);
    expect(() => hexToBytes(`0X${fixture.publicKeyHex}`)).toThrow(/invalid hex/);
    expect(() => parseAddress(`0X${fixture.publicKeyHex}`, 3)).toThrow(/invalid hex/);
    const body = fixture.senderAddressLegacy.slice(4, -3);
    expect(() => parseAddress(`kvnc0x${body}dag`, 3)).toThrow(/invalid hex/);
    expect(() => parseAddress(`kvnc0x${body}dag`, 1)).toThrow(/invalid hex/);
  });

  it("parses KVNC with 9 decimal places", () => {
    expect(parseKuna("1.5")).toBe(1_500_000_000n);
    expect(parseKuna("0")).toBe(0n);
    expect(parseKuna("50000")).toBe(50_000_000_000_000n);
    expect(formatKuna(1_500_000_000n)).toBe("1.5");
    expect(formatKuna(50_000_000_000_000n)).toBe("50000");
    expect(() => parseKuna("1.1234567891")).toThrow(/9 decimal/);
    expect(() => parseKuna("-1")).toThrow(/amount/);
    expect(() => parseKuna("1e2")).toThrow(/amount/);
  });

  it("round-trips the spec seed through the 24-word phrase", async () => {
    expect(seedToMnemonic(seed)).toBe(fixture.mnemonic);
    const key = await keyFromMnemonic(fixture.mnemonic);
    expect(bytesToHex(key.publicKey)).toBe(fixture.publicKeyHex);
    expect(key.address).toBe(fixture.senderAddress);
    await expect(keyFromMnemonic("abandon ".repeat(12).trim())).rejects.toThrow(/24/);
  });

  it("encodes call with exact wire bytes matching fixture", async () => {
    const call = {
      sender,
      nonce: 6n,
      fee: 10n,
      kind: {
        type: "call" as const,
        contract: hexToBytes("33".repeat(32)),
        value: 0n,
        method: "transfer",
        args: hexToBytes("010203"),
        gasLimit: 100_000n,
      },
    };
    const signed = await signTransaction(call, 2, seed);
    const encoded = encodeRawTransaction(signed);
    expect(encoded).toBe(fixture.transactions.find((r) => r.name === "call-value-zero")?.rawHex);
  });

  it("rawTransactionSize equals encoded length / 2 for call", async () => {
    const tx = {
      sender,
      nonce: 1n,
      fee: 123n,
      kind: {
        type: "call" as const,
        contract: hexToBytes("44".repeat(32)),
        value: 5n,
        method: "fn",
        args: new Uint8Array([9, 8, 7, 6, 5]),
        gasLimit: 1_000_000n,
      },
    };
    const signed = await signTransaction(tx, 2, seed);
    const hex = encodeRawTransaction(signed);
    const size = rawTransactionSize(tx);
    expect(size).toBe(hex.length / 2);
    expect(size).toBeGreaterThan(0);
  });

  it("rejects call with empty method and invalid contract/value/gas", () => {
    const base = {
      sender,
      nonce: 1n,
      fee: 1n,
      kind: {
        type: "call" as const,
        contract: hexToBytes("44".repeat(32)),
        value: 0n,
        method: "x",
        args: new Uint8Array(),
        gasLimit: 100n,
      },
    };
    expect(() => rawTransactionSize({ ...base, kind: { ...base.kind, method: "" } as any })).toThrow(/method/);
    expect(() => rawTransactionSize({ ...base, kind: { ...base.kind, contract: new Uint8Array(31) } as any })).toThrow(/contract/);
    expect(() => rawTransactionSize({ ...base, kind: { ...base.kind, contract: new Uint8Array(33) } as any })).toThrow(/contract/);
  });
});
