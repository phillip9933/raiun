// Run with tsx from an isolated install of the pinned @fyears/rclone-crypt 0.0.7 source.
// WEB_ORACLE_SOURCE must point to that checkout's src/index.ts.
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const source = process.env.WEB_ORACLE_SOURCE;
if (!source) throw new Error("Set WEB_ORACLE_SOURCE to the pinned Web oracle source");
const { Cipher } = await import(pathToFileURL(source).href);
const mode = process.argv[2];
const directory = process.argv[3];
if (!directory || (mode !== "generate" && mode !== "verify")) {
  throw new Error("Usage: web-oracle.mts generate|verify OUTPUT_DIRECTORY");
}

const sizes = [0, 1, 65535, 65536, 65537];
const names = ["1", "123456789012345", "1234567890123456", "12345678901234567", "写真🗃️", "folder/école.txt"];
const nonce = () => Uint8Array.from({ length: 24 }, (_, i) => i + 1);
const plain = (size: number) => Uint8Array.from({ length: size }, (_, i) => (31 * i + 7) & 255);
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

const cipher = new Cipher("base32");
await cipher.key("potato", "");
if (mode === "generate") {
  await mkdir(directory, { recursive: true });
  const encryptedNames: Record<string, string> = {};
  for (const name of names) {
    encryptedNames[name] = await cipher.encryptFileName(name);
    if ((await cipher.decryptFileName(encryptedNames[name])) !== name) throw new Error(`Name mismatch: ${name}`);
  }
  const files: Record<string, string> = {};
  for (const size of sizes) {
    const encrypted = await cipher.encryptData(plain(size), nonce());
    files[String(size)] = sha256(encrypted);
    await writeFile(join(directory, `web-${size}.bin`), encrypted);
    const decrypted = await cipher.decryptData(encrypted);
    if (sha256(decrypted) !== sha256(plain(size))) throw new Error(`Content mismatch: ${size}`);
  }
  const uuid = new TextEncoder().encode("123e4567-e89b-12d3-a456-426614174000");
  const token = await cipher.encryptData(uuid, nonce());
  await writeFile(join(directory, "web-integrity-token.b64"), Buffer.from(token).toString("base64") + "\n");
  const manifest = {
    source: "@fyears/rclone-crypt 0.0.7, fe7ce657bcf92566986ed1572f90e1cbb4683464",
    password: "potato (synthetic)",
    nonce: "0102030405060708090a0b0c0d0e0f101112131415161718",
    names: encryptedNames,
    sha256: files,
  };
  await writeFile(join(directory, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
  console.log(JSON.stringify({ mode, names: names.length, files: sizes.length, sha256: files }));
} else {
  for (const size of sizes) {
    const encrypted = new Uint8Array(await readFile(join(directory, `codec-${size}.bin`)));
    const decrypted = await cipher.decryptData(encrypted);
    if (sha256(decrypted) !== sha256(plain(size))) throw new Error(`Codec to Web mismatch: ${size}`);
  }
  for (const name of names) {
    const encrypted = await readFile(join(directory, `codec-name-${names.indexOf(name)}.txt`), "utf8");
    if ((await cipher.decryptFileName(encrypted.trimEnd())) !== name) throw new Error(`Codec name to Web mismatch: ${name}`);
  }
  console.log(JSON.stringify({ mode, names: names.length, files: sizes.length, status: "verified" }));
}
