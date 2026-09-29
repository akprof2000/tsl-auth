// Общие помощники контрактных тестов: чтение vectors.json, локальные HTTP-заглушки.
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

/** vectors.json из SDK_CONTRACT_VECTORS или ../../tests/sdk-contract/vectors.json относительно каталога SDK. */
export function loadVectors() {
  const path = process.env.SDK_CONTRACT_VECTORS ?? resolve(here, "..", "..", "..", "tests", "sdk-contract", "vectors.json");
  return JSON.parse(readFileSync(path, "utf8"));
}

export const decodePayload = (token) => JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));

/** Поднимает node:http-сервер на свободном порту; возвращает { url, close }. */
export function listen(handler) {
  return new Promise((done) => {
    const server = createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      done({ url: `http://127.0.0.1:${port}`, port, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

/** Читает JSON-тело ответа node:http/fetch. */
export const json = async (res) => {
  const text = await res.text();
  return text ? JSON.parse(text) : null;
};

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
