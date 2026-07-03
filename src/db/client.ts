import { mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import type BetterSqlite3 from "better-sqlite3";
import { applySchema } from "./schema.ts";

const require = createRequire(import.meta.url);

// Prefere o better-sqlite3 nativo. Se o binário compilado não estiver
// disponível (ex.: ABI de Node diferente na máquina gerenciada), cai para o
// node:sqlite embutido, cuja superfície (new, exec, prepare/run/get/all,
// close) é compatível com o uso básico deste codebase.
function openDatabase(dbPath: string): BetterSqlite3.Database {
  try {
    const Database = require("better-sqlite3") as typeof BetterSqlite3;
    return new Database(dbPath) as unknown as BetterSqlite3.Database;
  } catch {
    const { DatabaseSync } =
      require("node:sqlite") as typeof import("node:sqlite");
    return new DatabaseSync(dbPath) as unknown as BetterSqlite3.Database;
  }
}

let _db: BetterSqlite3.Database | null = null;

export function getDb(dbPath: string): BetterSqlite3.Database {
  if (_db) return _db;
  mkdirSync(dirname(dbPath), { recursive: true });
  _db = openDatabase(dbPath);
  applySchema(_db);
  return _db;
}

export function closeDb(): void {
  if (_db) {
    _db.close();
    _db = null;
  }
}
