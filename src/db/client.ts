import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3";
import { applySchema } from "./schema.ts";

let _db: ReturnType<typeof Database> | null = null;

export function getDb(dbPath: string): ReturnType<typeof Database> {
  if (_db) return _db;
  mkdirSync(dirname(dbPath), { recursive: true });
  _db = new Database(dbPath);
  applySchema(_db);
  return _db;
}

export function closeDb(): void {
  if (_db) {
    _db.close();
    _db = null;
  }
}
