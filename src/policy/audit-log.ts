import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditEntry } from "./types.js";

export class AuditLog {
  private readonly entries: AuditEntry[] = [];
  private dirEnsured = false;

  public constructor(private readonly logPath?: string) {}

  public async append(entry: AuditEntry): Promise<void> {
    this.entries.push(entry);
    if (this.logPath) {
      if (!this.dirEnsured) {
        await mkdir(dirname(this.logPath), { recursive: true });
        this.dirEnsured = true;
      }
      await appendFile(this.logPath, JSON.stringify(entry) + "\n");
    }
  }

  public getEntries(): ReadonlyArray<AuditEntry> {
    return this.entries;
  }
}
