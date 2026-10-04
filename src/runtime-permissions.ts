import type { Database } from './db.js';
export async function assertRuntimePermissions(db: Database) {
  for (const sql of [
    'UPDATE audit_events SET hash=hash WHERE false',
    'DELETE FROM audit_events WHERE false',
    'UPDATE policy_versions SET version=version WHERE false',
    'DELETE FROM policy_versions WHERE false',
  ]) {
    let denied = false;
    try {
      await db.pool.query(sql);
    } catch (error) {
      if ((error as { code?: string }).code === '42501') denied = true;
      else throw error;
    }
    if (!denied)
      throw new Error('Runtime database role can mutate append-only history; refusing startup');
  }
}
