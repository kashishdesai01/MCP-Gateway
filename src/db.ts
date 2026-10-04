import pg, { type PoolClient } from 'pg';
export type Tx = Pick<PoolClient, 'query'>;
export class Database {
  readonly pool: pg.Pool;
  constructor(url: string) {
    this.pool = new pg.Pool({
      connectionString: url,
      max: 12,
      connectionTimeoutMillis: 5000,
      statement_timeout: 10000,
    });
  }
  // The callback MUST contain only database work, never network side effects.
  async tx<T>(fn: (tx: Tx) => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      const client = await this.pool.connect();
      let retry = false;
      try {
        await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
        const result = await fn(client);
        await client.query('COMMIT');
        return result;
      } catch (error) {
        await client.query('ROLLBACK').catch(() => undefined);
        if ((error as { code?: string }).code !== '40001' || attempt >= 5) throw error;
        retry = true;
      } finally {
        client.release();
      }
      if (retry)
        await new Promise((resolve) =>
          setTimeout(resolve, Math.random() * Math.min(250, 10 * 2 ** attempt)),
        );
    }
  }
  async close() {
    await this.pool.end();
  }
}
