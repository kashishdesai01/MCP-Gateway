import { readFile, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';

const keysSchema = z
  .object({ master: z.string().regex(/^[a-f0-9]{64}$/), audit: z.string().regex(/^[a-f0-9]{64}$/) })
  .strict();
export async function localKeys(path: string) {
  try {
    return keysSchema.parse(JSON.parse(await readFile(path, 'utf8')));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  const keys = { master: randomBytes(32).toString('hex'), audit: randomBytes(32).toString('hex') };
  try {
    await writeFile(path, JSON.stringify(keys), { mode: 0o600, flag: 'wx' });
    return keys;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST')
      return keysSchema.parse(JSON.parse(await readFile(path, 'utf8')));
    throw error;
  }
}
