import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { dirname, extname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { sql } from './client.js';

// Resolved relative to this source file. Always run via `pnpm db:migrate` (tsx),
// never from the compiled dist/ output — tsc does not copy .sql files.
const MIGRATIONS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), 'migrations');

async function bootstrap(): Promise<void> {
  await sql`
    create table if not exists schema_migrations (
      filename   text primary key,
      checksum   text not null,
      applied_at timestamptz not null default now()
    )
  `;
  await sql`alter table schema_migrations enable row level security`;
}

function checksum(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

interface MigrationRow {
  filename: string;
  checksum: string;
}

async function getApplied(): Promise<Map<string, string>> {
  const rows = await sql<MigrationRow[]>`
    select filename, checksum from schema_migrations order by filename
  `;
  return new Map(rows.map(r => [r.filename, r.checksum]));
}

async function runMigration(filename: string, content: string, hash: string): Promise<void> {
  await sql.begin(async tx => {
    await tx.unsafe(content);
    await tx`
      insert into schema_migrations (filename, checksum)
      values (${filename}, ${hash})
    `;
  });
}

async function main(): Promise<void> {
  await bootstrap();

  const applied = await getApplied();

  const files = (await readdir(MIGRATIONS_DIR))
    .filter(f => extname(f) === '.sql')
    .sort();

  let ran = 0;

  for (const filename of files) {
    const content = await readFile(resolve(MIGRATIONS_DIR, filename), 'utf8');
    const hash = checksum(content);

    if (applied.has(filename)) {
      if (applied.get(filename) !== hash) {
        throw new Error(
          `Checksum mismatch for already-applied migration "${filename}". ` +
          'Applied migrations must not be edited. Create a new migration instead.'
        );
      }
      console.log(`  skip  ${filename}`);
      continue;
    }

    console.log(`  apply ${filename}`);
    await runMigration(filename, content, hash);
    ran++;
  }

  console.log(ran > 0 ? `\n${ran} migration(s) applied.` : '\nNo new migrations.');
  await sql.end();
}

main().catch(err => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});