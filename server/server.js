let _schemaReady = null;

async function ensureSchema(db) {
  if (_schemaReady) return _schemaReady;
  _schemaReady = (async () => {
    await db.prepare(`PRAGMA foreign_keys = ON;`).run();

    // ---------- devices ----------
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS devices (
        uuid           TEXT PRIMARY KEY,
        name           TEXT NOT NULL,
        vendor         TEXT NOT NULL,
        driver_version TEXT,
        hash_rate      REAL NOT NULL DEFAULT 0,
        last_update    TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP)
      );
    `).run();

    // ---------- hits ----------
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS hits (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        device_uuid TEXT NOT NULL,
        address     TEXT NOT NULL,
        mnemonic    TEXT NOT NULL,
        "timestamp" TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP),
        FOREIGN KEY (device_uuid) REFERENCES devices(uuid)
          ON UPDATE CASCADE
          ON DELETE CASCADE
      );
    `).run();

    await db.prepare(`CREATE INDEX IF NOT EXISTS idx_hits_device_uuid ON hits(device_uuid);`).run();
    await db.prepare(`CREATE INDEX IF NOT EXISTS idx_hits_address     ON hits(address);`).run();
    await db.prepare(`CREATE INDEX IF NOT EXISTS idx_hits_timestamp   ON hits("timestamp");`).run();

    // ---------- stride (slots) ----------
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS stride (
        job_id         INTEGER PRIMARY KEY,
        state          TEXT,
        checkpoint_pos TEXT,
        updated_at     INTEGER,
        start_pos      TEXT,
        end_pos        TEXT,
        chunk_size     INTEGER
      );
    `).run();

    await db.prepare(`CREATE INDEX IF NOT EXISTS idx_stride_updated_at ON stride(updated_at);`).run();
    await db.prepare(`CREATE INDEX IF NOT EXISTS idx_stride_state      ON stride(state);`).run();
  })();
  return _schemaReady;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors() });
    }

    try {
      await ensureSchema(env.DB);

      // ===================== /api/devices =====================
      // GET /api/devices?minutes=15
      if (url.pathname === "/api/devices" && request.method === "GET") {
        const minutes = clampInt(url.searchParams.get("minutes") ?? url.searchParams.get("m"), 15, 1, 180);
        const modifier = `-${minutes} minutes`;

        const { results } = await env.DB.prepare(`
          SELECT uuid, name, vendor, driver_version, hash_rate, last_update
          FROM devices
          WHERE last_update >= datetime('now', ?1)
            AND hash_rate > 0
          ORDER BY last_update DESC
        `).bind(modifier).all();

        return j(results);
      }

      // ===================== /api/hits =====================
      // GET /api/hits?limit=500
      if (url.pathname === "/api/hits" && request.method === "GET") {
        const limit = clampInt(url.searchParams.get("limit") ?? url.searchParams.get("l"), 200, 1, 2000);

        const { results } = await env.DB.prepare(`
          SELECT
            h.id AS id,
            h.device_uuid AS device_uuid,
            COALESCE(d.name, 'Unknown') AS device_name,
            COALESCE(d.vendor, 'Unknown') AS vendor,
            COALESCE(d.driver_version, 'Unknown') AS driver_version,
            h.address AS address,
            h.mnemonic AS mnemonic,
            h."timestamp" AS "timestamp"
          FROM hits h
          LEFT JOIN devices d ON d.uuid = h.device_uuid
          ORDER BY h."timestamp" DESC
          LIMIT ?1
        `).bind(limit).all();

        return j(results);
      }

      // ===================== DELETE 1 HIT =====================
      // POST /api/hits/delete  { id: 123 }
      if (url.pathname === "/api/hits/delete" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const id = clampInt(body?.id, 0, 1, 1_000_000_000);
        if (!id) return j({ ok: false, error: "id required" }, 400);

        const r = await env.DB.prepare(`DELETE FROM hits WHERE id = ?1`).bind(id).run();
        return j({ ok: true, deleted: r?.meta?.changes ?? 0 });
      }

      // ===================== CLEAR HITS =====================
      // POST /api/hits/clear { all: true }
      if (url.pathname === "/api/hits/clear" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        if (!body?.all) return j({ ok: false, error: "send { all: true }" }, 400);

        const r = await env.DB.prepare(`DELETE FROM hits`).run();
        return j({ ok: true, deleted: r?.meta?.changes ?? 0, all: true });
      }

      // ===================== /register-device =====================
      if (url.pathname === "/register-device" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const uuid = body.uuid;
        const name = body.name ?? "Unknown";
        const vendor = body.vendor ?? "Unknown";
        const driver_version = body.driver_version ?? "Unknown";
        const hash_rate = Number(body.hash_rate ?? 0);

        if (!uuid) return new Response("Bad Request: uuid required", { status: 400, headers: cors() });

        await env.DB.prepare(`
          INSERT INTO devices (uuid, name, vendor, driver_version, hash_rate, last_update)
          VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)
          ON CONFLICT(uuid) DO UPDATE SET
            name = excluded.name,
            vendor = excluded.vendor,
            driver_version = excluded.driver_version,
            hash_rate = excluded.hash_rate,
            last_update = CURRENT_TIMESTAMP
        `).bind(uuid, name, vendor, driver_version, hash_rate).run();

        return j({ ok: true });
      }

      // ===================== /update-hashrate =====================
      if (url.pathname === "/update-hashrate" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const uuid = body.uuid;
        const hash_rate = Number(body.hash_rate);

        if (!uuid || !Number.isFinite(hash_rate))
          return new Response("Bad Request: uuid and hash_rate required", { status: 400, headers: cors() });

        await env.DB.prepare(`
          INSERT INTO devices (uuid, name, vendor, driver_version, hash_rate, last_update)
          VALUES (?1, 'Unknown', 'Unknown', 'Unknown', ?2, CURRENT_TIMESTAMP)
          ON CONFLICT(uuid) DO UPDATE SET
            hash_rate = excluded.hash_rate,
            last_update = CURRENT_TIMESTAMP
        `).bind(uuid, hash_rate).run();

        return j({ ok: true });
      }

      // ===================== /update-hashrates =====================
      if (url.pathname === "/update-hashrates" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const devices = body.devices;

        if (!Array.isArray(devices) || devices.length === 0)
          return new Response("Bad Request: { devices: [...] } expected", { status: 400, headers: cors() });

        const statements = devices
          .filter(d => d && d.uuid && Number.isFinite(Number(d.hash_rate)))
          .map(d =>
            env.DB.prepare(`
              INSERT INTO devices (uuid, name, vendor, driver_version, hash_rate, last_update)
              VALUES (?1, 'Unknown', 'Unknown', 'Unknown', ?2, CURRENT_TIMESTAMP)
              ON CONFLICT(uuid) DO UPDATE SET
                hash_rate = excluded.hash_rate,
                last_update = CURRENT_TIMESTAMP
            `).bind(d.uuid, Number(d.hash_rate))
          );

        if (statements.length === 0) return j({ ok: false, error: "no valid devices" }, 400);

        await env.DB.batch(statements);
        return j({ ok: true, updated: statements.length });
      }

      // ===================== /report-hit =====================
      if (url.pathname === "/report-hit" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const uuid = body.uuid;
        const address = body.address;
        const mnemonic = body.mnemonic;

        if (!uuid || !address || !mnemonic)
          return new Response("Bad Request: uuid, address and mnemonic required", { status: 400, headers: cors() });

        // garante device mínimo (não aparece em /api/devices porque hash_rate > 0)
        await env.DB.prepare(`
          INSERT INTO devices (uuid, name, vendor, driver_version, hash_rate, last_update)
          VALUES (?1, 'Unknown', 'Unknown', 'Unknown', 0, CURRENT_TIMESTAMP)
          ON CONFLICT(uuid) DO NOTHING
        `).bind(uuid).run();

        await env.DB.prepare(`
          INSERT INTO hits (device_uuid, address, mnemonic, "timestamp")
          VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP)
        `).bind(uuid, address, mnemonic).run();

        return j({ ok: true });
      }

      // ===================== /api/slot/upsert =====================
      if (request.method === "POST" && url.pathname === "/api/slot/upsert") {
        const body = await request.json().catch(() => null);
        if (!body || body.job_id == null) return j({ ok: false, error: "missing job_id" }, 400);

        const nowSec = Math.floor(Date.now() / 1000);

        const job_id = Number(body.job_id);
        const state = body.state ?? null;
        const checkpoint_pos = body.checkpoint_pos ?? null;
        const start_pos = body.start_pos ?? null;
        const end_pos = body.end_pos ?? null;
        const chunk_size = body.chunk_size ?? null;
        const updated_at = body.updated_at ?? nowSec;

        await env.DB.prepare(`
          INSERT INTO stride (job_id, state, checkpoint_pos, updated_at, start_pos, end_pos, chunk_size)
          VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
          ON CONFLICT(job_id) DO UPDATE SET
            state          = COALESCE(excluded.state, stride.state),
            checkpoint_pos = COALESCE(excluded.checkpoint_pos, stride.checkpoint_pos),
            updated_at     = COALESCE(excluded.updated_at, stride.updated_at),
            start_pos      = COALESCE(excluded.start_pos, stride.start_pos),
            end_pos        = COALESCE(excluded.end_pos, stride.end_pos),
            chunk_size     = COALESCE(excluded.chunk_size, stride.chunk_size);
        `).bind(job_id, state, checkpoint_pos, updated_at, start_pos, end_pos, chunk_size).run();

        return j({ ok: true, job_id, updated_at });
      }

      // ===================== /api/stride =====================
      if (url.pathname === "/api/stride" && request.method === "GET") {
        const { results } = await env.DB.prepare(`
          SELECT job_id, state, checkpoint_pos, updated_at, start_pos, end_pos, chunk_size
          FROM stride
          ORDER BY CAST(job_id AS INTEGER) ASC
        `).all();

        return j(results);
      }

      // ===================== /api/slot =====================
      // GET /api/slot?total=2252&prefer_active=1
      if (request.method === "GET" && url.pathname === "/api/slot") {
        const TOTAL_SLOTS = Number(url.searchParams.get("total") || 2252);
        const preferActive = (url.searchParams.get("prefer_active") || "1") !== "0";

        // 1) menor slot livre
        const freeRow = await env.DB.prepare(`
          WITH RECURSIVE seq(x) AS (
            SELECT 0
            UNION ALL
            SELECT x + 1 FROM seq WHERE x + 1 < ?1
          )
          SELECT x AS slot
          FROM seq
          LEFT JOIN stride s
            ON CAST(s.job_id AS INTEGER) = x
          WHERE s.job_id IS NULL
          ORDER BY x
          LIMIT 1;
        `).bind(TOTAL_SLOTS).first();

        if (freeRow && Number.isFinite(freeRow.slot)) {
          return j({
            ok: true,
            total_slots: TOTAL_SLOTS,
            mode: "free",
            job_id: freeRow.slot,
            checkpoint_pos: "0",
          });
        }

        // 2) sem slots livres -> reclaim do mais stale
        const reclaimSql = preferActive
          ? `
            SELECT
              CAST(job_id AS INTEGER) AS slot,
              state,
              updated_at,
              checkpoint_pos
            FROM stride
            WHERE COALESCE(LOWER(state),'') NOT IN ('done','finished','complete','completed','ok')
            ORDER BY
              CASE WHEN updated_at IS NULL THEN 0 ELSE 1 END,
              CAST(updated_at AS INTEGER) ASC
            LIMIT 1;
          `
          : `
            SELECT
              CAST(job_id AS INTEGER) AS slot,
              state,
              updated_at,
              checkpoint_pos
            FROM stride
            ORDER BY
              CASE WHEN updated_at IS NULL THEN 0 ELSE 1 END,
              CAST(updated_at AS INTEGER) ASC
            LIMIT 1;
          `;

        let stale = await env.DB.prepare(reclaimSql).first();

        // fallback: se tudo "done"
        if (!stale) {
          stale = await env.DB.prepare(`
            SELECT CAST(job_id AS INTEGER) AS slot, state, updated_at, checkpoint_pos
            FROM stride
            ORDER BY
              CASE WHEN updated_at IS NULL THEN 0 ELSE 1 END,
              CAST(updated_at AS INTEGER) ASC
            LIMIT 1;
          `).first();
        }

        const nowSec = Math.floor(Date.now() / 1000);
        const updatedAt = stale?.updated_at == null ? null : Number(stale.updated_at);
        const ageSec = updatedAt == null || !Number.isFinite(updatedAt) ? null : (nowSec - updatedAt);

        return j({
          ok: true,
          mode: "reclaim_stale",
          total_slots: TOTAL_SLOTS,
          job_id: stale?.slot ?? -1,
          state: stale?.state ?? null,
          updated_at: updatedAt ?? 0,
          stale_age_sec: ageSec ?? 0,
          checkpoint_pos: stale?.checkpoint_pos ?? 0,
        });
      }

      // Fallback: assets (se tiver)
      if (env.ASSETS?.fetch) return env.ASSETS.fetch(request);

      return new Response("Not Found", { status: 404, headers: cors() });
    } catch (e) {
      console.error(e);
      return new Response(`Error: ${e.message}`, { status: 500, headers: cors() });
    }
  },
};

function cors() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Auth-Token",
  };
}

function j(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { ...cors(), "content-type": "application/json; charset=utf-8" },
  });
}

function clampInt(v, def, lo, hi) {
  const n = parseInt(v ?? def, 10);
  if (!Number.isFinite(n)) return def;
  return Math.max(lo, Math.min(hi, n));
}
