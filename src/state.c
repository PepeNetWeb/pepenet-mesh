// state.c — anchor-ordered per-key LWW state (see state.h for the model).
//
// The §2.2 cert machinery is ported byte-for-byte from the retired vpost
// carrier (pepenet-social impls/c/src/vpost_core.c) so certs minted before the
// migration keep verifying; the op envelope is NEW (SP_STATE_VER leads the
// preimage, so a state-op signature can never be replayed as a vpost entry or
// a chain structure, and vice versa).
#include "pepenet/state.h"
#include "pepenet/crypto.h"
#include "pepenet/wire.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ── low-S (§2.4 admission rule, same constant the carrier pinned) ────────────
static const uint8_t N_HALF[32] = {
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
};
static int be_cmp32(const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < 32; i++) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}
static int low_s(const uint8_t s32[32]) { return be_cmp32(s32, N_HALF) <= 0; }

// ── §2.2 / §2.2b certs (wire-identical port) ─────────────────────────────────
static int multisig_parse(const uint8_t *rs, int len, int *m_out, int *n_out,
                          const uint8_t **pubs) {
    if (len < 3) return 0;
    if (rs[len - 1] != 0xAE) return 0;                        // OP_CHECKMULTISIG
    if (rs[0] < 0x51 || rs[0] > 0x60) return 0;               // OP_1..OP_16
    int m = rs[0] - 0x50;
    int nb = rs[len - 2];
    if (nb < 0x51 || nb > 0x60) return 0;
    int n = nb - 0x50;
    int off = 1, cnt = 0;
    while (off < len - 2) {
        if (rs[off] != 0x21) return 0;                        // push exactly 33
        if (off + 1 + 33 > len - 2) return 0;
        if (cnt >= n) return 0;
        pubs[cnt++] = rs + off + 1;
        off += 1 + 33;
    }
    if (cnt != n || m < 1 || m > n) return 0;
    *m_out = m; *n_out = n;
    return 1;
}

static int multisig_verify(const uint8_t id32[32], const uint8_t *sigs, int sig_count,
                           int m, const uint8_t **pubs, int n) {
    if (sig_count != m) return 0;                             // threshold is exact
    int si = 0, pj = 0;
    while (si < m && pj < n) {
        const uint8_t *sig = sigs + si * 64;
        int ok = low_s(sig + 32) && sp_ecdsa_verify(id32, sig, pubs[pj], 33);
        if (ok) { si++; pj++; }
        else    { pj++; }
        if (m - si > n - pj) return 0;
    }
    return si == m;
}

int sp_cert_parse(int cert_type, const uint8_t *c, int len, SpCert *out) {
    memset(out, 0, sizeof *out);
    int off = 0; uint64_t v;
    if (off >= len || c[off++] != SP_CERT_VER) return 0;
    if (!sp_rvar(c, len, &off, &v) || v < 1 || v > SP_NAME_MAX) return 0;
    out->name = c + off; out->name_len = (int)v;
    if (off + (int)v > len) return 0; off += (int)v;
    if (cert_type == SP_CERT_P2PKH) {
        if (off + 33 > len) return 0; out->owner_key = c + off; off += 33;
    } else if (cert_type == SP_CERT_P2SH) {
        if (!sp_rvar(c, len, &off, &v) || v < 3 || v > 520) return 0;
        out->redeem = c + off; out->redeem_len = (int)v;
        if (off + (int)v > len) return 0; off += (int)v;
    } else return 0;
    if (off + 33 > len) return 0; out->posting_key = c + off; off += 33;
    if (!sp_rvar(c, len, &off, &out->scope)) return 0;
    if (off + 4 > len) return 0; out->not_after = sp_rle32(c + off); off += 4;
    sp_sha256(c, (size_t)off, out->cert_id);                  // preimage ends here
    if (cert_type == SP_CERT_P2PKH) {
        if (off + 64 > len) return 0;
        out->sigs = c + off; out->n_sigs = 1; off += 64;
    } else {
        if (!sp_rvar(c, len, &off, &v) || v < 1 || v > 16) return 0;
        out->sigs = c + off; out->n_sigs = (int)v;
        if (off + (int)v * 64 > len) return 0; off += (int)v * 64;
    }
    out->type = cert_type;
    out->wire_len = off;
    return 1;
}

int sp_cert_verify(const SpCert *ct, const uint8_t *name, int name_len,
                   const uint8_t posting_key[33], uint32_t height_anchor,
                   const uint8_t owner_h160[20]) {
    if (ct->name_len != name_len || memcmp(ct->name, name, (size_t)name_len) != 0) return 0;
    if (memcmp(ct->posting_key, posting_key, 33) != 0) return 0;
    if (!(height_anchor < ct->not_after)) return 0;
    if (ct->type == SP_CERT_P2PKH) {
        uint8_t h[20]; sp_hash160(ct->owner_key, 33, h);
        if (memcmp(h, owner_h160, 20) != 0) return 0;
        return low_s(ct->sigs + 32) &&
               sp_ecdsa_verify(ct->cert_id, ct->sigs, ct->owner_key, 33);
    }
    if (ct->type == SP_CERT_P2SH) {
        uint8_t h[20]; sp_hash160(ct->redeem, (size_t)ct->redeem_len, h);
        if (memcmp(h, owner_h160, 20) != 0) return 0;
        int m, n; const uint8_t *pubs[16];
        if (!multisig_parse(ct->redeem, ct->redeem_len, &m, &n, pubs)) return 0;
        return multisig_verify(ct->cert_id, ct->sigs, ct->n_sigs, m, pubs, n);
    }
    return 0;
}

int sp_cert_build_p2pkh(const uint8_t *name, int name_len,
                        const uint8_t owner_priv[32], const uint8_t posting_key[33],
                        uint64_t scope, uint32_t not_after,
                        uint8_t *out, int outmax) {
    if (name_len < 1 || name_len > SP_NAME_MAX) return -1;
    if (outmax < 1 + 3 + name_len + 33 + 33 + 10 + 4 + 64) return -1;
    uint8_t opub[33];
    if (!sp_pubkey(owner_priv, opub)) return -1;
    int n = 0;
    out[n++] = SP_CERT_VER;
    n += sp_wvar(out + n, (uint64_t)name_len); memcpy(out + n, name, (size_t)name_len); n += name_len;
    memcpy(out + n, opub, 33); n += 33;
    memcpy(out + n, posting_key, 33); n += 33;
    n += sp_wvar(out + n, scope);
    n += sp_wle32(out + n, not_after);
    uint8_t cert_id[32]; sp_sha256(out, (size_t)n, cert_id);
    uint8_t sig[64];
    if (!sp_ecdsa_sign(owner_priv, cert_id, sig)) return -1;  // libsecp → low-S
    memcpy(out + n, sig, 64); n += 64;
    return n;
}

// ── op codec ─────────────────────────────────────────────────────────────────
int sp_state_op_build(uint8_t op, const char *name,
                      const uint8_t *key, int key_len,
                      const uint8_t *payload, int payload_len,
                      uint32_t anchor, const uint8_t anchor_hash[32],
                      const uint8_t priv[32], const uint8_t pub33[33],
                      int cert_type, const uint8_t *cert, int cert_len,
                      uint8_t *out, int outmax) {
    size_t nlen = name ? strlen(name) : 0;
    if (!sp_name_valid(name, nlen)) return -1;
    if (op == SP_OP_PUT) { if (key_len < 1 || payload_len < 1) return -1; }
    else if (op == SP_OP_DEL) { if (key_len < 1 || payload_len != 0) return -1; }
    else if (op == SP_OP_CLEAR) { if (key_len != 0 || payload_len != 0) return -1; }
    else return -1;
    if (key_len > SP_STATE_KEY_MAX) return -1;
    if (cert_type != SP_CERT_NONE && (!cert || cert_len < 1)) return -1;
    int need = 1 + 1 + 3 + (int)nlen + 3 + key_len + 4 + 32 + 5 + payload_len
             + 1 + (cert_type != SP_CERT_NONE ? cert_len : 0) + 33 + 64;
    if (outmax < need || need > SP_STATE_OP_MAX) return -1;
    int n = 0;
    out[n++] = SP_STATE_VER;
    out[n++] = op;
    n += sp_wvar(out + n, (uint64_t)nlen); memcpy(out + n, name, nlen); n += (int)nlen;
    n += sp_wvar(out + n, (uint64_t)key_len);
    if (key_len) { memcpy(out + n, key, (size_t)key_len); n += key_len; }
    n += sp_wle32(out + n, anchor);
    memcpy(out + n, anchor_hash, 32); n += 32;
    n += sp_wvar(out + n, (uint64_t)payload_len);
    if (payload_len) { memcpy(out + n, payload, (size_t)payload_len); n += payload_len; }
    out[n++] = (uint8_t)cert_type;
    if (cert_type != SP_CERT_NONE) { memcpy(out + n, cert, (size_t)cert_len); n += cert_len; }
    memcpy(out + n, pub33, 33); n += 33;
    uint8_t id[32]; sp_sha256(out, (size_t)n, id);            // preimage ends here
    uint8_t sig[64];
    if (!sp_ecdsa_sign(priv, id, sig)) return -1;
    memcpy(out + n, sig, 64); n += 64;
    return n;
}

int sp_state_op_parse(const uint8_t *e, int len, SpStateOp *out) {
    memset(out, 0, sizeof *out);
    if (len < 2 || len > SP_STATE_OP_MAX || e[0] != SP_STATE_VER) return 0;
    out->op = e[1];
    if (out->op < SP_OP_PUT || out->op > SP_OP_CLEAR) return 0;
    int off = 2; uint64_t v;
    if (!sp_rvar(e, len, &off, &v) || v < 1 || v > SP_NAME_MAX) return 0;
    out->name = e + off; out->name_len = (int)v;
    if (off + (int)v > len) return 0; off += (int)v;
    if (!sp_rvar(e, len, &off, &v) || v > SP_STATE_KEY_MAX) return 0;
    out->key = v ? e + off : NULL; out->key_len = (int)v;
    if (off + (int)v > len) return 0; off += (int)v;
    if (off + 4 + 32 > len) return 0;
    out->anchor = sp_rle32(e + off); off += 4;
    out->anchor_hash = e + off; off += 32;
    if (!sp_rvar(e, len, &off, &v) || off + (int)v > len) return 0;
    out->payload = v ? e + off : NULL; out->payload_len = (int)v;
    off += (int)v;
    if (off >= len) return 0;
    out->has_cert = e[off++];
    if (out->has_cert != SP_CERT_NONE) {
        if (!sp_cert_parse(out->has_cert, e + off, len - off, &out->cert)) return 0;
        off += out->cert.wire_len;
    }
    if (off + 33 + 64 != len) return 0;                       // exactly signer+sig left
    out->signer = e + off; off += 33;
    sp_sha256(e, (size_t)off, out->op_id);                    // preimage ends here
    out->sig = e + off; off += 64;
    // shape rules mirror the builder
    if (out->op == SP_OP_PUT   && (out->key_len < 1 || out->payload_len < 1)) return 0;
    if (out->op == SP_OP_DEL   && (out->key_len < 1 || out->payload_len != 0)) return 0;
    if (out->op == SP_OP_CLEAR && (out->key_len != 0 || out->payload_len != 0)) return 0;
    out->wire_len = off;
    return 1;
}

// ── store ────────────────────────────────────────────────────────────────────
struct SpState { sqlite3 *db; };

static const char *SCHEMA =
    "PRAGMA journal_mode=WAL;"
    "CREATE TABLE IF NOT EXISTS st_rows("
    "  name TEXT NOT NULL, key BLOB NOT NULL, op INTEGER, anchor INTEGER,"
    "  op_id BLOB, blob BLOB, PRIMARY KEY(name, key));"
    "CREATE TABLE IF NOT EXISTS st_names("
    "  name TEXT PRIMARY KEY, owner BLOB, floor INTEGER, sum_bytes INTEGER,"
    "  clear_id BLOB, clear_blob BLOB);";

SpState *sp_state_open(const char *path) {
    SpState *s = calloc(1, sizeof *s);
    if (sqlite3_open(path, &s->db) != SQLITE_OK) {
        fprintf(stderr, "state: cannot open %s: %s\n", path, sqlite3_errmsg(s->db));
        sqlite3_close(s->db); free(s); return NULL;
    }
    sqlite3_busy_timeout(s->db, 5000);
    char *errmsg = NULL;
    if (sqlite3_exec(s->db, SCHEMA, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "state: schema: %s\n", errmsg ? errmsg : "?");
        sqlite3_free(errmsg); sqlite3_close(s->db); free(s); return NULL;
    }
    return s;
}

void sp_state_close(SpState *s) { if (s) { sqlite3_close(s->db); free(s); } }

typedef struct {                                              // st_names row
    int      present;
    uint8_t  owner[20];
    uint32_t floor;
    int64_t  sum;
} NameMeta;

static void meta_get(SpState *s, const uint8_t *name, int nlen, NameMeta *m) {
    memset(m, 0, sizeof *m);
    sqlite3_stmt *st;
    sqlite3_prepare_v2(s->db, "SELECT owner,floor,sum_bytes FROM st_names WHERE name=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, (const char *)name, nlen, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        m->present = 1;
        if (sqlite3_column_bytes(st, 0) == 20) memcpy(m->owner, sqlite3_column_blob(st, 0), 20);
        m->floor = (uint32_t)sqlite3_column_int64(st, 1);
        m->sum   = sqlite3_column_int64(st, 2);
    }
    sqlite3_finalize(st);
}

static void meta_put(SpState *s, const uint8_t *name, int nlen, const NameMeta *m,
                     const uint8_t *clear_id, const uint8_t *clear_blob, int clear_len) {
    sqlite3_stmt *st;
    if (clear_blob) {
        sqlite3_prepare_v2(s->db,
            "INSERT INTO st_names(name,owner,floor,sum_bytes,clear_id,clear_blob) VALUES(?,?,?,?,?,?)"
            " ON CONFLICT(name) DO UPDATE SET owner=excluded.owner,floor=excluded.floor,"
            " sum_bytes=excluded.sum_bytes,clear_id=excluded.clear_id,clear_blob=excluded.clear_blob",
            -1, &st, NULL);
        sqlite3_bind_blob(st, 5, clear_id, 32, SQLITE_STATIC);
        sqlite3_bind_blob(st, 6, clear_blob, clear_len, SQLITE_STATIC);
    } else {
        sqlite3_prepare_v2(s->db,
            "INSERT INTO st_names(name,owner,floor,sum_bytes) VALUES(?,?,?,?)"
            " ON CONFLICT(name) DO UPDATE SET owner=excluded.owner,floor=excluded.floor,"
            " sum_bytes=excluded.sum_bytes",
            -1, &st, NULL);
    }
    sqlite3_bind_text (st, 1, (const char *)name, nlen, SQLITE_STATIC);
    sqlite3_bind_blob (st, 2, m->owner, 20, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, (int64_t)m->floor);
    sqlite3_bind_int64(st, 4, m->sum);
    sqlite3_step(st); sqlite3_finalize(st);
}

static void rows_wipe(SpState *s, const uint8_t *name, int nlen) {
    sqlite3_stmt *st;
    sqlite3_prepare_v2(s->db, "DELETE FROM st_rows WHERE name=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, (const char *)name, nlen, SQLITE_STATIC);
    sqlite3_step(st); sqlite3_finalize(st);
}

static int fail(char *err, int errlen, const char *m) {
    if (err && errlen > 0) snprintf(err, (size_t)errlen, "%s", m);
    return 0;
}

int sp_state_admit(SpState *s, const SpChainOracle *o,
                   int64_t budget, uint64_t scope,
                   const uint8_t *e, int len, char *err, int errlen) {
    SpStateOp p;
    if (!sp_state_op_parse(e, len, &p)) return fail(err, errlen, "malformed op");
    if (!sp_name_valid((const char *)p.name, (size_t)p.name_len))
        return fail(err, errlen, "invalid name (§3.1)");
    char name[SP_NAME_MAX + 1];
    memcpy(name, p.name, (size_t)p.name_len); name[p.name_len] = '\0';

    // ownership: ops verify against the CURRENT owner (lease-gated by the
    // oracle) — a lapsed name admits nothing (the sweep drops its rows), a
    // transferred name starts an epoch.
    uint8_t owner[20];
    if (!o->owner_now(o->u, name, owner))
        return fail(err, errlen, "name unowned");

    // signature (low-S over op_id) + authority (owner key, or §2.2 cert with
    // the overlay's scope bit, minted by the owner, live at this op's anchor)
    if (!low_s(p.sig + 32)) return fail(err, errlen, "high-S signature");
    if (!sp_ecdsa_verify(p.op_id, p.sig, p.signer, 33))
        return fail(err, errlen, "signature invalid");
    if (p.has_cert != SP_CERT_NONE) {
        if (!(p.cert.scope & scope)) return fail(err, errlen, "cert lacks scope");
        if (!sp_cert_verify(&p.cert, p.name, p.name_len, p.signer, p.anchor, owner))
            return fail(err, errlen, "delegation cert invalid");
    } else if (!sp_key_is_owner(p.signer, 33, owner)) {
        return fail(err, errlen, "signer is not the owner");
    }

    // anchor: 1 ⇒ compare against the header we hold (mismatch = stale branch
    // or forgery ⇒ reject); 0 ⇒ the publisher is ahead of us ⇒ hold; -1 ⇒ the
    // height is below our horizon ⇒ admit on the signature alone.
    uint8_t hh[32];
    int ha = o->header_at(o->u, p.anchor, hh);
    if (ha == 0) { fail(err, errlen, "anchor ahead of tip"); return -2; }
    if (ha > 0 && memcmp(hh, p.anchor_hash, 32) != 0)
        return fail(err, errlen, "anchor hash not on our chain");

    // epoch pin: owner changed ⇒ held rows are a prior epoch. Wipe, and raise
    // the floor to tip−REORG so the prior epoch cannot replay (fresh ops anchor
    // at tip−REORG, so the new owner is never blocked by this).
    NameMeta m; meta_get(s, p.name, p.name_len, &m);
    if (m.present && memcmp(m.owner, owner, 20) != 0) {
        rows_wipe(s, p.name, p.name_len);
        uint32_t tip = o->tip(o->u);
        m.floor = tip > SP_STATE_REORG ? tip - SP_STATE_REORG : 0;
        m.sum = 0;
        memcpy(m.owner, owner, 20);
        meta_put(s, p.name, p.name_len, &m, NULL, NULL, 0);   // clears clear_blob? no — keep schema simple:
        // a prior epoch's clear is void with its rows; drop it explicitly.
        sqlite3_stmt *st;
        sqlite3_prepare_v2(s->db, "UPDATE st_names SET clear_id=NULL,clear_blob=NULL WHERE name=?", -1, &st, NULL);
        sqlite3_bind_text(st, 1, (const char *)p.name, p.name_len, SQLITE_STATIC);
        sqlite3_step(st); sqlite3_finalize(st);
    }
    if (!m.present) memcpy(m.owner, owner, 20);

    if (p.op == SP_OP_CLEAR) {
        sqlite3_stmt *st;
        sqlite3_prepare_v2(s->db, "SELECT clear_id FROM st_names WHERE name=?", -1, &st, NULL);
        sqlite3_bind_text(st, 1, (const char *)p.name, p.name_len, SQLITE_STATIC);
        int dup = sqlite3_step(st) == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 32
               && memcmp(sqlite3_column_blob(st, 0), p.op_id, 32) == 0;
        sqlite3_finalize(st);
        if (dup) return -1;
        if (m.present && m.floor > 0 && p.anchor <= m.floor)
            return fail(err, errlen, "clear at or below floor");
        // void everything anchored below the new floor; survivors keep their bytes
        sqlite3_prepare_v2(s->db, "DELETE FROM st_rows WHERE name=? AND anchor<?", -1, &st, NULL);
        sqlite3_bind_text (st, 1, (const char *)p.name, p.name_len, SQLITE_STATIC);
        sqlite3_bind_int64(st, 2, (int64_t)p.anchor);
        sqlite3_step(st); sqlite3_finalize(st);
        sqlite3_prepare_v2(s->db, "SELECT COALESCE(SUM(LENGTH(blob)),0) FROM st_rows WHERE name=?", -1, &st, NULL);
        sqlite3_bind_text(st, 1, (const char *)p.name, p.name_len, SQLITE_STATIC);
        int64_t survivors = sqlite3_step(st) == SQLITE_ROW ? sqlite3_column_int64(st, 0) : 0;
        sqlite3_finalize(st);
        if (survivors + len > budget) return fail(err, errlen, "per-name budget");
        m.floor = p.anchor;
        m.sum = survivors + len;
        meta_put(s, p.name, p.name_len, &m, p.op_id, e, len);
        return 1;
    }

    // PUT / DEL — one row per key, strictly-higher anchor wins
    if (p.anchor < m.floor) return fail(err, errlen, "anchor below floor");
    sqlite3_stmt *st;
    sqlite3_prepare_v2(s->db, "SELECT anchor,op_id,LENGTH(blob) FROM st_rows WHERE name=? AND key=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, (const char *)p.name, p.name_len, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, p.key, p.key_len, SQLITE_STATIC);
    int64_t held_anchor = -1, held_len = 0; int dup = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        held_anchor = sqlite3_column_int64(st, 0);
        dup = sqlite3_column_bytes(st, 1) == 32 && memcmp(sqlite3_column_blob(st, 1), p.op_id, 32) == 0;
        held_len = sqlite3_column_int64(st, 2);
    }
    sqlite3_finalize(st);
    if (dup) return -1;
    if ((int64_t)p.anchor <= held_anchor)
        return fail(err, errlen, "anchor does not raise the key (rate limit)");
    if (m.sum - held_len + len > budget) return fail(err, errlen, "per-name budget");

    sqlite3_prepare_v2(s->db,
        "INSERT OR REPLACE INTO st_rows(name,key,op,anchor,op_id,blob) VALUES(?,?,?,?,?,?)",
        -1, &st, NULL);
    sqlite3_bind_text (st, 1, (const char *)p.name, p.name_len, SQLITE_STATIC);
    sqlite3_bind_blob (st, 2, p.key, p.key_len, SQLITE_STATIC);
    sqlite3_bind_int  (st, 3, p.op);
    sqlite3_bind_int64(st, 4, (int64_t)p.anchor);
    sqlite3_bind_blob (st, 5, p.op_id, 32, SQLITE_STATIC);
    sqlite3_bind_blob (st, 6, e, len, SQLITE_STATIC);
    sqlite3_step(st); sqlite3_finalize(st);
    m.sum = m.sum - held_len + len;
    meta_put(s, p.name, p.name_len, &m, NULL, NULL, 0);
    return 1;
}

// ── reads ────────────────────────────────────────────────────────────────────
int sp_state_get(SpState *s, const char *name, const uint8_t *key, int key_len,
                 uint8_t **blob, int *blen) {
    sqlite3_stmt *st; int found = 0;
    sqlite3_prepare_v2(s->db, "SELECT blob FROM st_rows WHERE name=? AND key=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, key, key_len, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        int n = sqlite3_column_bytes(st, 0);
        if (blob) { *blob = malloc((size_t)n); memcpy(*blob, sqlite3_column_blob(st, 0), (size_t)n); }
        if (blen) *blen = n;
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

int sp_state_iter(SpState *s, const char *name,
                  int (*cb)(void *u, const uint8_t *key, int key_len, int op,
                            uint32_t anchor, const uint8_t *blob, int blen),
                  void *u) {
    sqlite3_stmt *st; int n = 0;
    sqlite3_prepare_v2(s->db,
        "SELECT key,op,anchor,blob FROM st_rows WHERE name=? ORDER BY key", -1, &st, NULL);
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (!cb(u, sqlite3_column_blob(st, 0), sqlite3_column_bytes(st, 0),
                sqlite3_column_int(st, 1), (uint32_t)sqlite3_column_int64(st, 2),
                sqlite3_column_blob(st, 3), sqlite3_column_bytes(st, 3))) break;
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

int64_t sp_state_sum(SpState *s, const char *name) {
    sqlite3_stmt *st; int64_t sum = 0;
    sqlite3_prepare_v2(s->db, "SELECT sum_bytes FROM st_names WHERE name=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) sum = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return sum;
}

uint32_t sp_state_floor(SpState *s, const char *name) {
    sqlite3_stmt *st; uint32_t f = 0;
    sqlite3_prepare_v2(s->db, "SELECT floor FROM st_names WHERE name=?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) f = (uint32_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return f;
}

int sp_state_clear_get(SpState *s, const char *name, uint8_t **blob, int *blen) {
    sqlite3_stmt *st; int found = 0;
    sqlite3_prepare_v2(s->db, "SELECT clear_blob FROM st_names WHERE name=? AND clear_blob IS NOT NULL",
                       -1, &st, NULL);
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        int n = sqlite3_column_bytes(st, 0);
        if (blob) { *blob = malloc((size_t)n); memcpy(*blob, sqlite3_column_blob(st, 0), (size_t)n); }
        if (blen) *blen = n;
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

int sp_state_names(SpState *s, int (*cb)(void *u, const char *name), void *u) {
    sqlite3_stmt *st; int n = 0;
    sqlite3_prepare_v2(s->db, "SELECT name FROM st_names ORDER BY name", -1, &st, NULL);
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (!cb(u, (const char *)sqlite3_column_text(st, 0))) break;
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

void sp_state_drop_name(SpState *s, const char *name) {
    static const char *Q[2] = { "DELETE FROM st_rows WHERE name=?",
                                "DELETE FROM st_names WHERE name=?" };
    for (int i = 0; i < 2; i++) {
        sqlite3_stmt *st;
        sqlite3_prepare_v2(s->db, Q[i], -1, &st, NULL);
        sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
        sqlite3_step(st); sqlite3_finalize(st);
    }
}
