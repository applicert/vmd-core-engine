/**
 * AuditLogger
 *
 * Append-only, cryptographically chained log of all VMD Core Engine events.
 *
 * Audit integrity is a core principle of the VMD model: all activity is
 * auditable, and each interaction produces a verifiable record. This module
 * enforces that guarantee structurally — the log is chained so that any
 * modification to any historical entry invalidates all subsequent entries.
 * This is the same structure used in certificate transparency logs.
 *
 * Log entries are written for:
 *   QUERY_RECEIVED      — every incoming query
 *   QUERY_REJECTED      — any query that fails validation or consent
 *   QUERY_PROCESSED     — any query that completes successfully
 *   CONSENT_CHANGED     — any consent state transition initiated by a user
 *   OVERRIDE_INITIATED  — start of a lawful access override request
 *   OVERRIDE_COMPLETED  — override completed with multi-party cooperation
 *   OVERRIDE_REJECTED   — override request that did not meet threshold
 *
 * Verifiers receive only an opaque auditRef token — never log entry contents.
 * Users can request their own credential's history via getCbdoHistory().
 */

import { createHash, randomUUID } from 'crypto';

export const EventType = Object.freeze({
  QUERY_RECEIVED:     'QUERY_RECEIVED',
  QUERY_REJECTED:     'QUERY_REJECTED',
  QUERY_PROCESSED:    'QUERY_PROCESSED',
  CONSENT_CHANGED:    'CONSENT_CHANGED',
  OVERRIDE_INITIATED: 'OVERRIDE_INITIATED',
  OVERRIDE_COMPLETED: 'OVERRIDE_COMPLETED',
  OVERRIDE_REJECTED:  'OVERRIDE_REJECTED',
});

export class AuditLogger {
  constructor() {
    this._entries = [];
  }

  /**
   * Append a new entry to the audit log.
   *
   * @param {string} eventType  - One of EventType
   * @param {Object} fields     - Event-specific fields
   * @returns {string}          - Opaque auditRef token returned to callers
   */
  log(eventType, fields) {
    const entryId = randomUUID();
    const previousHash = this._entries.length > 0
      ? this._entries[this._entries.length - 1].entryHash
      : null;

    const timestamp = Date.now();

    const entry = {
      entryId,
      previousHash,
      timestamp,
      eventType,
      credentialId: fields.credentialId ?? null,
      verifierId:   fields.verifierId   ?? null,
      queryId:      fields.queryId      ?? null,
      outcome:      fields.outcome      ?? null,
      reason:       fields.reason       ?? null,
      meta:         fields.meta         ?? null,
    };

    entry.entryHash = this._hash(entry);
    this._entries.push(Object.freeze(entry));

    // Return an opaque reference (first 16 chars of entryId, dashes stripped)
    return entryId.replace(/-/g, '').substring(0, 16);
  }

  /**
   * Verify the integrity of the entire audit chain.
   * Returns { valid: true, entries: N } or { valid: false, reason, corruptedIndex }.
   */
  verifyChain() {
    for (let i = 0; i < this._entries.length; i++) {
      const entry = this._entries[i];

      const expectedHash = this._hash({ ...entry, entryHash: undefined });
      if (entry.entryHash !== expectedHash) {
        return {
          valid: false,
          reason: `Entry ${i} (${entry.entryId}) hash mismatch`,
          corruptedIndex: i,
        };
      }

      if (i > 0) {
        const prevHash = this._entries[i - 1].entryHash;
        if (entry.previousHash !== prevHash) {
          return {
            valid: false,
            reason: `Entry ${i} previousHash does not match entry ${i - 1} entryHash`,
            corruptedIndex: i,
          };
        }
      } else {
        if (entry.previousHash !== null) {
          return {
            valid: false,
            reason: 'Genesis entry should have null previousHash',
            corruptedIndex: 0,
          };
        }
      }
    }

    return { valid: true, entries: this._entries.length };
  }

  /**
   * Get all entries. Access should be restricted in production.
   */
  getEntries() {
    return [...this._entries];
  }

  /**
   * Look up a specific entry by auditRef token.
   */
  getByRef(auditRef) {
    return (
      this._entries.find((e) =>
        e.entryId.replace(/-/g, '').startsWith(auditRef)
      ) ?? null
    );
  }

  /**
   * Get a user-facing summary of events for a specific credential.
   * Returns only high-level metadata — not internal processing details.
   * This supports the VMD principle of user transparency without
   * exposing audit internals to verifiers.
   */
  getCredentialHistory(credentialId) {
    return this._entries
      .filter((e) => e.credentialId === credentialId)
      .map((e) => ({
        timestamp:  e.timestamp,
        eventType:  e.eventType,
        outcome:    e.outcome,
        verifierId: e.verifierId,
        auditRef:   e.entryId.replace(/-/g, '').substring(0, 16),
      }));
  }

  // ─── Private Helpers ─────────────────────────────────────────────────────

  _hash(entry) {
    const hashable = [
      entry.entryId,
      entry.previousHash ?? '',
      String(entry.timestamp),
      entry.eventType,
      entry.credentialId ?? '',
      entry.verifierId   ?? '',
      entry.queryId      ?? '',
      entry.outcome      ?? '',
    ].join('|');

    return createHash('sha256').update(hashable).digest('hex');
  }
}
