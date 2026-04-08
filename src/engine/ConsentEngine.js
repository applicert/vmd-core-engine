/**
 * ConsentEngine
 *
 * State machine governing consent for (credentialId, verifierId, queryType) triples.
 *
 * In the VMD model, no query proceeds without passing user-defined consent checks.
 * Consent is not an afterthought — it is a structural gate in the
 * Query → Policy → Consent → Response pipeline. This module enforces that gate.
 *
 * Consent states:
 *
 *   UNKNOWN  — No consent record exists for this triple
 *   PENDING  — Consent has been requested; awaiting user action
 *   GRANTED  — Consent is active and within its expiry window
 *   DENIED   — User has explicitly denied consent
 *   EXPIRED  — A previously granted consent has elapsed
 *   REVOKED  — User has explicitly revoked a previously granted consent
 *
 * State transitions:
 *
 *   UNKNOWN  → PENDING   : query arrives, requireExplicitConsent = true
 *   UNKNOWN  → GRANTED   : query arrives, defaultConsent = true
 *   PENDING  → GRANTED   : user approves
 *   PENDING  → DENIED    : user denies
 *   GRANTED  → EXPIRED   : consentExpiry elapsed
 *   GRANTED  → REVOKED   : user revokes
 *   EXPIRED  → PENDING   : new query arrives, renewalPolicy = prompt
 *   EXPIRED  → GRANTED   : renewalPolicy = automatic
 *   DENIED   → PENDING   : new request after cooling-off
 *   REVOKED  → PENDING   : new request (explicit re-consent required)
 *
 * No credential data is accessed in this module.
 */

export const ConsentState = Object.freeze({
  UNKNOWN:  'UNKNOWN',
  PENDING:  'PENDING',
  GRANTED:  'GRANTED',
  DENIED:   'DENIED',
  EXPIRED:  'EXPIRED',
  REVOKED:  'REVOKED',
});

export class ConsentEngine {
  constructor() {
    // Map<consentKey, ConsentRecord>
    // key = `${credentialId}::${verifierId}::${queryType}`
    this._records = new Map();
  }

  /**
   * Evaluate whether a query may proceed based on consent state.
   * Applies expiry and renewal policy, mutating state as needed.
   *
   * @param {Object} query
   * @param {Object} profile
   * @returns {{ consented: boolean, state: string, record: Object }}
   */
  evaluate(query, profile) {
    const { credentialId, verifierId, queryType } = query;
    const consentRules = profile.consentRules;
    const key = this._key(credentialId, verifierId, queryType);

    let record = this._records.get(key);

    if (!record) {
      if (consentRules.defaultConsent) {
        record = this._createRecord(credentialId, verifierId, queryType, ConsentState.GRANTED);
        this._addHistory(record, 'UNKNOWN→GRANTED', 'system', 'defaultConsent=true');
      } else if (consentRules.requireExplicitConsent) {
        record = this._createRecord(credentialId, verifierId, queryType, ConsentState.PENDING);
        this._addHistory(record, 'UNKNOWN→PENDING', 'system', 'requireExplicitConsent=true');
      } else {
        record = this._createRecord(credentialId, verifierId, queryType, ConsentState.GRANTED);
        this._addHistory(record, 'UNKNOWN→GRANTED', 'system', 'implicit consent');
      }
      this._records.set(key, record);
    }

    // Check expiry on GRANTED records
    if (record.state === ConsentState.GRANTED && record.expiresAt !== null) {
      if (Date.now() / 1000 > record.expiresAt) {
        const prevState = record.state;
        record.state = ConsentState.EXPIRED;
        this._addHistory(record, `${prevState}→EXPIRED`, 'system', 'consent expiry elapsed');

        if (consentRules.renewalPolicy === 'automatic') {
          record.state = ConsentState.GRANTED;
          record.grantedAt = Math.floor(Date.now() / 1000);
          record.expiresAt = record.grantedAt + consentRules.consentExpiry;
          this._addHistory(record, 'EXPIRED→GRANTED', 'system', 'renewalPolicy=automatic');
        } else {
          record.state = ConsentState.PENDING;
          this._addHistory(record, 'EXPIRED→PENDING', 'system', `renewalPolicy=${consentRules.renewalPolicy}`);
        }
      }
    }

    const consented = record.state === ConsentState.GRANTED;
    return { consented, state: record.state, record: { ...record } };
  }

  /**
   * Grant consent. Called when the user approves a consent request.
   */
  grant(credentialId, verifierId, queryType, userDID, consentRules) {
    const key = this._key(credentialId, verifierId, queryType);
    let record = this._records.get(key);

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = consentRules.consentExpiry > 0
      ? now + consentRules.consentExpiry
      : null;

    if (!record) {
      record = this._createRecord(credentialId, verifierId, queryType, ConsentState.PENDING);
      this._records.set(key, record);
    }

    const prevState = record.state;
    record.state = ConsentState.GRANTED;
    record.grantedAt = now;
    record.expiresAt = expiresAt;
    record.grantedBy = userDID;
    this._addHistory(record, `${prevState}→GRANTED`, 'user', `grantedBy=${userDID}`);

    return { ...record };
  }

  /**
   * Deny consent.
   */
  deny(credentialId, verifierId, queryType, userDID) {
    const key = this._key(credentialId, verifierId, queryType);
    let record = this._records.get(key);

    if (!record) {
      record = this._createRecord(credentialId, verifierId, queryType, ConsentState.PENDING);
      this._records.set(key, record);
    }

    const prevState = record.state;
    record.state = ConsentState.DENIED;
    this._addHistory(record, `${prevState}→DENIED`, 'user', `deniedBy=${userDID}`);

    return { ...record };
  }

  /**
   * Revoke a previously granted consent.
   */
  revoke(credentialId, verifierId, queryType, userDID) {
    const key = this._key(credentialId, verifierId, queryType);
    const record = this._records.get(key);

    if (!record || record.state !== ConsentState.GRANTED) {
      throw new ConsentError('Cannot revoke consent that is not in GRANTED state');
    }

    const prevState = record.state;
    record.state = ConsentState.REVOKED;
    this._addHistory(record, `${prevState}→REVOKED`, 'user', `revokedBy=${userDID}`);

    return { ...record };
  }

  /**
   * Get the current consent record for a triple.
   */
  getRecord(credentialId, verifierId, queryType) {
    return this._records.get(this._key(credentialId, verifierId, queryType)) ?? null;
  }

  // ─── Private Helpers ─────────────────────────────────────────────────────

  _key(credentialId, verifierId, queryType) {
    return `${credentialId}::${verifierId}::${queryType}`;
  }

  _createRecord(credentialId, verifierId, queryType, initialState) {
    return {
      credentialId,
      verifierId,
      queryType,
      state: initialState,
      grantedAt: null,
      expiresAt: null,
      grantedBy: null,
      history: [],
    };
  }

  _addHistory(record, transition, actor, reason = '') {
    record.history.push({
      transition,
      timestamp: Math.floor(Date.now() / 1000),
      actor,
      reason,
    });
  }
}

export class ConsentError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConsentError';
  }
}
