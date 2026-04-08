/**
 * CoreEngine
 *
 * The orchestrator of the VMD interaction pipeline.
 *
 * Verifiable Minimal Disclosure (VMD) defines an interaction pattern:
 *
 *   Query → Policy → Consent → Response
 *
 * External systems do not retrieve credential data. They submit constrained
 * queries. The Core Engine evaluates those queries against defined profile
 * rules, enforces user consent, processes the underlying data internally,
 * and returns only the minimal, verifiable result required.
 *
 * Pipeline (never skip or reorder steps):
 *
 *   1. RECEIVE  — log query receipt
 *   2. PROFILE  — load and verify the profile exists
 *   3. VALIDATE — check query against profile schema and rules
 *   4. CONSENT  — evaluate consent state for this (credential, verifier, queryType) triple
 *   5. EXECUTE  — process query against credential data INTERNALLY
 *   6. MINIMIZE — strip result to permitted fields only
 *   7. PROVE    — generate cryptographic proof for the minimized result
 *   8. LOG      — record the interaction in the audit trail
 *   9. RETURN   — send minimized result + proof to verifier
 *
 * Credential data is accessed ONLY in step 5, in memory, and never
 * appears in the output of any subsequent step.
 */

import { ProfileLoader } from './ProfileLoader.js';
import { QueryValidator } from './QueryValidator.js';
import { ConsentEngine } from './ConsentEngine.js';
import { ResponseMinimizer } from './ResponseMinimizer.js';
import { ProofGenerator } from './ProofGenerator.js';
import { AuditLogger, EventType } from './AuditLogger.js';

export class CoreEngine {
  /**
   * @param {Object} options
   * @param {import('./ProofGenerator.js').ProofGenerator} [options.proofGenerator]
   */
  constructor(options = {}) {
    this.profileLoader    = new ProfileLoader();
    this.queryValidator   = new QueryValidator(this.profileLoader);
    this.consentEngine    = new ConsentEngine();
    this.responseMinimizer = new ResponseMinimizer();
    this.proofGenerator   = options.proofGenerator ?? new ProofGenerator();
    this.auditLogger      = new AuditLogger();
  }

  /**
   * Load a VMD profile into the engine.
   * @param {Object} profileData
   */
  loadProfile(profileData) {
    return this.profileLoader.load(profileData);
  }

  /**
   * Process an incoming query through the full VMD pipeline.
   *
   * @param {Object} query          - Incoming query object
   * @param {string} profileId      - VMD profile to apply
   * @param {Object} credential     - W3C Verifiable Credential (never leaves engine)
   * @param {string} holderDID      - DID of the credential holder
   * @returns {Promise<Object>}     - Minimized response or rejection
   */
  async processQuery(query, profileId, credential, holderDID) {

    // ── Step 1: Log receipt ───────────────────────────────────────────────
    this.auditLogger.log(EventType.QUERY_RECEIVED, {
      credentialId: query.credentialId,
      verifierId:   query.verifierId,
      queryId:      query.queryId,
      outcome:      'RECEIVED',
    });

    // ── Step 2: Load profile ──────────────────────────────────────────────
    const profile = this.profileLoader.get(profileId);
    if (!profile) {
      const auditRef = this.auditLogger.log(EventType.QUERY_REJECTED, {
        credentialId: query.credentialId,
        verifierId:   query.verifierId,
        queryId:      query.queryId,
        outcome:      'REJECTED',
        reason:       'PROFILE_NOT_FOUND',
      });
      return this._rejection(query, 'PROFILE_NOT_FOUND', `No profile loaded: '${profileId}'`, auditRef);
    }

    // ── Step 3: Validate query against profile ────────────────────────────
    const validation = this.queryValidator.validate(query, profileId);
    if (!validation.valid) {
      const auditRef = this.auditLogger.log(EventType.QUERY_REJECTED, {
        credentialId: query.credentialId,
        verifierId:   query.verifierId,
        queryId:      query.queryId,
        outcome:      'REJECTED',
        reason:       validation.reason,
      });
      return this._rejection(query, validation.reason, validation.detail, auditRef);
    }

    const { queryDef } = validation;

    // ── Step 4: Evaluate consent ──────────────────────────────────────────
    // This is a structural gate. No credential data is accessed until
    // consent is confirmed GRANTED.
    const consentResult = this.consentEngine.evaluate(query, profile);
    if (!consentResult.consented) {
      const auditRef = this.auditLogger.log(EventType.QUERY_REJECTED, {
        credentialId: query.credentialId,
        verifierId:   query.verifierId,
        queryId:      query.queryId,
        outcome:      'REJECTED',
        reason:       `CONSENT_${consentResult.state}`,
      });
      return this._rejection(
        query,
        `CONSENT_${consentResult.state}`,
        `Consent is in state '${consentResult.state}'. Query cannot proceed.`,
        auditRef
      );
    }

    // ── Step 5: Execute query internally ─────────────────────────────────
    // This is the ONLY place credential field values are read.
    // The raw field value is used only to compute the boolean result —
    // it is never stored, logged, or returned.
    let rawResult;
    try {
      rawResult = this._executeQuery(query, queryDef, credential);
    } catch (err) {
      const auditRef = this.auditLogger.log(EventType.QUERY_REJECTED, {
        credentialId: query.credentialId,
        verifierId:   query.verifierId,
        queryId:      query.queryId,
        outcome:      'ERROR',
        reason:       'EXECUTION_ERROR',
      });
      return this._rejection(query, 'EXECUTION_ERROR', 'Query execution failed', auditRef);
    }

    // ── Step 6: Minimize response ─────────────────────────────────────────
    const minimized = this.responseMinimizer.minimize(
      {
        result:    rawResult.result,
        issuerId:  credential.issuer ?? credential.id,
        profileId,
        timestamp: Math.floor(Date.now() / 1000),
      },
      queryDef,
      profile
    );

    // ── Step 7: Generate proof ────────────────────────────────────────────
    const proof = await this.proofGenerator.generateProof(
      credential,
      query.queryType,
      query.parameters,
      minimized.result,
      holderDID
    );

    // ── Step 8: Log success ───────────────────────────────────────────────
    const auditRef = this.auditLogger.log(EventType.QUERY_PROCESSED, {
      credentialId: query.credentialId,
      verifierId:   query.verifierId,
      queryId:      query.queryId,
      outcome:      'SUCCESS',
    });

    // ── Step 9: Return minimized result + proof ───────────────────────────
    return {
      status:    'OK',
      queryId:   query.queryId,
      credentialId: query.credentialId,
      ...minimized,
      proof,
      auditRef,
    };
  }

  /**
   * Grant consent for a (credentialId, verifierId, queryType) triple.
   */
  grantConsent(credentialId, verifierId, queryType, userDID, profileId) {
    const profile = this.profileLoader.get(profileId);
    if (!profile) throw new Error(`Profile not found: ${profileId}`);

    const record = this.consentEngine.grant(
      credentialId, verifierId, queryType, userDID, profile.consentRules
    );

    this.auditLogger.log(EventType.CONSENT_CHANGED, {
      credentialId,
      verifierId,
      outcome: 'GRANTED',
      meta: { queryType, userDID },
    });

    return record;
  }

  /**
   * Revoke consent for a (credentialId, verifierId, queryType) triple.
   */
  revokeConsent(credentialId, verifierId, queryType, userDID) {
    const record = this.consentEngine.revoke(credentialId, verifierId, queryType, userDID);

    this.auditLogger.log(EventType.CONSENT_CHANGED, {
      credentialId,
      verifierId,
      outcome: 'REVOKED',
      meta: { queryType, userDID },
    });

    return record;
  }

  /**
   * Get the interaction history for a credential (for user transparency).
   */
  getCredentialHistory(credentialId) {
    return this.auditLogger.getCredentialHistory(credentialId);
  }

  /**
   * Verify audit log chain integrity.
   */
  verifyAuditChain() {
    return this.auditLogger.verifyChain();
  }

  // ─── Private: Query Execution ─────────────────────────────────────────────

  /**
   * Execute a query against credential data.
   *
   * IMPORTANT: This is the only method that accesses credential field values.
   * It returns only the computed result — the raw field value goes out of
   * scope at the end of the relevant sub-method and is never stored or returned.
   *
   * @returns {{ result: boolean }}
   */
  _executeQuery(query, queryDef, credential) {
    switch (query.queryType) {
      case 'AGE_THRESHOLD':
        return this._executeAgeThreshold(query.parameters, credential);
      default:
        throw new Error(`Unknown query type: ${query.queryType}`);
    }
  }

  _executeAgeThreshold(parameters, credential) {
    const { threshold } = parameters;
    const subject = credential.credentialSubject;

    if (!subject?.dateOfBirth) {
      throw new Error('Credential does not contain a dateOfBirth field');
    }

    const dob = new Date(subject.dateOfBirth);
    if (isNaN(dob.getTime())) {
      throw new Error('Invalid dateOfBirth format in credential');
    }

    // Compute the boolean result internally.
    // dateOfBirth and age go out of scope here — they are never stored,
    // logged, or returned. Only the boolean crosses this boundary.
    const today = new Date();
    let age = today.getFullYear() - dob.getFullYear();
    const monthDiff = today.getMonth() - dob.getMonth();
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < dob.getDate())) {
      age--;
    }

    return { result: age >= threshold };
  }

  // ─── Private: Response Helpers ────────────────────────────────────────────

  _rejection(query, reason, detail, auditRef) {
    return {
      status:       'REJECTED',
      queryId:      query.queryId,
      credentialId: query.credentialId,
      reason,
      detail,
      timestamp:    Math.floor(Date.now() / 1000),
      auditRef,
    };
  }
}
