/**
 * ResponseMinimizer
 *
 * Enforces data minimization on all outgoing responses.
 *
 * Data minimization is a core principle of the VMD model: only the necessary
 * answer is returned — never the underlying dataset. This module is the final
 * gate before any result leaves the Core Engine. It is not advisory — it
 * actively strips, validates, and aborts if prohibited data is detected.
 *
 * Rules applied (per VMD spec section 7.1):
 *
 * 1. Field whitelist     — only allowedResponseFields may be present
 * 2. Prohibited removal  — prohibitedFields are stripped unconditionally
 * 3. Raw value guard     — for boolean queries, any value derivable from the
 *                          underlying credential field triggers a hard abort
 * 4. Metadata stripping  — internal processing fields are never forwarded
 * 5. Field count cap     — maxResponseFields limit is enforced
 *
 * The whitelist is built from the profile definition, not inferred —
 * this ensures the profile remains the authoritative policy contract.
 */

export class ResponseMinimizer {
  /**
   * Minimize a result before it leaves the Core Engine.
   *
   * @param {Object} rawResult     - Internal result object
   * @param {Object} queryDef      - Query definition from the profile
   * @param {Object} profile       - Full profile
   * @returns {Object}             - Minimized, safe response object
   * @throws {MinimizationError}   - If prohibited data is detected
   */
  minimize(rawResult, queryDef, profile) {
    const allowedFields = new Set(queryDef.allowedResponseFields ?? []);
    const prohibitedFields = new Set(profile.dataMinimization?.prohibitedFields ?? []);
    const maxFields = profile.dataMinimization?.maxResponseFields ?? Infinity;

    // Build output from the whitelist only — never spread rawResult
    const output = {};

    for (const field of allowedFields) {
      if (prohibitedFields.has(field)) continue;
      if (rawResult[field] !== undefined) {
        output[field] = rawResult[field];
      }
      if (Object.keys(output).length >= maxFields) break;
    }

    // Safety net: verify no prohibited field leaked through
    for (const field of prohibitedFields) {
      if (field in output) {
        delete output[field];
        console.error(
          `[ResponseMinimizer] CRITICAL: prohibited field '${field}' found in output and removed. ` +
          `This is a bug — please report it.`
        );
      }
    }

    // For boolean response types, perform an additional guard against
    // any value that could reveal the underlying credential data
    if (queryDef.responseType === 'boolean') {
      this._assertBooleanSafety(output, queryDef);
    }

    return output;
  }

  /**
   * Assert that a boolean response contains no credential-derived data.
   *
   * In the VMD model, a boolean query response must carry exactly one bit
   * of information about the credential: true or false. Any date-like or
   * age-like value in the output indicates a data leak and is a hard error.
   */
  _assertBooleanSafety(output, queryDef) {
    for (const [key, value] of Object.entries(output)) {
      // Detect date strings (YYYY-MM-DD or similar)
      if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}/.test(value)) {
        throw new MinimizationError(
          `ResponseMinimizer: date-like value detected in field '${key}'. ` +
          `A credential field value may have leaked into the response. Aborting.`
        );
      }

      // Detect year-like or age-like numbers
      if (typeof value === 'number' && key !== 'timestamp') {
        if (value >= 1900 && value <= 2100) {
          throw new MinimizationError(
            `ResponseMinimizer: year-range numeric value ${value} in field '${key}'. ` +
            `This may be a credential-derived value. Aborting.`
          );
        }
        if (value >= 0 && value <= 150 && !['threshold'].includes(key)) {
          throw new MinimizationError(
            `ResponseMinimizer: age-range numeric value ${value} in field '${key}'. ` +
            `This may be a credential-derived value. Aborting.`
          );
        }
      }
    }
  }
}

export class MinimizationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'MinimizationError';
  }
}
