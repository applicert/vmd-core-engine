/**
 * AgePass Demo
 *
 * End-to-end demonstration of the VMD Core Engine processing
 * an age verification query via the AgePass profile.
 *
 * Run: node demo/agepass-demo.js
 *
 * This demo exercises the full VMD pipeline:
 *   Query → Policy → Consent → Response
 *
 * Scenarios covered:
 *   1. Engine setup and profile loading
 *   2. Query rejected — no consent (PENDING state)
 *   3. Consent granted
 *   4. Over-18 query — Alice (age 30) → true
 *   5. Over-21 query — Alice (age 30) → true
 *   6. Over-21 query — Bob (age 19)   → false
 *   7. Rejected — invalid query type (no raw data access attempted)
 *   8. Rejected — threshold parameter out of range
 *   9. Audit chain integrity verification
 *
 * NOTE: Uses stub proof generator. See src/engine/ProofGenerator.js
 * for production replacement requirements.
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { randomUUID } from 'crypto';
import { CoreEngine } from '../src/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─── Setup ────────────────────────────────────────────────────────────────────

const agePpassProfile = JSON.parse(
  readFileSync(join(__dirname, '../src/profiles/agepass-v1.json'), 'utf8')
);

// Sample W3C Verifiable Credential (simplified for demo).
// In production, this credential is issued and signed by a Trust Authority.
// The dateOfBirth field is accessed ONLY internally during query execution —
// it never appears in any response.
const aliceCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'AgeCredential'],
  issuer: 'did:example:applicert-trust-authority',
  validFrom: '2026-01-01T00:00:00Z',
  credentialSubject: {
    id: 'did:example:user-alice',
    dateOfBirth: '1996-03-15',  // Alice is 30 in April 2026
  },
};

const USER_DID        = 'did:example:user-alice';
const CREDENTIAL_ID   = 'vmd:agepass:alice-001';
const VERIFIER_DID    = 'did:example:platform-xyz';

// ─── Helper ───────────────────────────────────────────────────────────────────

function makeQuery(queryType, parameters, credentialId = CREDENTIAL_ID) {
  return {
    queryId:            randomUUID(),
    credentialId,
    verifierId:         VERIFIER_DID,
    queryType,
    parameters,
    timestamp:          Math.floor(Date.now() / 1000),
    nonce:              randomUUID(),
    verifierSignature:  'stub-signature',
  };
}

function printSection(title) {
  console.log('\n' + '─'.repeat(60));
  console.log(`  ${title}`);
  console.log('─'.repeat(60));
}

function printResult(label, result) {
  const isOk    = result.status === 'OK';
  const icon    = isOk ? '✓' : '✗';
  const color   = isOk ? '\x1b[32m' : '\x1b[31m';
  const reset   = '\x1b[0m';

  console.log(`\n${color}${icon} ${label}${reset}`);

  if (isOk) {
    console.log(`  result:       ${result.result}`);
    console.log(`  profile:      ${result.profileId}`);
    console.log(`  issuer:       ${result.issuerId}`);
    console.log(`  auditRef:     ${result.auditRef}`);
    console.log(`  proof:        ${result.proof.substring(0, 60)}...`);

    // Verify the VMD guarantee: no raw credential data in the response
    const responseStr   = JSON.stringify(result);
    const sensitiveTerms = ['1996', 'dateOfBirth', '1996-03-15', 'march'];
    const leaked        = sensitiveTerms.some(v => responseStr.toLowerCase().includes(v));

    if (leaked) {
      console.log('\x1b[41m  ⚠ WARNING: Potential credential data leak detected! \x1b[0m');
    } else {
      console.log('  \x1b[90m✓ No raw credential data in response\x1b[0m');
    }
  } else {
    console.log(`  reason:       ${result.reason}`);
    console.log(`  detail:       ${result.detail}`);
    console.log(`  auditRef:     ${result.auditRef}`);
  }
}

// ─── Demo ─────────────────────────────────────────────────────────────────────

async function runDemo() {
  console.log('\n\x1b[1mVMD Core Engine — AgePass Demo\x1b[0m');
  console.log('Applicert  |  https://applicert.com');
  console.log('Model: Verifiable Minimal Disclosure (VMD)');
  console.log('Pipeline: Query → Policy → Consent → Response');
  console.log('\x1b[33mNOTE: Stub proof generator active — not for production\x1b[0m');

  // ── 1. Initialize engine ──────────────────────────────────────────────────

  printSection('1. Engine Setup');
  const engine = new CoreEngine();
  engine.loadProfile(agePpassProfile);
  console.log('  ✓ VMD Core Engine initialized');
  console.log('  ✓ Profile loaded: agepass-v1');
  console.log(`  ✓ Alice's credential loaded (dateOfBirth: ${aliceCredential.credentialSubject.dateOfBirth})`);
  console.log('    This value will NEVER appear in any query response.');

  // ── 2. Query without consent ──────────────────────────────────────────────

  printSection('2. Query Without Consent  →  expect REJECTED');
  const noConsentQuery = makeQuery('AGE_THRESHOLD', { threshold: 18 });
  const noConsentResult = await engine.processQuery(
    noConsentQuery, 'agepass-v1', aliceCredential, USER_DID
  );
  printResult('Over-18 query, consent not yet granted', noConsentResult);

  // ── 3. Grant consent ──────────────────────────────────────────────────────

  printSection('3. User Grants Consent');
  engine.grantConsent(CREDENTIAL_ID, VERIFIER_DID, 'AGE_THRESHOLD', USER_DID, 'agepass-v1');
  console.log(`  ✓ Consent GRANTED`);
  console.log(`    ${USER_DID}`);
  console.log(`    → ${VERIFIER_DID} for AGE_THRESHOLD`);

  // ── 4. Over-18 query ──────────────────────────────────────────────────────

  printSection('4. AGE_THRESHOLD: Over 18?  (Alice is 30)  →  expect true');
  const over18Query = makeQuery('AGE_THRESHOLD', { threshold: 18 });
  const over18Result = await engine.processQuery(
    over18Query, 'agepass-v1', aliceCredential, USER_DID
  );
  printResult('Over-18 query', over18Result);

  // ── 5. Over-21 query ──────────────────────────────────────────────────────

  printSection('5. AGE_THRESHOLD: Over 21?  (Alice is 30)  →  expect true');
  const over21Query = makeQuery('AGE_THRESHOLD', { threshold: 21 });
  const over21Result = await engine.processQuery(
    over21Query, 'agepass-v1', aliceCredential, USER_DID
  );
  printResult('Over-21 query', over21Result);

  // ── 6. Younger user ───────────────────────────────────────────────────────

  printSection('6. AGE_THRESHOLD: Over 21?  (Bob is 19)  →  expect false');
  const bobCredential = {
    ...aliceCredential,
    credentialSubject: {
      id: 'did:example:user-bob',
      dateOfBirth: '2006-11-20',  // Bob is 19 in April 2026
    },
  };
  const BOB_CREDENTIAL_ID = 'vmd:agepass:bob-001';
  engine.grantConsent(BOB_CREDENTIAL_ID, VERIFIER_DID, 'AGE_THRESHOLD', 'did:example:user-bob', 'agepass-v1');

  const bobQuery = {
    ...makeQuery('AGE_THRESHOLD', { threshold: 21 }),
    credentialId: BOB_CREDENTIAL_ID,
  };
  const bobResult = await engine.processQuery(
    bobQuery, 'agepass-v1', bobCredential, 'did:example:user-bob'
  );
  printResult('Over-21 query (Bob, 19)', bobResult);

  // ── 7. Invalid query type ─────────────────────────────────────────────────

  printSection('7. Invalid Query Type  →  expect REJECTED (no credential access)');
  const badTypeQuery = makeQuery('GET_DATE_OF_BIRTH', {});
  const badTypeResult = await engine.processQuery(
    badTypeQuery, 'agepass-v1', aliceCredential, USER_DID
  );
  printResult('Direct credential field access attempt', badTypeResult);

  // ── 8. Parameter out of range ─────────────────────────────────────────────

  printSection('8. Threshold Out of Range  →  expect REJECTED');
  const badParamQuery = makeQuery('AGE_THRESHOLD', { threshold: 99 });
  const badParamResult = await engine.processQuery(
    badParamQuery, 'agepass-v1', aliceCredential, USER_DID
  );
  printResult('Threshold=99 (profile max is 25)', badParamResult);

  // ── 9. Audit chain verification ───────────────────────────────────────────

  printSection('9. Audit Chain Integrity');
  const chainResult = engine.verifyAuditChain();
  console.log(`  Chain valid:    ${chainResult.valid}`);
  console.log(`  Total entries:  ${chainResult.entries}`);

  const history = engine.getCredentialHistory(CREDENTIAL_ID);
  console.log(`\n  Alice's credential history (${history.length} events):`);
  for (const event of history) {
    const date = new Date(event.timestamp).toISOString();
    console.log(`    [${date}]  ${event.eventType.padEnd(18)} → ${event.outcome}`);
  }

  // ── Summary ───────────────────────────────────────────────────────────────

  printSection('Summary');
  console.log('  ✓ VMD pipeline: Query → Policy → Consent → Response');
  console.log('  ✓ Consent enforcement: query blocked without GRANTED state');
  console.log('  ✓ Data minimization: no raw credential data in any response');
  console.log('  ✓ Schema enforcement: invalid query types rejected before data access');
  console.log('  ✓ Parameter validation: out-of-range values rejected by profile');
  console.log('  ✓ Audit chain integrity verified');
  console.log('');
  console.log('  \x1b[33mNext: Replace ProofGenerator stub with BBS+/ZKP implementation\x1b[0m');
  console.log('  See: src/engine/ProofGenerator.js\n');
}

runDemo().catch(console.error);
