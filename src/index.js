/**
 * @applicert/vmd-core-engine
 *
 * VMD Core Engine — execution layer for Verifiable Minimal Disclosure
 *
 * Verifiable Minimal Disclosure (VMD) is a model in which systems answer
 * narrowly scoped questions by returning the smallest possible, verifiable
 * result — without exposing underlying data.
 *
 * The interaction pattern is:  Query → Policy → Consent → Response
 *
 * External systems do not retrieve data. They submit constrained queries.
 * The VMD Core Engine evaluates those queries against defined rules, enforces
 * user consent, processes the underlying data internally, and returns only
 * the minimal result required to satisfy the request.
 *
 * Quick start:
 *
 *   import { CoreEngine } from '@applicert/vmd-core-engine';
 *   import agePpassProfile from './profiles/agepass-v1.json' assert { type: 'json' };
 *
 *   const engine = new CoreEngine();
 *   engine.loadProfile(agePpassProfile);
 *
 *   engine.grantConsent(credentialId, verifierId, 'AGE_THRESHOLD', userDID, 'agepass-v1');
 *   const response = await engine.processQuery(query, 'agepass-v1', credential, userDID);
 *
 * See /demo/agepass-demo.js for a complete working example.
 * See /spec/VMD-Core-Engine-Spec-v0.1.md for the full specification.
 * See /docs/VMD-Whitepaper-v1.0.pdf for the conceptual model.
 */

export { CoreEngine } from './engine/CoreEngine.js';
export { ProfileLoader, ProfileValidationError } from './engine/ProfileLoader.js';
export { QueryValidator } from './engine/QueryValidator.js';
export { ConsentEngine, ConsentState, ConsentError } from './engine/ConsentEngine.js';
export { ResponseMinimizer, MinimizationError } from './engine/ResponseMinimizer.js';
export { ProofGenerator } from './engine/ProofGenerator.js';
export { AuditLogger, EventType } from './engine/AuditLogger.js';
