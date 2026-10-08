import { isAuthorized, validate, type Schema } from '@cedar-policy/cedar-wasm/nodejs';
import { GatewayError } from './errors.js';

export const policySchema: Schema = {
  Gw: {
    entityTypes: {
      Agent: { shape: { type: 'Record', attributes: {} } },
      User: { shape: { type: 'Record', attributes: {} } },
      Tool: { shape: { type: 'Record', attributes: { effect: { type: 'String' } } } },
    },
    actions: {
      call: {
        appliesTo: {
          principalTypes: ['Agent', 'User'],
          resourceTypes: ['Tool'],
          context: {
            type: 'Record',
            attributes: {
              repo: { type: 'String' },
              readPrivate: { type: 'Boolean' },
              readUntrusted: { type: 'Boolean' },
            },
          },
        },
      },
    },
  },
};
export const defaultPolicy = `permit(principal, action == Gw::Action::"call", resource)
when { context.repo == "demo/public" || context.repo == "demo/private" };
forbid(principal, action, resource)
when { resource.effect == "write" && context.readPrivate };`;
export function validatePolicy(text: string) {
  if (Buffer.byteLength(text) > 32_768) throw new GatewayError('policy_too_large', 400);
  const result = validate({ schema: policySchema, policies: { staticPolicies: text } });
  if (result.type !== 'success' || result.validationErrors.length)
    throw new GatewayError('invalid_policy', 400);
}
export interface PolicyFacts {
  repo: string;
  readPrivate: boolean;
  readUntrusted: boolean;
}
export function evaluate(
  policy: string,
  kind: 'Agent' | 'User',
  id: string,
  tool: string,
  effect: string,
  context: PolicyFacts,
) {
  const principal = { type: `Gw::${kind}`, id };
  const resource = { type: 'Gw::Tool', id: tool };
  const result = isAuthorized({
    principal,
    action: { type: 'Gw::Action', id: 'call' },
    resource,
    context: { ...context },
    schema: policySchema,
    validateRequest: true,
    policies: { staticPolicies: policy },
    entities: [
      { uid: principal, attrs: {}, parents: [] },
      { uid: resource, attrs: { effect }, parents: [] },
    ],
  });
  if (result.type !== 'success' || result.response.diagnostics.errors.length)
    return { allowed: false, reasons: ['policy_error'] };
  const { decision, diagnostics } = result.response;
  return {
    allowed: decision === 'allow',
    reasons: diagnostics.reason.length ? diagnostics.reason : ['default_deny'],
  };
}
