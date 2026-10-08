import { z } from 'zod';
import { fromJsonSchema, type JsonSchemaType } from '@modelcontextprotocol/server';
// Zod and the SDK use different JSON-schema TypeScript declarations. The emitted
// schemas are JSON Schema 2020-12 objects, validated by the SDK's AJV adapter.
export const sdkSchema = (schema: z.ZodType) =>
  fromJsonSchema(z.toJSONSchema(schema) as unknown as JsonSchemaType);
