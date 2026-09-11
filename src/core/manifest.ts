import { Ajv2020, type ErrorObject } from "ajv/dist/2020.js";
import schema from "../../schemas/ew-safe-package-manifest-v0.1.schema.json" with { type: "json" };

const ajv = new Ajv2020({ allErrors: true, strict: true, formats: { "date-time": true } });
const validate = ajv.compile(schema);

export function assertValidManifest(manifest: unknown): void {
  if (!validate(manifest)) throw new Error(`Manifest schema validation failed: ${formatErrors(validate.errors)}`);
}

function formatErrors(errors: ErrorObject[] | null | undefined): string {
  return (errors ?? []).map((error) => `${error.instancePath || "/"} ${error.message ?? "invalid"}`).join("; ");
}
