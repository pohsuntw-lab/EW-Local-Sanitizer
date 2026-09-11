export interface NormalizationPolicy {
  latinCaseSensitive: boolean;
}

export function normalizeSensitiveValue(value: string, policy: NormalizationPolicy): string {
  const normalized = value.normalize("NFKC").trim().replace(/\s+/gu, " ");
  return policy.latinCaseSensitive ? normalized : normalized.replace(/[A-Z]/g, (character) => character.toLowerCase());
}
