export function isRecord(value: unknown): value is Record<string, unknown> {
  const isObject = typeof value === 'object';
  const isNotNull = value !== null;

  return isObject && isNotNull;
}

export function isNonEmptyString(value: unknown): value is string {
  const isString = typeof value === 'string';
  const isBlank = isString && value.trim() === '';

  return isString && !isBlank;
}
