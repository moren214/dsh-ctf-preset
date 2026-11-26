export const ENVELOPE_SCHEMA_VERSION = 1;

export function makeSuccessEnvelope({
  tool,
  data = {},
  resultId,
  artifacts = [],
  evidence = [],
  warnings = [],
  meta = {},
}) {
  return {
    schema_version: ENVELOPE_SCHEMA_VERSION,
    ok: true,
    tool,
    ...(resultId !== undefined ? { result_id: resultId } : {}),
    data,
    ...(artifacts.length > 0 ? { artifacts } : {}),
    ...(evidence.length > 0 ? { evidence } : {}),
    ...(warnings.length > 0 ? { warnings } : {}),
    ...(Object.keys(meta).length > 0 ? { meta } : {}),
  };
}

export function makeErrorEnvelope({ tool, file, error }) {
  return {
    schema_version: ENVELOPE_SCHEMA_VERSION,
    ok: false,
    ...(tool ? { tool } : {}),
    ...(file !== undefined ? { file } : {}),
    error,
  };
}

/**
 * Project a Core envelope into the legacy flat DSH tool output object so all
 * existing DSH callers and schema tests stay compatible.
 */
export function toFlatToolPayload(envelope) {
  if (!envelope.ok) {
    return {
      ok: false,
      ...(envelope.file !== undefined ? { file: envelope.file } : {}),
      error: envelope.error,
    };
  }
  return {
    ...(envelope.result_id !== undefined ? { result_id: envelope.result_id } : {}),
    ...envelope.data,
    ...(envelope.meta ?? {}),
  };
}
