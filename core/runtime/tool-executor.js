import { createHash } from 'node:crypto';
import { RESULT_HASH } from '../../ctf-result-values.js';
import { experimentRequestHash } from '../../experiment-input.js';
import { describeToolError, ToolError } from '../contracts/errors.js';

export { experimentRequestHash };

export function objectWithKeys(value, allowed) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const set = new Set(allowed);
  return Object.keys(value).every(key => set.has(key));
}

export function materializeSourceResultInput(args, { session, scope, results, artifactStore }) {
  const sourceResultId = typeof args?.source_result_id === 'string' ? args.source_result_id.trim() : '';
  if (!sourceResultId) return { prepared: args, materialized: undefined };
  if (args.file_path !== undefined) {
    throw new ToolError('unsupported', '请只提供 file_path 或 source_result_id 之一。');
  }
  if (!RESULT_HASH.test(sourceResultId)) {
    throw new ToolError('unsupported', 'source_result_id 须为 64 位十六进制结果编号。');
  }

  let bytes = results?.getArtifact?.(session, sourceResultId)?.bytes;
  if (!Buffer.isBuffer(bytes)) {
    const cached = results?.get?.(session, scope, sourceResultId);
    if (Buffer.isBuffer(cached?.artifactBytes)) bytes = cached.artifactBytes;
  }

  let materialized;
  if (artifactStore) {
    const diskMat = artifactStore.materializeToTemp(sourceResultId, '.bin');
    if (diskMat) {
      materialized = { source_result_id: sourceResultId, relPath: diskMat.relPath, sha256: diskMat.sha256, bytes: diskMat.bytes };
    }
  }
  if (!materialized && Buffer.isBuffer(bytes) && artifactStore && !artifactStore.readOnly) {
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    artifactStore.putArtifact({ resultId: sourceResultId, tool: 'materialized', bytes, sources: [] });
    const diskMat = artifactStore.materializeToTemp(sourceResultId, '.bin');
    if (diskMat) {
      materialized = { source_result_id: sourceResultId, relPath: diskMat.relPath, sha256, bytes };
    }
  }
  if (!materialized) {
    throw new ToolError('missing', `未找到结果编号 ${sourceResultId} 对应的持久化产物字节（请确保先由上游工具生成带 Artifact 的结果，且工作区可写入 .ctf/artifacts）。`);
  }

  const nextArgs = { ...args, file_path: materialized.relPath };
  delete nextArgs.source_result_id;
  return { prepared: nextArgs, materialized };
}

export function createToolExecutor({
  runtime,
  shouldRegisterTool,
  normalizePath = value => String(value).replaceAll('\\', '/'),
  resolveLocation,
  rewriteInputPaths,
  persistResult,
  resultSources,
  compactJson,
  registerTarget,
  deferTarget,
}) {
  const results = runtime.results;
  const formatJson = compactJson ?? ((value, cfg) => JSON.stringify(value, null, cfg?.compact === false ? 2 : 0));

  return function registerTool(toolName, description, properties, run, required = ['file_path'], capture, parametersOverride) {
    const schema = parametersOverride ?? {
      type: 'object',
      properties,
      additionalProperties: false,
      required,
    };
    const allowedKeys = Object.keys(schema.properties ?? properties);
    const acceptsSourceResultId = Boolean(
      Object.hasOwn(schema.properties ?? properties, 'source_result_id')
      && typeof capture === 'object' && capture?.materializeSourceResult === true,
    );

    const toolDef = {
      name: toolName,
      description,
      parameters: schema,
      output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
      async execute(args, execution) {
        const askedFile = typeof args?.file_path === 'string' ? args.file_path : undefined;
        const binding = typeof capture === 'function' ? capture(args) : capture;
        const outputConfig = binding?.config ?? runtime.getConfig?.();
        const shouldMaterialize = Boolean(binding?.materializeSourceResult);

        try {
          if (!objectWithKeys(args, allowedKeys)) {
            throw new ToolError('unsupported', '提供了此工具不支持的参数。');
          }
          for (const req of required) {
            if (req === 'file_path' && (shouldMaterialize || acceptsSourceResultId)
              && typeof args.source_result_id === 'string' && args.source_result_id.trim()) {
              continue;
            }
            if (!Object.hasOwn(args, req) || args[req] === undefined) {
              throw new ToolError('unsupported', `缺少必填参数 ${req}。`);
            }
          }

          const hasLocationService = typeof resolveLocation === 'function';
          const location = (binding?.workspace || (shouldMaterialize && args.source_result_id)) && hasLocationService
            ? await resolveLocation(execution)
            : undefined;
          const scope = binding?.workspace ? location?.directoryKey : (binding?.scope ?? null);
          const session = execution?.agent?.session;

          let prepared = args;
          let imported;
          let materialized;

          if (location !== undefined && shouldMaterialize && typeof args.source_result_id === 'string' && args.source_result_id.trim()) {
            const artifactStore = runtime.getArtifactStore?.(location.cwd);
            ({ prepared, materialized } = materializeSourceResultInput(args, { session, scope, results, artifactStore }));
          }

          if (location !== undefined && typeof rewriteInputPaths === 'function' && !materialized) {
            ({ args: prepared, imported } = await rewriteInputPaths(prepared, location, execution));
          }

          const report = await run(prepared, execution, location);
          const artifactBytes = Buffer.isBuffer(report?.__artifact_bytes) ? report.__artifact_bytes : undefined;
          if (artifactBytes !== undefined) delete report.__artifact_bytes;

          const requestHash = binding?.workspace
            ? experimentRequestHash(toolName, typeof prepared.file_path === 'string'
              ? { ...prepared, file_path: normalizePath(prepared.file_path) }
              : prepared)
            : undefined;

          const output = {
            ...(materialized ? { source_result_id: materialized.source_result_id } : {}),
            ...(prepared.file_path !== undefined ? { file: prepared.file_path } : {}),
            ...(imported?.length ? { imported } : {}),
            ...report,
            ...(requestHash === undefined ? {} : { request_sha256: requestHash }),
          };

          const sources = resultSources?.(toolName, output, binding?.workspace, prepared) ?? [];
          const resultId = binding && scope !== undefined
            ? results.remember(session, scope, toolName, output, sources)
            : undefined;

          if (resultId === undefined) return formatJson(output, outputConfig);

          if (artifactBytes !== undefined) {
            results.rememberArtifact(session, resultId, artifactBytes, sources);
          }

          let artifactStored;
          if (location?.cwd && artifactBytes !== undefined) {
            const artifactStore = runtime.getArtifactStore?.(location.cwd);
            if (artifactStore && !artifactStore.readOnly) {
              try {
                artifactStored = artifactStore.putArtifact({ resultId, tool: toolName, bytes: artifactBytes, sources, report: output });
              } catch {
                // Non-fatal if artifact cap exceeded or readonly dir.
              }
            }
          }

          const result = binding.workspace ? results.get(session, scope, resultId) : undefined;
          const summary = result?.summary;
          const evidencePersistence = result !== undefined && typeof persistResult === 'function'
            ? await persistResult(location, execution, resultId, result)
            : undefined;

          return formatJson({
            result_id: resultId,
            ...output,
            ...(artifactStored?.persisted ? { artifact_sha256: artifactStored.artifact_sha256 } : {}),
            ...(evidencePersistence === undefined ? {} : { evidence_persistence: evidencePersistence }),
            ...(summary === undefined ? {} : {
              result_cache: { mode: 'fields', field_count: summary.fields.size, limited: summary.limited },
            }),
          }, outputConfig);
        } catch (error) {
          return formatJson({ ok: false, file: askedFile, error: describeToolError(error) }, outputConfig);
        }
      },
    };

    if (shouldRegisterTool && !shouldRegisterTool(toolName)) {
      deferTarget?.(toolDef);
      return false;
    }

    registerTarget(toolDef);
    return true;
  };
}
