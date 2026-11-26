import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeDomainName } from './ctf-router.js';

const DEFAULT_SKILLS_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../skills');

export function loadSkillForDomains(domains = ['triage'], { skillsDir = DEFAULT_SKILLS_DIR, includeCore = true } = {}) {
  const sections = [];
  const loadedFiles = [];

  if (includeCore) {
    const coreFile = path.join(skillsDir, 'core.md');
    if (existsSync(coreFile)) {
      sections.push(readFileSync(coreFile, 'utf8').trim());
      loadedFiles.push('core.md');
    }
  }

  const domainList = Array.isArray(domains) ? domains : [domains];
  const seen = new Set();
  for (const raw of domainList) {
    const norm = normalizeDomainName(String(raw ?? ''));
    if (!norm || norm === 'all' || seen.has(norm)) continue;
    seen.add(norm);
    const domainFile = path.join(skillsDir, 'domains', `${norm}.md`);
    if (existsSync(domainFile)) {
      sections.push(readFileSync(domainFile, 'utf8').trim());
      loadedFiles.push(`domains/${norm}.md`);
    }
  }

  const text = sections.join('\n\n---\n\n');
  return {
    domains: [...seen],
    loaded_files: loadedFiles,
    byte_length: Buffer.byteLength(text, 'utf8'),
    text,
  };
}
