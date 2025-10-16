import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
type LocaleMap = Record<string, unknown>;

async function loadLocale(locale: string): Promise<LocaleMap> {
  const file = fileURLToPath(new URL(`../src/locales/${locale}/common.json`, import.meta.url));
  const data = await readFile(file, 'utf-8');
  return JSON.parse(data);
}

function collectKeys(map: LocaleMap, prefix = ''): string[] {
  return Object.entries(map).flatMap(([key, value]) => {
    const next = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return collectKeys(value as LocaleMap, next);
    }
    return [next];
  });
}

(async () => {
  const base = await loadLocale('en');
  const compare = await loadLocale('ru');
  const baseKeys = new Set(collectKeys(base));
  const compareKeys = new Set(collectKeys(compare));

  const missingInRu = [...baseKeys].filter((key) => !compareKeys.has(key));
  const missingInEn = [...compareKeys].filter((key) => !baseKeys.has(key));

  if (missingInRu.length || missingInEn.length) {
    console.error('Locale mismatch detected');
    if (missingInRu.length) {
      console.error('Missing in RU:', missingInRu.join(', '));
    }
    if (missingInEn.length) {
      console.error('Missing in EN:', missingInEn.join(', '));
    }
    process.exitCode = 1;
  } else {
    console.log('Locales are in sync');
  }
})();
