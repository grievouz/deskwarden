import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['src/plugin.ts'],
  format: ['cjs'],
  platform: 'node',
  target: 'node22',
  outDir: 'dist',
  clean: true,
  deps: { neverBundle: ['varlock'] },
  // Varlock runs plugin.cjs itself, so the plugin has to be one self-contained file.
  outputOptions: { codeSplitting: false },
});
