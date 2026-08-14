import js from '@eslint/js';
import globals from 'globals';

export default [
  {
    ignores: [
      'node_modules/**',
      'data/**',
      'pgdata/**',
      'src/**/bin/**',
      'src/**/obj/**',
      'tests/**/bin/**',
      'tests/**/obj/**'
    ]
  },
  js.configs.recommended,
  {
    files: ['plugins/**/*.mjs', 'scripts/**/*.mjs', 'tests/**/*.mjs'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        ...globals.node,
        ...globals.es2024
      }
    }
  },
  {
    files: ['src/VulTrack.App/wwwroot/js/**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        ...globals.browser,
        alert: 'readonly',
        confirm: 'readonly'
      }
    }
  }
];
