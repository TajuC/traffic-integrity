import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default defineConfig(
  { ignores: ['dist/**', 'node_modules/**', 'data/**', 'coverage/**'] },
  {
    files: ['src/**/*.ts', 'test/**/*.ts'],
    extends: [js.configs.recommended, ...tseslint.configs.recommendedTypeChecked],
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
      globals: globals.node,
    },
    rules: {
      'no-console': 'error',
      eqeqeq: ['error', 'always'],
      '@typescript-eslint/consistent-type-imports': ['error', { fixStyle: 'inline-type-imports' }],
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': ['error', { checksVoidReturn: { arguments: false } }],
      '@typescript-eslint/switch-exhaustiveness-check': 'error',
    },
  },
  {
    files: ['test/**/*.ts'],
    rules: {
      '@typescript-eslint/no-floating-promises': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
    },
  },
  {
    files: ['public/**/*.js'],
    extends: [js.configs.recommended],
    languageOptions: { sourceType: 'script', globals: globals.browser },
  },
  {
    files: ['eslint.config.js'],
    extends: [js.configs.recommended],
    languageOptions: { globals: globals.node },
  },
);
