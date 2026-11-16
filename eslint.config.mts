import { fileURLToPath } from "node:url";

import { includeIgnoreFile } from "@eslint/config-helpers";
import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import eslintConfigPrettier from "eslint-config-prettier";
import simpleImportSort from "eslint-plugin-simple-import-sort";
import globals from "globals";
import tseslint from "typescript-eslint";

// https://eslint.org/docs/latest/use/configure/ignore#include-gitignore-file
const gitignorePath = fileURLToPath(new URL(".gitignore", import.meta.url));

export default defineConfig([
    js.configs.recommended,
    ...tseslint.configs.recommended,

    includeIgnoreFile(gitignorePath),
    {
        files: ["src/**/*.ts", "*.mts"],
        languageOptions: {
            globals: {
                ...globals.node
            }
        },
        plugins: {
            "simple-import-sort": simpleImportSort
        },
        rules: {
            "@typescript-eslint/ban-ts-comment": "off", // https://github.com/vfsfitvnm/frida-il2cpp-bridge/wiki/Changelog#v090
            "@typescript-eslint/no-this-alias": "off", // Needed to access the class instance inside Il2cpp hooks
            "@typescript-eslint/no-unused-vars": "warn",
            "simple-import-sort/imports": "warn",
            "simple-import-sort/exports": "warn"
        }
    },

    eslintConfigPrettier
]);
