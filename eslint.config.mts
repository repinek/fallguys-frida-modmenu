import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import eslintConfigPrettier from "eslint-config-prettier";

import { defineConfig, globalIgnores } from "eslint/config";

export default defineConfig([
    js.configs.recommended,
    ...tseslint.configs.recommended,

    globalIgnores(["src/tests/"]),

    {
        files: ["src/**/*.ts"],
        languageOptions: {
            globals: {
                ...globals.browser,
                ...globals.node
            }
        },
        rules: {
            "@typescript-eslint/no-explicit-any": "off",
            "@typescript-eslint/ban-ts-comment": "off", // Look https://github.com/vfsfitvnm/frida-il2cpp-bridge/wiki/Changelog#v090 that's why we should use @ts-ignore
            "@typescript-eslint/no-this-alias": "off", // Needed to access the class instance inside hooks where this is rebound to the class Instance (refer Il2Cpp things)
            "@typescript-eslint/no-unused-vars": "warn"
        }
    },

    eslintConfigPrettier
]);
