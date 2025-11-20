import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import eslintConfigPrettier from "eslint-config-prettier";

import { defineConfig, globalIgnores  } from "eslint/config";

export default defineConfig([
    js.configs.recommended,
    ...tseslint.configs.recommended,

    globalIgnores([
        "src/tests/"
	]),

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
            "@typescript-eslint/ban-ts-comment": "off",
            "@typescript-eslint/no-this-alias": "off",
            "@typescript-eslint/no-unused-vars": "warn"
        },
    },
    
    eslintConfigPrettier
]);
