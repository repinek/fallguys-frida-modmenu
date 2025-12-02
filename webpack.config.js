/* eslint-disable */
const path = require("path");
const webpack = require("webpack");
const TerserPlugin = require("terser-webpack-plugin");

/*
 * Webpack configuration adapted from Gene Brawl
 * Source: https://github.com/RomashkaTea/genebrawl-public
 */

module.exports = function (env) {
    let targetEnv = "release";
    if (env.dev) targetEnv = "dev"
    if (env.staging) targetEnv = "staging"

    const isDev = targetEnv === "dev" || targetEnv === "staging";
    const isRelease = targetEnv === 'release';

    console.log(`Building script with ${targetEnv}`);

    let plugins = [];

    plugins.push(new webpack.DefinePlugin({
        'process.env.BUILD_ENV': JSON.stringify(targetEnv)
    }));

    // No reason to add obfuscator here idk 

    return {
        mode: isDev ? "development" : "production",
        entry: "./src/index.ts",
        target: "node",
        module: {
            rules: [
                {
                    test: /\.ts$/,
                    include: path.resolve(__dirname, 'src'), 
                    use: "ts-loader",
                }
            ]
        },
        resolve: {
            extensions: ['.ts', '.js'],
            extensionAlias: {
                '.js': ['.ts', '.js']
            }
        },
        output: {
            filename: "agent.js",
            path: path.resolve(__dirname, "dist"),
            clean: true
        },

        devtool: "inline-source-map",

        optimization: {
            minimize: !isDev,
            minimizer: !isDev ? [
                new TerserPlugin({
                    terserOptions: {
                        format: {
                            comments: false,
                        },
                        compress: {
                            drop_console: isRelease, 
                            dead_code: true,
                        },
                    },
                    extractComments: false,
                }),
            ]: [],
        },
        plugins: plugins,
        stats: "normal"
    };
};
