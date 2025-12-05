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
    if (env.dev) targetEnv = "dev";
    if (env.staging) targetEnv = "staging";

    const isDev = targetEnv === "dev" || targetEnv === "staging";
    const isRelease = targetEnv === "release";

    console.log(`Building script with ${targetEnv} env`);

    const opts = {
        DEV: isDev,
        RELEASE: isRelease,
        version: 3,
        "ifdef-verbose": true,
        "ifdef-triple-slash": true
    };

    let plugins = [];

    plugins.push(
        new webpack.DefinePlugin({
            "process.env.BUILD_ENV": JSON.stringify(targetEnv)
        })
    );

    // No reason to add obfuscator here idk

    return {
        mode: isDev ? "development" : "production",
        entry: "./src/index.ts",
        target: "node",
        module: {
            rules: [
                {
                    test: /\.ts$/,
                    include: path.resolve(__dirname, "src"),
                    use: [
                        { loader: "ts-loader" },
                        { loader: "ifdef-loader", options: opts }
                    ]
                }
            ]
        },
        resolve: {
            extensions: [".ts"],
        },
        output: {
            filename: "agent.js",
            path: path.resolve(__dirname, "dist"),
            clean: true
        },

        devtool: "inline-source-map",

        optimization: {
            minimize: !isDev,
            minimizer: !isDev
                ? [
                      new TerserPlugin({
                          terserOptions: {
                              format: {
                                  comments: false
                              },
                              compress: {
                                  drop_console: isRelease,
                                  dead_code: true
                              }
                          },
                          extractComments: false
                      })
                  ]
                : []
        },
        plugins: plugins,
        stats: "minimal"
    };
};
