import path from "node:path";

import TerserPlugin from "terser-webpack-plugin";
import type { Configuration } from "webpack";
import webpack from "webpack";

interface WebpackEnv {
    dev?: boolean;
    release?: boolean;
}

type BuildEnv = "dev" | "release";

export default function (env: WebpackEnv = {}): Configuration {
    let targetEnv: BuildEnv = "release";
    if (env.dev) targetEnv = "dev";

    const isDev = targetEnv === "dev";
    const isRelease = targetEnv === "release";

    console.log(`Building script with ${targetEnv} version`);
    if (isRelease) console.warn("Excluding all logs in Release version!");

    const ifdefOptions = {
        DEV: isDev,
        RELEASE: isRelease,
        version: 3,
        "ifdef-verbose": true,
        "ifdef-triple-slash": true
    };

    const plugins = [
        new webpack.DefinePlugin({
            "process.env.BUILD_ENV": JSON.stringify(targetEnv)
        }),
        new webpack.ProvidePlugin({
            process: "process/browser",
            Buffer: ["buffer", "Buffer"]
        })
    ];

    return {
        mode: isDev ? "development" : "production",
        entry: "./src/index.ts",
        module: {
            rules: [
                {
                    test: /\.ts$/,
                    include: path.resolve(import.meta.dirname, "src"),
                    use: [{ loader: "ts-loader" }, { loader: "ifdef-loader", options: ifdefOptions }]
                },
                {
                    test: /\.m?js$/,
                    resolve: {
                        fullySpecified: false
                    }
                }
            ]
        },
        resolve: {
            extensions: [".ts", ".js", ".json"]
        },
        output: {
            filename: "agent.js",
            path: path.resolve(import.meta.dirname, "dist"),
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
        plugins,
        stats: "minimal",
        performance: {
            maxAssetSize: 5 * 1024 * 1024,
            maxEntrypointSize: 5 * 1024 * 1024
        }
    };
}
