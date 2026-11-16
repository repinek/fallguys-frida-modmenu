declare const process: { env: { BUILD_ENV: string } };

export const ModPreferences = {
    VERSION: "4.00",
    ENV: (process.env.BUILD_ENV || "dev") as "dev" | "release",
    FOR_GAME_VERSION: "21.3.1"
} as const;

/*
!! TODO:
fix spam popups
minimalistic fps counter: check ToggleFPSCounter() and FGDebug::GlobalDebug class
eula popup (cool)
refer changeResolutionScale()
all cosmetics lobby (?)
*/
