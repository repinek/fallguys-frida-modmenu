export namespace Config {
    export const VERSION = "2.12";
    export const VERSION_URL = "https://floyzi.github.io/FGTools/mobile/version.json";
    export const ICON_URL = "https://floyzi.github.io/images/obed-guys-present.png";
    export const TELEPORT_COOLDOWN = 500;

    // === Spoof ===
    export const USE_SPOOF = true;
    export let customSignature: string;
    export let customGameVersion: string;

    export namespace Toggles {
        // === Movement ===
        export let toggle360Dives: boolean;
        export let toggleAirJump: boolean;
        export let toggleDontSendFallGuyState: boolean;

        export let toggleCustomSpeed: boolean;
        export let toggleCustomVelocity: boolean;
        export let toggleNegativeVelocity: boolean;
        export let toggleNoVelocity: boolean;

        export let toggleCustomJumpForce: boolean;
        export let toggleCustomDiveForce: boolean;

        // === Visuals ===
        export let toggleCustomFov: boolean;
        export let toggleFGDebug: boolean;
        export let toggleHideDoors: boolean;
        export let toggleShowQueuedPlayers: boolean;
    };

    export namespace CustomValues {
        export let normalMaxSpeed = 9.5;
        export let maxGravityVelocity = 40;
        export let jumpForce = 17.5;
        export let diveForce = 16.5;
        export let ResolutionScale = 1;
        export let FOV = 70;
    };

    export namespace DefaultValues {
        export const divePlayerSensitivity = 70;
        export const normalMaxSpeed = 9.5;
        export const carryMaxSpeed = 8;
        export const grabbingMaxSpeed = 5;
        export const maxGravityVelocity = 40;
        export const jumpForce = 17.5;
        export const airDiveForce = 7;
        export const diveForce = 16.5;
        export const diveMultiplier = diveForce / airDiveForce;
    };

    export namespace BuildInfo {
        // uhh here's probably will const
        export const PLATFORM = "android_ega"; // you can change it to other one, like pc_egs, ps5, switch...
        export let gameVersion: string;
        export let spoofedGameVersion: string;
        export let originalSignature: string;
        export let spoofedSignature: string;
        export let unityVersion: string;
        export let buildNumber = "Local build";
        export let buildDate = "n/a";
    };
};