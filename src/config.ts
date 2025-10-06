export namespace Config {
    export const VERSION = "2.15";
    export const ICON_URL = "https://floyzi.github.io/images/obed-guys-present.png";

    export const SPOOF_VERSION_URL = "https://floyzi.github.io/FGTools/mobile/version.json";
    export const VERSION_URL = "https://repinek.github.io/fallguys-modmenu/latest_version.json";
    export const GITHUB_URL = "https://github.com/repinek/fallguys-frida-modmenu";
    export const GITHUB_RELEASES_URL = "https://github.com/repinek/fallguys-frida-modmenu/releases/latest";
    export const DISCORD_URL = "https://discord.gg/cNFJ73P6p3";

    export const TELEPORT_COOLDOWN = 500;

    // === Login Spoof ===
    export const USE_SPOOF = true;
    export let customSignature: string;
    export let customGameVersion: string;

    // === Custom Server === 
    export const USE_CUSTOM_SERVER = false;
    export const CUSTOM_LOGIN_URL = "https://login.fallguys.oncatapult.com/api/v1"; 
    export const CUSTOM_LOGIN_PORT = -1;
    export const CUSTOM_GATEWAY_URL = "gateway.fallguys.oncatapult.com";
    export const CUSTOM_GATEWAY_PORT = 443;
    export const IS_GATEWAY_SECURE = true;
    export const CUSTOM_ANALYTICS_URL = "analytics-gateway.fallguys.oncatapult.com";
    export const CUSTOM_ANALYTICS_PORT = 443;
    export const IS_ANALYTICS_SECURE = true;

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
        export const PLATFORM = "android_ega"; // you can change it to other one here, refer BuildCatapultConfig hook
        export let gameVersion: string;
        export let spoofedGameVersion: string;
        export let originalSignature: string;
        export let spoofedSignature: string;
        export let unityVersion: string;
        export let buildNumber = "Local build";
        export let buildDate = "n/a";
    };
};