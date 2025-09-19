export namespace Config {
    // TODO: 
    // fix follow the leader teleport (add +y)
    export const VERSION = "2.08";
    export const VERSION_URL = "https://floyzi.github.io/FGTools/mobile/version.json1";
    export const ICON_URL = "https://floyzi.github.io/images/obed-guys-present.png";
    export const TELEPORT_COOLDOWN = 1000;

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
    }


    export namespace CustomValues {
        export let normalMaxSpeed = 9.5;
        export let maxGravityVelocity = 40;
        export let jumpForce = 17.5;
        export let diveForce = 16.5;
        export let ResolutionScale = 1;
        export let FOV = 70;
    }

    export namespace DefaultValues {
        export let divePlayerSensitivity = 70;
        export let normalMaxSpeed = 9.5;
        export let carryMaxSpeed = 8;
        export let grabbingMaxSpeed = 5;
        export let maxGravityVelocity = 40;
        export let jumpForce = 17.5;
        export let airDiveForce = 7;
        export let diveForce = 16.5;
    }

    export namespace BuildInfo {
        export let appVersion: string;
        export let original_signature: string;
        export let used_signature: string;
        export let platform = "android_ega"; // you can change it to other one, like pc_egs, ps5...
        export let unityVersion: string;
        export let buildNumber = "Local build";
        export let buildDate = "n/a";
    }
}