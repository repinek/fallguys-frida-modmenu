import "frida-java-menu";

import { ModPreferences } from "./modPreferences.js";

// Maybe log it into logcat too (but not so useful I guess)
export namespace Logger {

    const RESET = '\x1b[0m';

    const GRAY = '\x1b[90m';
    const BLUE = '\x1b[34m';
    const GREEN = '\x1b[32m';
    const CYAN = '\x1b[36m';
    const YELLOW = '\x1b[33m';
    const RED = '\x1b[31m';
    
    function getTime(): string {
        const date = new Date();
        const hh = date.getHours().toString().padStart(2, "0");
        const mm = date.getMinutes().toString().padStart(2, "0");
        const ss = date.getSeconds().toString().padStart(2, "0");
        return `${GRAY}[${hh}:${mm}:${ss}]${RESET}`;
    }

    export function info(...args: any[]) {
        console.log(`${getTime()} ${BLUE}[INFO]${RESET}`, ...args);
    };

    export function infoGreen(...args: any[]) {
        console.log(`${getTime()} ${GREEN}[INFO]`, ...args, RESET);
    };

    export function debug(...args: any[]) {
        if (ModPreferences.ENV === "release") return;
        console.debug(`${getTime()} ${CYAN}[DEBUG]${RESET}`, ...args);
    };

    export function hook(...args: any[]) {
        if (ModPreferences.ENV === "release") return;
        console.debug(`${getTime()} ${GRAY}[HOOK]`, ...args, RESET);
    };

    export function warn(...args: any[]) {
        console.warn(`${getTime()} ${YELLOW}[WARN]${RESET}`, ...args);
    };

    export function error(...args: any[]) {
        console.error(`${getTime()} ${RED}[ERROR]${RESET}`, ...args); 
    };

    export function warnToast(error: any, message: string = "") {
        Logger.warn(`${message} ${error.stack}`);
        Menu.toast(`${message} ${error.message}`, 1);
    };

    /**
     * Error log and showing toast for 3.5s 
     * 
     * Behavior: 
     * - console: {message} {error.stack}
     * - toast: {message} {error.message} 
     * 
     * @param error The error object
     * @param message "desc" -> "desc Error: {stack}" 
     */
    export function errorToast(error: any, message: string = "") {
        Logger.error(`${message} ${error.stack}`);
        Menu.toast(`${message} ${error.message}`, 1);
    };
};