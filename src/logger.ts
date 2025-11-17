import { modPreferences } from "./modPreferences.js";

export namespace Logger {

    const RESET = '\x1b[0m';

    const GRAY = '\x1b[90m';
    const BLUE = '\x1b[34m';
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

    export function debug(...args: any[]) {
        if (modPreferences.ENV === "release") return;
        console.debug(`${getTime()} ${CYAN}[DEBUG]${RESET}`, ...args);
    };

    export function warn(...args: any[]) {
        console.warn(`${getTime()} ${YELLOW}[WARN]${RESET}`, ...args);
    };

    export function error(...args: any[]) {
        console.error(`${getTime()} ${RED}[ERROR]${RESET}`, ...args); 
    };
};