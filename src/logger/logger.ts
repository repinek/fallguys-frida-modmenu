import { ModPreferences } from "../data/modPreferences.js";

// Maybe log it into logcat too (but it's useless I guess)
export class Logger {
    private static readonly RESET = "\x1b[0m";
    private static readonly GRAY = "\x1b[90m";
    private static readonly BLUE = "\x1b[34m";
    private static readonly GREEN = "\x1b[32m";
    private static readonly CYAN = "\x1b[36m";
    private static readonly YELLOW = "\x1b[33m";
    private static readonly RED = "\x1b[31m";

    private static getTime(): string {
        const date = new Date();
        const hh = date.getHours().toString().padStart(2, "0");
        const mm = date.getMinutes().toString().padStart(2, "0");
        const ss = date.getSeconds().toString().padStart(2, "0");
        return `${this.GRAY}[${hh}:${mm}:${ss}]${this.RESET}`;
    }

    public static info(...args: any[]) {
        console.info(`${this.getTime()} ${this.BLUE}[INFO]${this.RESET}`, ...args);
    }

    public static infoGreen(...args: any[]) {
        console.info(`${this.getTime()} ${this.GREEN}[INFO]`, ...args, this.RESET);
    }

    public static debug(...args: any[]) {
        if (ModPreferences.ENV === "release") return;
        console.debug(`${this.getTime()} ${this.CYAN}[DEBUG]${this.RESET}`, ...args);
    }

    public static hook(...args: any[]) {
        if (ModPreferences.ENV === "release") return;
        console.debug(`${this.getTime()} ${this.GRAY}[HOOK]`, ...args, this.RESET);
    }

    public static warn(...args: any[]) {
        console.warn(`${this.getTime()} ${this.YELLOW}[WARN]${this.RESET}`, ...args);
    }

    public static error(...args: any[]) {
        console.error(`${this.getTime()} ${this.RED}[ERROR]${this.RESET}`, ...args);
    }

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
    // errortoast
    public static errorThrow(error: any, message: string = "") {
        this.error(`${message} ${error.stack}`);
        Menu.toast(`${message} ${error.message}`, 1);
    }
}
