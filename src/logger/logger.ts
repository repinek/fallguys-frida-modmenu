import { ModPreferences } from "../data/modPreferences.js";

export class Logger {
    private static readonly Colors = {
        RESET: "\x1b[0m",
        GRAY: "\x1b[90m",
        BLUE: "\x1b[34m",
        GREEN: "\x1b[32m",
        CYAN: "\x1b[36m",
        YELLOW: "\x1b[33m",
        RED: "\x1b[31m"
    } as const; 

    private static getTime(): string {
        const date = new Date();
        const hh = date.getHours().toString().padStart(2, "0");
        const mm = date.getMinutes().toString().padStart(2, "0");
        const ss = date.getSeconds().toString().padStart(2, "0");
        return `${this.Colors.GRAY}[${hh}:${mm}:${ss}]${this.Colors.RESET}`;
    }

    public static info(...messages: any[]) {
        console.info(`${this.getTime()} ${this.Colors.BLUE}[INFO]${this.Colors.RESET}`, ...messages);
    }

    public static infoGreen(...messages: any[]) {
        console.info(`${this.getTime()} ${this.Colors.GREEN}[INFO]`, ...messages, this.Colors.RESET);
    }

    public static debug(...messages: any[]) {
        if (ModPreferences.ENV === "release") return;
        console.debug(`${this.getTime()} ${this.Colors.CYAN}[DEBUG]${this.Colors.RESET}`, ...messages);
    }

    public static hook(...messages: any[]) {
        if (ModPreferences.ENV === "release") return;
        console.debug(`${this.getTime()} ${this.Colors.GRAY}[HOOK]`, ...messages, this.Colors.RESET);
    }

    public static warn(...messages: any[]) {
        console.warn(`${this.getTime()} ${this.Colors.YELLOW}[WARN]${this.Colors.RESET}`, ...messages);
    }

    public static error(...messages: any[]) {
        console.error(`${this.getTime()} ${this.Colors.RED}[ERROR]${this.Colors.RESET}`, ...messages);
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
        this.toast(`${message} ${error.message}`, 1);
    }

    /** 
     * Creates toast
     * Wrapper over Menu.Toast
     * 
     * @param [length=0] 0 - 2s, 1 - 3.5s, default is 2s
     */
    public static toast(text: string, length: 0 | 1 = 0) {
        Menu.toast(text, length);
    }
}
