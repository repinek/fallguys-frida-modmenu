import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { BaseModule } from "../../core/baseModule.js";
import { Config } from "../../data/config.js";

/*
 * Hooks LocalisedString::GetString and return UwUified result
 *
 * Thanks a lot: https://github.com/KieronQuinn/owoify
 */

export class UwUifyModule extends BaseModule {
    public name = "UwUify";

    private LocalisedStrings!: Il2Cpp.Class;

    private getString!: Il2Cpp.Method;
    private getString2!: Il2Cpp.Method;

    public init(): void {
        this.LocalisedStrings = AssemblyHelper.TheMultiplayerGuys.class("LocalisedStrings");

        // System.String LocalisedStrings::GetString(System.String)
        this.getString = this.LocalisedStrings.method("GetString").overload("System.String");
        this.getString2 = this.LocalisedStrings.method("GetString").overload("System.String", "System.Object[]");
    }

    public initHooks(): void {
        const module = this;

        //@ts-ignore
        this.getString.implementation = function (id: Il2Cpp.String): Il2Cpp.String {
            let localisedString = this.method<Il2Cpp.String>("GetString", 1).invoke(id);
            if (Config.Toggles.toggleUwUifyMode) {
                localisedString = Il2Cpp.string(module.uwuify(localisedString.content!));
            }
            return localisedString;
        };

        //@ts-ignore
        this.getString2.implementation = function (id: Il2Cpp.String, params): Il2Cpp.String {
            let localisedString = this.method<Il2Cpp.String>("GetString", 2).invoke(id, params);
            if (Config.Toggles.toggleUwUifyMode) {
                localisedString = Il2Cpp.string(module.uwuify(localisedString.content!));
            }
            return localisedString;
        };
    }

    private uwuify(text: string): string {
        const prefixes = ["<3 ", "0w0 ", "H-hewwo?? ", "HIIII! ", "Haiiii! ", "Huohhhh. ", "OWO ", "OwO ", "UwU "];

        const suffixes = [
            " :3",
            " UwU",
            " (✿ ♡‿♡)",
            " ÙωÙ",
            " ʕʘ‿ʘʔ",
            " ʕ•̫͡•ʔ",
            " >_>",
            " ^_^",
            "..",
            " Huoh.",
            " ^-^",
            " ;_;",
            " ;-;",
            " xD",
            " x3",
            " :D",
            " :P",
            " ;3",
            " XDDD",
            ", fwendo",
            " ㅇㅅㅇ",
            "（＾ｖ＾）",
            " x3",
            " ._.",
            ' (　"◟ ")',
            " (；ω；)",
            " (◠‿◠✿)",
            " >_<",
            " >w<",
            " ^w^",
            " Nyaa~"
        ];

        const replacements: { reg: RegExp; val: string }[] = [
            { reg: /r/g, val: "w" },
            { reg: /l/g, val: "w" },
            { reg: /R/g, val: "W" },
            { reg: /L/g, val: "W" },
            { reg: /no/g, val: "nu" },
            { reg: /has/g, val: "haz" },
            { reg: /have/g, val: "haz" },
            { reg: /you/g, val: "uu" },
            { reg: /the /g, val: "da " },
            { reg: /The /g, val: "Da " },
            { reg: /ove/g, val: "uv" },
            // nya
            { reg: /n([aeiou])/g, val: "ny$1" },
            { reg: /N([aeiou])/g, val: "Ny$1" },
            { reg: /N([AEIOU])/g, val: "NY$1" }
        ];

        for (const replacement of replacements) {
            text = text.replace(replacement.reg, replacement.val);
        }

        const getRandom = (arr: string[], chance: number): string => {
            if (Math.random() > chance) return "";
            return arr[Math.floor(Math.random() * arr.length)];
        };

        const prefix = getRandom(prefixes, 0.3);
        const suffix = getRandom(suffixes, 0.3);

        return `${prefix}${text}${suffix}`;
    }
}
