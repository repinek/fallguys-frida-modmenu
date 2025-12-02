import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { BaseModule } from "../../core/baseModule.js";
import { ModSettings } from "../../data/modSettings.js";

/*
 * Hooks TMP_Text::set_text and return UwUified result
 *
 * We can also hook LocalisedString::GetString, but it's not all strings
 *
 * Thanks a lot: https://github.com/KieronQuinn/owoify
 */

export class UwUifyModule extends BaseModule {
    public readonly name = "UwUify";

    // Classes
    private TMP_Text!: Il2Cpp.Class;

    // Methods
    private set_text!: Il2Cpp.Method;

    public init(): void {
        this.TMP_Text = AssemblyHelper.TextMeshPro.class("TMPro.TMP_Text");

        this.set_text = this.TMP_Text.method<void>("set_text");
    }

    public initHooks(): void {
        const module = this;

        //@ts-ignore
        this.set_text.implementation = function (string: Il2Cpp.String): void {
            if (string.isNull()) {
                this.method<void>("set_text").invoke(string);
                return;
            }

            if (ModSettings.uwuifyMode) {
                const content = string.content;
                if (content && content.length > 0) string = Il2Cpp.string(module.uwuify(content));
            }

            this.method<void>("set_text").invoke(string);
        };
    }

    private uwuify(text: string): string {
        const prefixes = ["<3 ", "0w0 ", "H-hewwo?? ", "HIIII! ", "Haiiii! ", "Huohhhh. ", "OWO ", "OwO ", "UwU "];

        const suffixes = [
            " :3",
            " UwU",
            " ÙωÙ",
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
            " (；ω；)",
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

        const processText = (str: string): string => {
            let text = str;
            for (const replacement of replacements) {
                text = text.replace(replacement.reg, replacement.val);
            }
            return text;
        };

        // no uwuify tags <cowow=#E937A2FF></cowow>
        text = text.replace(/(<[^>]*>|[^<]+)/g, match => {
            if (match.startsWith("<") && match.endsWith(">")) {
                return match;
            }
            return processText(match);
        });

        const getRandom = (arr: string[], chance: number): string => {
            if (Math.random() > chance) return "";
            return arr[Math.floor(Math.random() * arr.length)];
        };

        const prefix = getRandom(prefixes, 0.3);
        const suffix = getRandom(suffixes, 0.3);

        return `${prefix}${text}${suffix}`;
    }
}
