import { AssemblyHelper } from "../../core/AssemblyHelper";
import { Logger } from "../../logger/Logger";

/*
 * Well, here's a patch for missing game localised strings
 * The game returns [id] in [brackets] if a string is missing in localization
 *
 * The reason why I did this is popups.
 * You can select the NotLocalised option for title and message, but not for ok, cancel and other buttons...
 *
 * You could also just patch the _localisedStrings dictionary and add the strings you need.
 * I even implemented this at first (see commit 35e4619 on GitHub)
 *
 * But it's a little bit complicated and there's no reason to do that,
 * so now I just hook the GetString method and return the missing string without brackets.
 *
 * But now we can't use strings like "play", because they are already used in the original localisedStrings.
 * We could add an exception list and add our strings to it, but I think there's no reason to do that.
 *
 * Example:
 * play -> PLAY!
 * achievement_big_air_title -> Big Air
 * ThisIsMyString -> ThisIsMyString (because it is not in the _localisedString dict, originally it would return [ThisIsMyString])
 */

export class LocalisedStrings {
    private static readonly tag = "LocalisedStrings";

    // Classes
    private static LocalisedStrings: Il2Cpp.Class;

    // Methods
    private static GetString: Il2Cpp.Method;

    static init(): void {
        this.LocalisedStrings = AssemblyHelper.TheMultiplayerGuys.class("LocalisedStrings");

        this.GetString = this.LocalisedStrings.method<Il2Cpp.String>("GetString", 1);

        this.initHooks();
        Logger.info(`[${this.tag}::init] Initialized`);
    }

    private static initHooks(): void {
        // @ts-ignore
        this.GetString.implementation = function (id: Il2Cpp.String): Il2Cpp.String {
            // when opening shop access violation accessing 0x10 -> get length -> get content
            if (id.isNull()) {
                return this.method<Il2Cpp.String>("GetString", 1).invoke(id);
            }

            const result = this.method<Il2Cpp.String>("GetString", 1).invoke(id);

            const originalText = result.content;
            const originalId = id.content;

            if (originalText === `[${originalId}]`) {
                return id;
            }
            return result;
        };
    }
}
