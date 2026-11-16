import { add, CENTER } from "frida-java-menu";

import { UnityUtils } from "../../engine/UnityUtils";
import { MenuBuilder } from "./MenuBuilder";

export class MenuUtils {
    /** Creates a callback wrapper over UnityUtils.runInMain */
    static run<T extends unknown[]>(action: (...args: T) => void): (...args: T) => void {
        return (...args: T) => {
            UnityUtils.runInMain(() => action(...args));
        };
    }

    /** Adds center text in menu */
    static addCenterText(text: string): void {
        if (MenuBuilder.layout) {
            const textToAdd = MenuBuilder.layout.textView(text);
            textToAdd.gravity = CENTER;
            add(textToAdd);
        }
    }
}
