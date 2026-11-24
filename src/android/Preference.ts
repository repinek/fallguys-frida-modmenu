import Java from "frida-java-bridge";
import { sharedPreferences } from "frida-java-menu";

/** Class for managing String SharedPreferences */
export class StringPrereference {
    constructor(private readonly key: string) {}

    /** @returns undefined if no value present in sharedPreferences, else value */
    read(): string | undefined {
        let value: string | undefined = undefined;

        Java.performNow(() => {
            if (sharedPreferences.contains(this.key)) {
                value = sharedPreferences.getString(this.key);
            }
        });

        return value;
    }

    save(value: string) {
        Java.performNow(() => {
            sharedPreferences.putString(this.key, value);
        });
    }
}
