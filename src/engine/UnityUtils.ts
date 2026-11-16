import { Logger } from "../utils/Logger";

export class UnityUtils {
    /** Wrapper over klass::get_Instance */
    static getInstance(klass: Il2Cpp.Class): Il2Cpp.Object | undefined {
        const instanceMethod = klass.tryMethod<Il2Cpp.Object>("get_Instance");
        if (!instanceMethod) {
            Logger.error(`[UnityUtils::getInstance] ${klass.name} is missing get_Instance`);
            return undefined;
        }

        return instanceMethod.invoke();
    }

    /**
     * Wrapper over Il2Cpp.perform(block, "main")
     *
     * From Java.scheduleOnMainThread you need call from main thread
     */
    static runInMain<T>(block: () => T | Promise<T>): Promise<T> {
        return Il2Cpp.perform(block, "main");
    }

    /**
     * Wrapper over klass.alloc(), .ctor(...parameters)
     *
     * @param parameters args for .ctor()
     */
    static createInstance(klass: Il2Cpp.Class, ...parameters: Il2Cpp.Parameter.Type[]): Il2Cpp.Object {
        const instance = klass.alloc();
        instance.method(".ctor").invoke(...parameters);
        return instance;
    }
}
