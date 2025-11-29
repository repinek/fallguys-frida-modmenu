import { AssemblyHelper } from "../core/assemblyHelper.js";
import { Logger } from "../logger/logger.js";

export class UnityUtils {
    // Classes
    private static Resources: Il2Cpp.Class;
    private static Vector3: Il2Cpp.Class;
    private static Vector2: Il2Cpp.Class;

    public static SystemAction: Il2Cpp.Class;

    public static init() {
        this.Resources = AssemblyHelper.CoreModule.class("UnityEngine.Resources");
        this.Vector3 = AssemblyHelper.CoreModule.class("UnityEngine.Vector3");
        this.Vector2 = AssemblyHelper.CoreModule.class("UnityEngine.Vector2");

        this.SystemAction = Il2Cpp.corlib.class("System.Action");
        Logger.info("[UnityUtils::init] Initialized");
    }

    /** Wrapper over UnityEngine::Resources::FindObjectsOfTypeAll */
    public static findObjectsOfTypeAll(klass: Il2Cpp.Class): Il2Cpp.Array<Il2Cpp.Object> {
        return this.Resources.method<Il2Cpp.Array<Il2Cpp.Object>>("FindObjectsOfTypeAll", 1).invoke(klass.type.object);
    }

    /** Wrapper over get_Instance */
    public static getInstance(klass: Il2Cpp.Class): Il2Cpp.Object | undefined {
        const instanceMethod = klass.tryMethod<Il2Cpp.Object>("get_Instance");
        if (!instanceMethod) {
            Logger.error(`[UnityUtils::getInstance] ${klass.name} is missing get_Instance`);
            return undefined;
        }

        return instanceMethod.invoke();
    }

    /** Wrapper over UnityEngine::Vector3::.ctor */
    public static createVector3(x: number, y: number, z: number): Il2Cpp.ValueType {
        const vector = this.Vector3.alloc().unbox();
        vector.method(".ctor", 3).invoke(x, y, z);
        return vector;
    }

    public static createVector2(x: number, y: number): Il2Cpp.ValueType {
        const vector = this.Vector2.alloc().unbox();
        vector.method(".ctor", 2).invoke(x, y);
        return vector;
    }

    /** Wrapper over constructor.name */
    public static getTypeName(object: any): string {
        return object.constructor.name;
    }

    /** Wrapper over get_gameObject */
    public static getGameObject(component: Il2Cpp.Object): Il2Cpp.Object {
        return component.method<Il2Cpp.Object>("get_gameObject").invoke();
    }

    /** Wrapper over SetActive */
    public static setActive(gameObject: Il2Cpp.Object, active: boolean): void {
        gameObject.method<void>("SetActive").invoke(active);
    }

    /**
     * Wrapper over Il2Cpp.perform(block, "main")
     *
     * From Java.scheduleOnMainThread you need call from main thread
     */
    public static runInMain<T>(block: () => T | Promise<T>): Promise<T> {
        return Il2Cpp.perform(block, "main");
    }

    /**
     * Wrapper over klass.alloc(), .ctor(...parameters)
     *
     * @param parameters args for .ctor()
     */
    public static createInstance(klass: Il2Cpp.Class, ...parameters: Il2Cpp.Parameter.Type[]): Il2Cpp.Object {
        const instance = klass.alloc();
        instance.method(".ctor").invoke(...parameters);
        return instance;
    }
}
