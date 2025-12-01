import { AssemblyHelper } from "../core/assemblyHelper.js";
import { Logger } from "../logger/logger.js";

export class UnityUtils {
    private static readonly tag = "UnityUtils";
    // Classes
    private static Resources: Il2Cpp.Class;
    private static Vector3: Il2Cpp.Class;
    private static Vector2: Il2Cpp.Class;

    private static SystemBoolean: Il2Cpp.Class;
    private static SystemString: Il2Cpp.Class;
    private static SystemInt: Il2Cpp.Class;

    static SystemActionBool: Il2Cpp.Class;
    static SystemActionBoolInt: Il2Cpp.Class;

    static GenericListString: Il2Cpp.Class;

    static init() {
        this.Resources = AssemblyHelper.CoreModule.class("UnityEngine.Resources");
        this.Vector3 = AssemblyHelper.CoreModule.class("UnityEngine.Vector3");
        this.Vector2 = AssemblyHelper.CoreModule.class("UnityEngine.Vector2");

        this.SystemBoolean = Il2Cpp.corlib.class("System.Boolean");
        this.SystemString = Il2Cpp.corlib.class("System.String");
        this.SystemInt = Il2Cpp.corlib.class("System.Int32");

        this.SystemActionBool = Il2Cpp.corlib.class("System.Action`1").inflate(this.SystemBoolean);
        this.SystemActionBoolInt = Il2Cpp.corlib.class("System.Action`2").inflate(this.SystemBoolean, this.SystemInt);

        this.GenericListString = Il2Cpp.corlib.class("System.Collections.Generic.List`1").inflate(this.SystemString);

        Logger.info(`[${this.tag}::init] Initialized`);
    }

    /** Wrapper over UnityEngine::Resources::FindObjectsOfTypeAll */
    static findObjectsOfTypeAll(klass: Il2Cpp.Class): Il2Cpp.Array<Il2Cpp.Object> {
        return this.Resources.method<Il2Cpp.Array<Il2Cpp.Object>>("FindObjectsOfTypeAll", 1).invoke(klass.type.object);
    }

    /** Wrapper over get_Instance */
    static getInstance(klass: Il2Cpp.Class): Il2Cpp.Object | undefined {
        const instanceMethod = klass.tryMethod<Il2Cpp.Object>("get_Instance");
        if (!instanceMethod) {
            Logger.error(`[${this.tag}::getInstance] ${klass.name} is missing get_Instance`);
            return undefined;
        }

        return instanceMethod.invoke();
    }

    /** Wrapper over UnityEngine::Vector3::.ctor */
    static createVector3(x: number, y: number, z: number): Il2Cpp.ValueType {
        const vector = this.Vector3.alloc().unbox();
        vector.method(".ctor", 3).invoke(x, y, z);
        return vector;
    }

    /** Wrapper over UnityEngine::Vector2::.ctor */
    static createVector2(x: number, y: number): Il2Cpp.ValueType {
        const vector = this.Vector2.alloc().unbox();
        vector.method(".ctor", 2).invoke(x, y);
        return vector;
    }

    static createStringList(items: string[]): Il2Cpp.Object {
        const list = UnityUtils.createInstance(this.GenericListString);

        const Add = list.method("Add");

        for (const item of items) {
            Add.invoke(Il2Cpp.string(item));
        }

        return list;
    }

    /** Wrapper over constructor.name */
    static getTypeName(object: any): string {
        return object.constructor.name;
    }

    /** Wrapper over get_gameObject */
    static getGameObject(component: Il2Cpp.Object): Il2Cpp.Object {
        return component.method<Il2Cpp.Object>("get_gameObject").invoke();
    }

    /** Wrapper over SetActive */
    static setActive(gameObject: Il2Cpp.Object, active: boolean): void {
        gameObject.method<void>("SetActive").invoke(active);
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
