import { AssemblyHelper } from "../core/assemblyHelper.js";
import { Logger } from "../logger/logger.js";

export class UnityUtils {
    // Classes
    private static Resources: Il2Cpp.Class;
    private static Vector3: Il2Cpp.Class;

    public static init() {
        this.Resources = AssemblyHelper.CoreModule.class("UnityEngine.Resources");
        this.Vector3 = AssemblyHelper.CoreModule.class("UnityEngine.Vector3");
        Logger.info("[UnityUtils] Initialized");
    }

    /** Wrapper over UnityEngine::Resources::FindObjectsOfTypeAll */
    public static findObjectsOfTypeAll(klass: Il2Cpp.Class): Il2Cpp.Array<Il2Cpp.Object> {
        return this.Resources.method<Il2Cpp.Array<Il2Cpp.Object>>("FindObjectsOfTypeAll", 1).invoke(klass.type.object);
    }

    /** Wrapper over get_Instance */
    public static getInstance(klass: Il2Cpp.Class): Il2Cpp.Object | undefined {
        const instanceMethod = klass.tryMethod<Il2Cpp.Object>("get_Instance");
        if (!instanceMethod) {
            Logger.error(`[UnityUtils] ${klass.name} is missing get_Instance`);
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

    /** Wrapper over constructor.name */
    public static getTypeName(object: any) {
        return object.constructor.name;
    }
}
