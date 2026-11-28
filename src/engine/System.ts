/** Shorthand to some System Types */
export class System {
    private static _boolean: Il2Cpp.Class;
    private static _string: Il2Cpp.Class;
    private static _int32: Il2Cpp.Class;

    private static _action1: Il2Cpp.Class;
    private static _actionBool: Il2Cpp.Class;
    private static _actionBoolInt: Il2Cpp.Class;
    private static _actionBoolString: Il2Cpp.Class;

    private static _listString: Il2Cpp.Class;

    static get Boolean(): Il2Cpp.Class {
        return (this._boolean ??= Il2Cpp.corlib.class("System.Boolean"));
    }
    static get String(): Il2Cpp.Class {
        return (this._string ??= Il2Cpp.corlib.class("System.String"));
    }
    static get Int32(): Il2Cpp.Class {
        return (this._int32 ??= Il2Cpp.corlib.class("System.Int32"));
    }

    static get Action1(): Il2Cpp.Class {
        return (this._action1 ??= Il2Cpp.corlib.class("System.Action`1"));
    }
    static get ActionBool(): Il2Cpp.Class {
        return (this._actionBool ??= Il2Cpp.corlib.class("System.Action`1").inflate(this.Boolean));
    }
    static get ActionBoolInt(): Il2Cpp.Class {
        return (this._actionBoolInt ??= Il2Cpp.corlib.class("System.Action`2").inflate(this.Boolean, this.Int32));
    }
    static get ActionBoolString(): Il2Cpp.Class {
        return (this._actionBoolString ??= Il2Cpp.corlib.class("System.Action`2").inflate(this.Boolean, this.String));
    }

    static get ListString(): Il2Cpp.Class {
        return (this._listString ??= Il2Cpp.corlib.class("System.Collections.Generic.List`1").inflate(this.String));
    }

    /** Wrapper over System.Collections.Generic.List<Il2Cpp.String> */
    // TODO fix
    static createStringList(items: string[]): Il2Cpp.Object {
        const list = this.ListString.alloc();
        list.method(".ctor").invoke();

        const Add = list.method("Add");

        for (const item of items) {
            Add.invoke(Il2Cpp.string(item));
        }

        return list;
    }
}
