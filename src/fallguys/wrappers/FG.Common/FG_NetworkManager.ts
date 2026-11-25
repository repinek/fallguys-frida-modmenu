import { GameConnection } from "./GameConnection";

export class FG_NetworkManager extends Il2Cpp.Object {
    get gameConnection(): GameConnection {
        return new GameConnection(this.method<Il2Cpp.Object>("get_ConnectionToServer").invoke());
    }

    get hostIpAddr(): Il2Cpp.String {
        return this.method<Il2Cpp.String>("get_HostIPAddr").invoke();
    }

    get hostPortNo(): number {
        return this.method<number>("get_HostPortNo").invoke();
    }
}
