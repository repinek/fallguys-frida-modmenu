export class GameConnection extends Il2Cpp.Object {
    get currentRtt(): number {
        return this.method<number>("CurrentRtt").invoke();
    }
}
