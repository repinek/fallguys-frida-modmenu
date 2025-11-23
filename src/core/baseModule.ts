export abstract class BaseModule {
    abstract name: string;
    abstract init(): void;

    public onEnable(): void {}
}
