export abstract class BaseModule {
    abstract name: string;

    abstract init(): void;

    public initHooks(): void {} // hooks here
}
