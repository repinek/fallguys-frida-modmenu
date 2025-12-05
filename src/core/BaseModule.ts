export abstract class BaseModule {
    abstract readonly name: string;

    abstract init(): void;

    public initHooks(): void {} // hooks here
}
