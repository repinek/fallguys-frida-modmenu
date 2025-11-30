import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { Logger } from "../../logger/logger.js";
import { GameLocalization } from "./gameLocalization.js";
import { UpdateUtils } from "../updateUtils.js";

// TODO: describe a lot of stuff here

export class CMSLoader {
    // Classes and Instances
    private static CMSLoader: Il2Cpp.Class;
    static CMSLoaderInstance?: Il2Cpp.Object;

    // Methods
    private static InitItemsFromContent: Il2Cpp.Method;

    static init(): void {
        this.CMSLoader = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.CMS.CMSLoader");

        this.InitItemsFromContent = this.CMSLoader.method<void>("InitItemsFromContent", 3);
        Logger.info("[CMSLoader::init] Initialized");
        this.initHooks();
    }

    static initHooks(): void {
        const module = this;

        //@ts-ignore
        this.InitItemsFromContent.implementation = function (
            this: Il2Cpp.Object,
            cmsData: Il2Cpp.Object,
            platofrm: Il2Cpp.String,
            cmsBranchUrl: Il2Cpp.String
        ) {
            Logger.hook("InitItemsFromContent called");
            this.method<void>("InitItemsFromContent", 3).invoke(cmsData, platofrm, cmsBranchUrl); // <--- OnLeave
            module.CMSLoaderInstance = this;
            GameLocalization.init();
            if (UpdateUtils.updateState == 2) {
                UpdateUtils.showUpdatePopup();
            }
        };
    }
}
