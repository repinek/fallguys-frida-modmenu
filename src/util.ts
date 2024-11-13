export function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function getActivity(activityName: string) {
  let activity: Java.Wrapper;

  Java.choose(activityName, {
    onMatch: function (instance) {
      activity = instance;
    },
    onComplete: function () {},
  });

  return Promise.resolve(activity!);
}

export async function ensureModuleInitialized(...modules: string[]) {
  while (modules.length > 0) {
    const md = modules.pop();
    if (!md) return;

    if (!Module.getBaseAddress(md)) {
      console.log(`Waiting for ${md} to be initialized...`);
      await sleep(500);
      modules.push(md);
    }
  }
}

  export function JavaIl2cppPerform(fn: () => void) {
    Java.perform(() => {
      Il2Cpp.perform(fn);
    });
  }