// The `@fontsource-variable/*` packages are CSS-only and ship no type
// declarations, so their side-effect imports in `main.ts` need an ambient module
// declaration to satisfy `svelte-check`/TypeScript.
declare module "@fontsource-variable/geist";
declare module "@fontsource-variable/jetbrains-mono";
