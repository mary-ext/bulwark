import { mount } from "svelte";
import App from "./App.svelte";

// Installs the API-client fetch wrapper that detects 401s. Imported first so the
// wrapper is in place before any request fires.
import "./lib/session.svelte";

// Self-hosted fonts (bundled by Vite — no CDN, works fully offline).
import "@fontsource-variable/geist";
import "@fontsource-variable/jetbrains-mono";

// Design system.
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/utilities.css";
import "./styles/components.css";

const app = mount(App, { target: document.getElementById("app")! });

export default app;
