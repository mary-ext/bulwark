import { mount } from "svelte";
import App from "./App.svelte";

import "./lib/session.svelte";

import "@fontsource-variable/geist";
import "@fontsource-variable/jetbrains-mono";

import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/utilities.css";
import "./styles/components.css";

const app = mount(App, { target: document.getElementById("app")! });

export default app;
