/* @refresh reload */
import { render } from "solid-js/web";
import { App } from "./App";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("#root not found");

render(() => <App />, root);

// Service Worker は vite-plugin-pwa が自動登録するが、安全側で手動も可能。
// (autoUpdate モードのため virtual:pwa-register は不要)
