// SPDX-License-Identifier: MIT
// kernoid's web app: mail, calendar, contacts and files of the logged-in account over JMAP, the account, and the
// administration.

import { mount } from "svelte";

import App from "./App.svelte";
import { setDocumentLanguage } from "./i18n.js";
import "@fontsource-variable/ibm-plex-sans/wght.css";
import "./style.css";
import "./theme.svelte.js";
import "./density.svelte.js";

setDocumentLanguage();
const target = document.getElementById("app");
if (target) mount(App, { target });
