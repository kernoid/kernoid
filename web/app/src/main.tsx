// SPDX-License-Identifier: MIT
// kernoid's web app: mail, calendar and contacts of the logged-in account, over JMAP.

import { render } from "solid-js/web";

import { App } from "./App.js";
import { setDocumentLanguage } from "./i18n.js";
import "./style.css";
import "./theme.js";

setDocumentLanguage();
const root = document.getElementById("app");
if (root) render(() => <App />, root);
