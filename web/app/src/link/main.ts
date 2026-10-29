// SPDX-License-Identifier: MIT
// What a link opens (RFC 0005, 11.3), for people without an account: link.html#<token> (LinkPage.svelte).

import { mount } from "svelte";

import { setDocumentLanguage } from "../i18n.js";
import LinkPage from "./LinkPage.svelte";
import "../style.css";
import "../theme.svelte.js";

setDocumentLanguage();
// Another link in the same tab: start over.
window.addEventListener("hashchange", () => window.location.reload());
const target = document.getElementById("app");
if (target) mount(LinkPage, { target });
