// SPDX-License-Identifier: MIT
// What a link opens (RFC 0005, 11.3), for people without an account: link.html#<token>.

import { mount } from "svelte";

import Pending from "../pending/Pending.svelte";
import { setDocumentLanguage } from "../i18n.js";
import "../style.css";
import "../theme.svelte.js";

setDocumentLanguage();
const target = document.getElementById("app");
if (target) mount(Pending, { target, props: { name: "link" } });
