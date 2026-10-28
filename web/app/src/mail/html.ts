// SPDX-License-Identifier: MIT
// HTML emails shown as rich text without risk: parsed into an inert document, cut down to text, structure, tables,
// links and embedded (data:) images, and shown in a shadow root so that nothing of the email reaches the app's
// styles. The page's Content-Security-Policy stays the second line: no scripts and no remote images, whatever slips
// through.

const ALLOWED = new Set([
  "a", "abbr", "b", "blockquote", "br", "caption", "cite", "code", "col", "colgroup", "dd", "del", "div", "dl", "dt",
  "em", "font", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "ins", "kbd", "li", "mark", "ol", "p", "pre", "q",
  "s", "small", "span", "strike", "strong", "sub", "sup", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "u", "ul",
  "center", "section", "article", "header", "footer", "main", "figure", "figcaption",
]);

/** Elements removed with everything in them. */
const DROPPED = new Set(["script", "style", "noscript", "iframe", "frame", "frameset", "object", "embed", "applet", "form", "input", "button", "select", "textarea", "template", "svg", "math", "link", "meta", "base", "title", "head"]);

const ATTRIBUTES = new Set(["href", "src", "alt", "title", "colspan", "rowspan", "align", "width", "height", "dir", "lang"]);

/** Whether a URL may stay: web and mail links; for images only data:. */
function safeUrl(value: string, image: boolean): boolean {
  const url = value.trim().toLowerCase();
  if (image) return url.startsWith("data:image/");
  return url.startsWith("https:") || url.startsWith("http:") || url.startsWith("mailto:") || url.startsWith("#");
}

function clean(source: Node, target: Node, document: Document): void {
  for (const child of Array.from(source.childNodes)) {
    if (child.nodeType === Node.TEXT_NODE) {
      target.appendChild(document.createTextNode(child.textContent ?? ""));
      continue;
    }
    if (child.nodeType !== Node.ELEMENT_NODE) continue;
    const element = child as Element;
    const name = element.localName;
    if (DROPPED.has(name)) continue;
    if (!ALLOWED.has(name)) {
      // Unknown elements give up their content only.
      clean(element, target, document);
      continue;
    }
    const copy = document.createElement(name);
    for (const attribute of Array.from(element.attributes)) {
      const key = attribute.name.toLowerCase();
      if (!ATTRIBUTES.has(key)) continue;
      if ((key === "href" || key === "src") && !safeUrl(attribute.value, name === "img")) continue;
      copy.setAttribute(key, attribute.value);
    }
    if (name === "a") {
      copy.setAttribute("target", "_blank");
      copy.setAttribute("rel", "noopener noreferrer nofollow");
    }
    if (name === "img" && !copy.hasAttribute("src")) {
      // A remote image: shown as its description, never loaded (no tracking).
      const alt = element.getAttribute("alt");
      if (alt) target.appendChild(document.createTextNode(`[${alt}]`));
      continue;
    }
    clean(element, copy, document);
    target.appendChild(copy);
  }
}

/** The email's HTML, cleaned, as a fragment of `document`. */
export function safeHtml(html: string, document: Document = window.document): DocumentFragment {
  const parsed = new DOMParser().parseFromString(html, "text/html");
  const fragment = document.createDocumentFragment();
  clean(parsed.body, fragment, document);
  return fragment;
}

/** Within the shadow root: images and tables no wider than the reader. */
let sheet: CSSStyleSheet | undefined;

function styles(): CSSStyleSheet[] {
  try {
    if (!sheet) {
      sheet = new CSSStyleSheet();
      sheet.replaceSync(":host { display: block; overflow-wrap: anywhere; } img, table { max-width: 100%; height: auto; } a { color: var(--accent); }");
    }
    return [sheet];
  } catch {
    return [];
  }
}

/** Shows cleaned HTML in `host`'s shadow root. */
export function showHtml(host: HTMLElement, html: string): void {
  const root = host.shadowRoot ?? host.attachShadow({ mode: "open" });
  root.adoptedStyleSheets = styles();
  root.replaceChildren(safeHtml(html, host.ownerDocument));
}
