// SPDX-License-Identifier: AGPL-3.0-or-later
// A question for a line of text – a name, a link, a quota – in the app's own dialog instead of the browser's
// `prompt()`, which some browsers block and which does not look like the app. `ask` answers as `prompt()` does: the
// text, or null when the dialog was cancelled. Ask.svelte shows it.

export interface Question {
  label: string;
  value: string;
  answer: (text: string | null) => void;
}

// Raw: a proxy of the question would never be the one `ask` compares with.
let open = $state.raw<{ question: Question | null }>({ question: null });

export function question(): Question | null {
  return open.question;
}

/** Asks for a line of text, `value` filled in; resolves with the text, or null when cancelled. A question asked while
 * another is open cancels that one. */
export function ask(label: string, value = ""): Promise<string | null> {
  open.question?.answer(null);
  return new Promise((resolve) => {
    const asked: Question = {
      label,
      value,
      answer: (text) => {
        if (open.question === asked) open = { question: null };
        resolve(text);
      },
    };
    open = { question: asked };
  });
}
