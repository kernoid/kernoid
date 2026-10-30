// SPDX-License-Identifier: MIT
// The texts of the login UI in English and German. The English text is the key; the language is the browser's first
// one kernoid knows (`?lang=de` or `?lang=en` overrides it). Placeholders are written `{name}`.

export type Lang = "en" | "de";

const de = {
  // Frame and errors
  "Log in – kernoid": "Anmelden – kernoid",
  "Your account – kernoid": "Ihr Konto – kernoid",
  "Something went wrong": "Etwas ist schiefgegangen",
  "Login failed": "Anmeldung fehlgeschlagen",
  "The login could not be completed.": "Die Anmeldung konnte nicht abgeschlossen werden.",
  "Try again": "Erneut versuchen",
  "The passkey was not used.": "Der Passkey wurde nicht verwendet.",
  "Too many failed attempts – try again in {minutes} minutes.":
    "Zu viele Fehlversuche – versuchen Sie es in {minutes} Minuten erneut.",
  "kernoid cannot be reached right now.": "kernoid ist gerade nicht erreichbar.",
  "The address or the password is wrong.": "Adresse oder Passwort ist falsch.",
  "The code is not valid or was used already.": "Der Code ist ungültig oder wurde schon verwendet.",
  "The passkey was not accepted.": "Der Passkey wurde nicht angenommen.",
  "The account is deactivated.": "Das Konto ist deaktiviert.",
  "The session is not valid.": "Die Sitzung ist nicht gültig.",
  "This needs a login with a second factor.": "Dafür ist eine Anmeldung mit zweitem Faktor nötig.",
  "Log in again to change how you log in.": "Melden Sie sich erneut an, um Ihre Anmeldung zu ändern.",

  // Logging in
  "Log in": "Anmelden",
  "Log in with a passkey": "Mit Passkey anmelden",
  "Continue": "Weiter",
  "Email address": "E-Mail-Adresse",
  "Password": "Passwort",
  "Cancel": "Abbrechen",
  "or": "oder",
  "Use another address": "Andere Adresse verwenden",
  "Email address or username": "E-Mail-Adresse oder Benutzername",
  "Continue with {provider}": "Weiter mit {provider}",
  "Create an account": "Konto anlegen",

  // Registering and linking
  "Create an account – kernoid": "Konto anlegen – kernoid",
  "Registering is not possible here.": "Hier ist keine Registrierung möglich.",
  "Back to logging in": "Zurück zur Anmeldung",
  "Your own address": "Eigene Adresse",
  "Your own address (optional)": "Eigene Adresse (optional)",
  "Username (optional)": "Benutzername (optional)",
  "Confirm your email address": "E-Mail-Adresse bestätigen",
  "We sent a code to {email}.": "Wir haben einen Code an {email} geschickt.",
  "Code": "Code",
  "Create the account": "Konto anlegen",
  "Link {provider}?": "{provider} verknüpfen?",
  "There is an account with {email} already. Log in to it to sign in with {provider} from now on.":
    "Es gibt schon ein Konto mit {email}. Melden Sie sich dort an, um sich künftig auch mit {provider} anzumelden.",
  "Log in and link": "Anmelden und verknüpfen",
  "Create a separate account": "Getrenntes Konto anlegen",
  "Other logins": "Weitere Anmeldungen",
  "Log in to this account with another provider as well.": "Melden Sie sich bei diesem Konto auch über einen anderen Anbieter an.",
  "Link {provider}": "{provider} verknüpfen",
  "Back": "Zurück",

  // Second factors
  "Use a recovery code": "Wiederherstellungscode verwenden",
  "Recovery code": "Wiederherstellungscode",
  "Confirm it is you": "Bestätigen Sie, dass Sie es sind",
  "This login needs a second factor.": "Diese Anmeldung braucht einen zweiten Faktor.",
  "Code from your authenticator app": "Code aus Ihrer Authenticator-App",
  "Use a passkey": "Passkey verwenden",
  "Set up a second factor": "Zweiten Faktor einrichten",
  "Your organisation requires a second factor. Set one up to continue.":
    "Ihre Organisation verlangt einen zweiten Faktor. Richten Sie einen ein, um fortzufahren.",
  "Your organisation requires a second factor. Until {date} you can log in without one.":
    "Ihre Organisation verlangt einen zweiten Faktor. Bis zum {date} können Sie sich noch ohne anmelden.",
  "Set it up now": "Jetzt einrichten",
  "Passkey created": "Passkey erstellt",
  "Now confirm this login with it once.": "Bestätigen Sie diese Anmeldung jetzt einmal damit.",
  "Confirm with the passkey": "Mit dem Passkey bestätigen",
  "Later": "Später",
  "Create a passkey": "Passkey erstellen",
  "Use an authenticator app": "Authenticator-App verwenden",
  "Authenticator app": "Authenticator-App",
  "Scan this code with your authenticator app, open the link on this device, or type in the key:":
    "Scannen Sie diesen Code mit Ihrer Authenticator-App, öffnen Sie den Link auf diesem Gerät oder geben Sie den Schlüssel ein:",
  "QR code for the authenticator app": "QR-Code für die Authenticator-App",
  "Open in authenticator app": "In der Authenticator-App öffnen",
  "Key": "Schlüssel",
  "Confirm": "Bestätigen",
  "Code shown by the app": "Code aus der App",
  "Recovery codes": "Wiederherstellungscodes",
  "If you lose your devices, each of these codes lets you log in once. Keep them somewhere safe – they are shown only now.":
    "Falls Sie Ihre Geräte verlieren, ermöglicht jeder dieser Codes eine Anmeldung. Bewahren Sie sie sicher auf – sie werden nur jetzt angezeigt.",
  "I have saved them": "Ich habe sie gespeichert",
  "Passkey on {platform}": "Passkey auf {platform}",
  "this device": "diesem Gerät",

  // Answering an application
  "This login has expired": "Diese Anmeldung ist abgelaufen",
  "Go back to the application and start again.": "Gehen Sie zurück zur Anwendung und beginnen Sie neu.",
  "Log in again to set up a second factor.": "Melden Sie sich erneut an, um einen zweiten Faktor einzurichten.",
  "{application} asks you to log in again.": "{application} bittet Sie, sich erneut anzumelden.",
  "Log in to continue to {application}.": "Melden Sie sich an, um zu {application} zu gelangen.",
  "Continue to {application}": "Weiter zu {application}",
  "You are logged in as {name} ({address}).": "Sie sind angemeldet als {name} ({address}).",
  "Continue as {name}": "Weiter als {name}",
  "Use another account": "Anderes Konto verwenden",
  "Know who you are": "Wissen, wer Sie sind",
  "See your name": "Ihren Namen sehen",
  "See your email address": "Ihre E-Mail-Adresse sehen",
  "Stay connected while you are not logged in": "Verbunden bleiben, während Sie nicht angemeldet sind",
  "Read and send your email (IMAP, SMTP)": "Ihre E-Mails lesen und senden (IMAP, SMTP)",
  "See your roles in this application": "Ihre Rollen in dieser Anwendung sehen",
  "Allow {application}?": "{application} erlauben?",
  "{application} asks to:": "{application} möchte:",
  "You can withdraw this on your account page at any time.":
    "Sie können das jederzeit auf Ihrer Kontoseite widerrufen.",
  "Allow": "Erlauben",
  "Not allowed": "Nicht erlaubt",
  "This account may not use {application}.": "Dieses Konto darf {application} nicht verwenden.",
  "Back to the application": "Zurück zur Anwendung",

  // The account page
  "Name": "Name",
  "Save": "Speichern",
  "Display name": "Anzeigename",
  "Saved.": "Gespeichert.",
  "Change password": "Passwort ändern",
  "Current password": "Aktuelles Passwort",
  "New password": "Neues Passwort",
  "Password changed – your other sessions have ended.": "Passwort geändert – Ihre anderen Sitzungen wurden beendet.",
  "Remove the authenticator app": "Authenticator-App entfernen",
  "The authenticator app was removed.": "Die Authenticator-App wurde entfernt.",
  "Set up an authenticator app": "Authenticator-App einrichten",
  "The authenticator app is set up.": "Die Authenticator-App ist eingerichtet.",
  "Passkeys": "Passkeys",
  "Remove": "Entfernen",
  "The passkey was removed.": "Der Passkey wurde entfernt.",
  " – last used {date}": " – zuletzt verwendet {date}",
  "never": "nie",
  "No passkeys yet.": "Noch keine Passkeys.",
  "The passkey was created.": "Der Passkey wurde erstellt.",
  "{count} left.": "{count} übrig.",
  "Make new recovery codes": "Neue Wiederherstellungscodes erstellen",
  "Applications": "Anwendungen",
  "You have not allowed any application anything yet.": "Sie haben noch keiner Anwendung etwas erlaubt.",
  " – since {date}": " – seit {date}",
  " – also while you are not logged in, since {date}": " – auch während Sie nicht angemeldet sind, seit {date}",
  "Withdraw": "Widerrufen",
  "{application} no longer has access.": "{application} hat keinen Zugriff mehr.",
  "Sessions": "Sitzungen",
  "This browser": "Dieser Browser",
  "Unknown device": "Unbekanntes Gerät",
  "End": "Beenden",
  "The session has ended.": "Die Sitzung wurde beendet.",
  "Log out": "Abmelden",
  "You are logged out.": "Sie sind abgemeldet.",
} as const;

export type Key = keyof typeof de;

function pick(): Lang {
  const asked = new URLSearchParams(window.location.search).get("lang");
  if (asked === "de" || asked === "en") return asked;
  for (const language of navigator.languages ?? [navigator.language]) {
    const primary = language.toLowerCase().split("-")[0];
    if (primary === "de" || primary === "en") return primary;
  }
  return "en";
}

export const lang: Lang = pick();

/** The text in the page's language, with `{name}` filled in from `values`. */
export function t(key: Key, values: Record<string, string | number> = {}): string {
  const text: string = lang === "de" ? de[key] : key;
  return text.replace(/\{(\w+)\}/g, (whole, name: string) => (name in values ? String(values[name]) : whole));
}

/** A date (and time) as people of the page's language write it. */
export function when(value: string | Date, withTime = true): string {
  const date = typeof value === "string" ? new Date(value) : value;
  return withTime ? date.toLocaleString(lang) : date.toLocaleDateString(lang);
}
