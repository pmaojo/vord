// clean.ts — negative regression corpus for TypeScript rules.
//
// Adapted from ESLint/typescript-eslint valid-code patterns (MIT).
// Scanned under a production-like path (`app/src/`) so rules that skip
// `fixtures/` still run here.
//
// Expected: NO typescript:* or owasp:* findings on this file.

export function greet(name: string): string {
  if (name === "") {
    return "anonymous";
  }
  return `hello ${name}`;
}

export async function loadUser(id: string): Promise<unknown> {
  try {
    const response = await fetch(`/api/users/${id}`);
    return JSON.parse(await response.text());
  } catch (error) {
    console.error("load failed", error);
    throw error;
  }
}

export function savePreference(key: string, value: string): void {
  if (key !== "theme") {
    return;
  }
  localStorage.setItem(key, value);
}

export function createToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function assignSafe(body: Record<string, unknown>): { name: string } {
  return { name: String(body.name ?? "") };
}

export function setMessage(el: HTMLElement, text: string): void {
  el.textContent = text;
}

export function redirect(): void {
  window.location.href = "https://example.com/dashboard";
}

const pattern = /^[a-z]+$/;

export function matchWord(word: string): boolean {
  return pattern.test(word);
}

export function chain(): Promise<void> {
  return fetch("/api").then(() => {}).catch(() => {});
}

export const value = 42;
