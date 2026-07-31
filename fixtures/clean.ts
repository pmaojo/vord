// clean.ts — negative regression fixture for TypeScript rules.
//
// Adapted from ESLint/typescript-eslint valid-code patterns (MIT).
//
// Expected: NO typescript:* issues on this file.

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

export function createToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function setMessage(el: HTMLElement, text: string): void {
  el.textContent = text;
}

export function chain(): Promise<void> {
  return fetch("/api").then(() => {}).catch(() => {});
}

export const value = 42;
