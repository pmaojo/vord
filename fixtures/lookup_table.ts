// lookup_table.ts — exercises the literal-density duplication filter.
//
// Expected findings:
// - statusColor/statusBg/statusIcon switches → NO duplication finding (suppressed by literal density)
// - validateName/validateEmail functions       → YES duplication finding (real logic, low literal density)
// - The two formatEuro functions                → YES duplication finding (identical, no placeholders at all)

// ─── Lookup-table switches (should be SUPPRESSED) ──────────────────────────

type Status = "active" | "inactive" | "pending" | "blocked" | "archived";

function statusColor(status: Status): string {
  switch (status) {
    case "active":
      return "green";
    case "inactive":
      return "gray";
    case "pending":
      return "orange";
    case "blocked":
      return "red";
    case "archived":
      return "dimgray";
    default:
      return "black";
  }
}

function statusBg(status: Status): string {
  switch (status) {
    case "active":
      return "#e8f5e9";
    case "inactive":
      return "#f5f5f5";
    case "pending":
      return "#fff3e0";
    case "blocked":
      return "#ffebee";
    case "archived":
      return "#eceff1";
    default:
      return "#ffffff";
  }
}

function statusIcon(status: Status): string {
  switch (status) {
    case "active":
      return "✅";
    case "inactive":
      return "⏸️";
    case "pending":
      return "⏳";
    case "blocked":
      return "🚫";
    case "archived":
      return "📦";
    default:
      return "❓";
  }
}

// ─── Real duplicated logic (should be FLAGGED) ──────────────────────────────

function validateName(name: unknown): string | null {
  if (typeof name !== "string") {
    return `Expected string, got ${typeof name}`;
  }
  const trimmed = name.trim();
  if (trimmed.length === 0) {
    return "Name must not be empty";
  }
  if (trimmed.length < 2) {
    return "Name must be at least 2 characters";
  }
  if (trimmed.length > 100) {
    return "Name must be at most 100 characters";
  }
  if (!/^[a-zA-Z0-9 ]+$/.test(trimmed)) {
    return "Name contains invalid characters";
  }
  return null;
}

function validateEmail(email: unknown): string | null {
  if (typeof email !== "string") {
    return `Expected string, got ${typeof email}`;
  }
  const trimmed = email.trim();
  if (trimmed.length === 0) {
    return "Email must not be empty";
  }
  if (trimmed.length < 5) {
    return "Email must be at least 5 characters";
  }
  if (trimmed.length > 254) {
    return "Email must be at most 254 characters";
  }
  if (!/^[^@]+@[^@]+$/.test(trimmed)) {
    return "Email must contain exactly one @";
  }
  return null;
}

// ─── Exact-structure duplication with no placeholders (should be FLAGGED) ───

function formatEuro(amount: number): string {
  const whole = Math.floor(amount);
  const cents = Math.round((amount - whole) * 100);
  return `${whole},${cents.toString().padStart(2, "0")} €`;
}

function formatDollar(amount: number): string {
  const whole = Math.floor(amount);
  const cents = Math.round((amount - whole) * 100);
  return `$${whole}.${cents.toString().padStart(2, "0")}`;
}

export { statusColor, statusBg, statusIcon, validateName, validateEmail, formatEuro, formatDollar };
