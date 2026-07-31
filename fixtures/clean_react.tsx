// clean_react.tsx — exercising the generic-on-hook parser fix and
// the JSX-aware long-function threshold.
//
// Expected findings:
// - useMemo<Bucket[]> WITH deps array         → NO finding (the fix)
// - useCallback<Handler> WITH deps array      → NO finding (the fix)
// - useMemo<number> WITHOUT deps array        → YES finding (react:hook-missing-deps-array)
// - LongJSXComponent (65 lines of JSX)        → NO finding (JSX threshold 80)
// - LongNonJSXFunction (65+ lines of logic)   → YES finding (standard threshold 50)

import { useState, useEffect, useMemo, useCallback } from "react";

interface Bucket { id: number; label: string; }

function GenericHookWithDeps({ logs }: { logs: Bucket[] }) {
  const computed = useMemo<Bucket[]>(() => {
    return logs.map((l) => ({ id: l.id, label: `computed-${l.label}` }));
  }, [logs]);

  const handler = useCallback<() => void>(() => {
    console.log(computed.length);
  }, [computed]);

  return <button onClick={handler}>Count: {computed.length}</button>;
}

function GenericHookMissingDeps() {
  // Generic type argument with no deps array — should still flag.
  const value = useMemo<number>(() => {
    return Date.now() * 2;
  });

  return <span>{value}</span>;
}

// A typical React component with a lot of JSX markup — naturally long
// but not complex. Spans ~65 lines, which should pass the JSX threshold (80).
function LongJSXComponent({ items }: { items: { id: number; name: string }[] }) {
  const [selected, setSelected] = useState<number | null>(null);
  const [filter, setFilter] = useState("");

  const filtered = useMemo(() => {
    return items.filter((i) => i.name.toLowerCase().includes(filter.toLowerCase()));
  }, [items, filter]);

  if (items.length === 0) {
    return (
      <div className="empty-state">
        <p>No items to show.</p>
        <button onClick={() => setFilter("")}>Clear filter</button>
      </div>
    );
  }

  return (
    <div className="item-list-container">
      <header className="list-header">
        <h1>Items ({filtered.length})</h1>
        <input
          type="text"
          placeholder="Filter items..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </header>
      <ul className="item-list">
        {filtered.map((item) => (
          <li
            key={item.id}
            className={selected === item.id ? "selected" : ""}
            onClick={() => setSelected(item.id)}
          >
            <span className="item-id">{item.id}</span>
            <span className="item-name">{item.name}</span>
          </li>
        ))}
      </ul>
      <footer className="list-footer">
        <p>Click an item to select it.</p>
      </footer>
    </div>
  );
}

// A non-JSX function with ~70 lines of pure logic.
// The 50-line default threshold must still apply and flag this.
function LongNonJSXFunction(data: number[]): { sum: number; avg: number; min: number; max: number; median: number; q1: number; q3: number } {
  const n = data.length;
  let sum = 0;
  let min = Number.MAX_VALUE;
  let max = Number.MIN_VALUE;
  for (let i = 0; i < n; i++) {
    sum += data[i];
    if (data[i] < min) min = data[i];
    if (data[i] > max) max = data[i];
  }
  const avg = sum / n;
  for (let i = 0; i < n; i++) {
    if (data[i] < 0) data[i] = -data[i];
  }
  let variance = 0;
  for (let i = 0; i < n; i++) {
    variance += (data[i] - avg) * (data[i] - avg);
  }
  variance /= n;
  const stddev = Math.sqrt(variance);
  let withinOneSigma = 0;
  for (let i = 0; i < n; i++) {
    if (Math.abs(data[i] - avg) <= stddev) withinOneSigma++;
  }
  let withinTwoSigma = 0;
  for (let i = 0; i < n; i++) {
    if (Math.abs(data[i] - avg) <= 2 * stddev) withinTwoSigma++;
  }
  const pctOne = withinOneSigma / n;
  const pctTwo = withinTwoSigma / n;
  let trimmedSum = 0;
  let trimmedCount = 0;
  for (let i = 0; i < n; i++) {
    if (data[i] >= min + (max - min) * 0.1 && data[i] <= max - (max - min) * 0.1) {
      trimmedSum += data[i];
      trimmedCount++;
    }
  }
  const trimmedMean = trimmedCount > 0 ? trimmedSum / trimmedCount : avg;
  const sorted = [...data].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const median = sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
  const q1Idx = Math.floor(sorted.length / 4);
  const q1 = sorted[q1Idx];
  const q3Idx = Math.floor((3 * sorted.length) / 4);
  const q3 = sorted[q3Idx];
  const iqr = q3 - q1;
  const lowerFence = q1 - 1.5 * iqr;
  const upperFence = q3 + 1.5 * iqr;
  let outlierCount = 0;
  for (let i = 0; i < n; i++) {
    if (data[i] < lowerFence || data[i] > upperFence) outlierCount++;
  }
  const freq: Map<number, number> = new Map();
  for (let i = 0; i < n; i++) {
    freq.set(data[i], (freq.get(data[i]) || 0) + 1);
  }
  let mode = sorted[0];
  let modeCount = 0;
  freq.forEach((count, val) => {
    if (count > modeCount) { modeCount = count; mode = val; }
  });
  return { sum, avg, min, max, median, q1, q3 };
}

export { GenericHookWithDeps, GenericHookMissingDeps, LongJSXComponent, LongNonJSXFunction };
