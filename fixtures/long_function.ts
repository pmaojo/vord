// long_function.ts — exercises the non-JSX (standard 50-line) threshold
// for the long-function rule. This is in a .ts file so the JSX threshold
// (80 lines) does NOT apply.
//
// Expected finding:
// - LongNonJSXFunction (70+ lines) → YES smells:long-function (max 50)
// - shortHelper (3 lines)           → NO finding

// This function spans ~70 lines of pure logic — no JSX in sight.
// Should flag at the standard 50-line threshold.
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

function shortHelper(x: number, y: number): number {
  return x * y + 1;
}

export { LongNonJSXFunction, shortHelper };
