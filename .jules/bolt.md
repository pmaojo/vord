## 2024-07-25 - Avoid String Allocation in propagate_bindings Hot Loop
**Learning:** We can bypass unconditional `.entry(key.to_string()).or_default()` in tight fixed-point iteration loops over `HashMap<String, T>`. Even if the key is typically borrowed, `.entry()` always takes ownership, allocating even if the key is already present.
**Action:** Use a `.get_mut(borrowed_key)` followed by a `.insert(borrowed_key.to_string(), ...)` fallback when dealing with string-keyed HashMaps inside hot loops, keeping allocations strictly proportional to the number of *unique* elements, rather than the number of iterations.
## 2026-07-27 - Remove redundant allocations inside hot loops\n**Learning:** Several internal HashMaps in core loop regions (, cross-file ) were performing  or string format allocation unconditionally or storing duplicate representations of function keys.\n**Action:** Replaced  allocating operations inside loops with  fast paths, removed string cloning when we can borrow or store  instead, and documented the performance improvements.

## 2024-07-27 - Remove redundant allocations inside hot loops
**Learning:** Several internal HashMaps in core loop regions (`file_issue_measures`, cross-file `summaries`) were performing `.clone()` or string format allocation unconditionally or storing duplicate representations of function keys.
**Action:** Replaced `.entry()` allocating operations inside loops with `.get_mut()` fast paths, removed string cloning when we can borrow or store `FunctionKey` instead, and documented the performance improvements.
