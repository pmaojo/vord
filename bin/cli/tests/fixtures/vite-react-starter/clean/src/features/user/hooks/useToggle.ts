import { useState } from 'react';

export function useToggle(initial: boolean) {
  const [value, setValue] = useState(initial);
  return [value, () => setValue((v) => !v)] as const;
}
