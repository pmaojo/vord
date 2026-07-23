// Deliberately React-anti-pattern-riddled component used to exercise the
// react ruleset.
import { useEffect, useState } from "react";

function Bad({ items, flag }: { items: { id: number; name: string }[]; flag: boolean }) {
  if (!flag) return null;

  const [count, setCount] = useState(0);
  const [rows, setRows] = useState<{ id: number; name: string }[]>([]);

  useEffect(() => {
    console.log(count);
  });

  function addRow(row: { id: number; name: string }) {
    rows.push(row);
  }

  return (
    <div>
      {items.map((item, index) => (
        <li key={index}>{item.name}</li>
      ))}
      <Row onSelect={() => setCount(count + 1)} config={{ big: true }} />
      <img src="logo.png" />
      <div dangerouslySetInnerHTML={{ __html: rows[0]?.name }} />
      <a href="https://example.com" target="_blank">
        external
      </a>
    </div>
  );
}

export default Bad;
