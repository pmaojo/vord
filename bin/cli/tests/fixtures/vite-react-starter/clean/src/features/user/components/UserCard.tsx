import { useUser } from '../api/queries';

export function UserCard({ id }: { id: string }) {
  const { data } = useUser(id);
  return (
    <div className="flex gap-4">
      <span>{data?.name}</span>
    </div>
  );
}
