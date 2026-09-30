export function nvdDataAge(retrievedAt: string | null | undefined, now = Date.now()) {
  if (!retrievedAt) return "age unavailable";
  const retrieved = Date.parse(retrievedAt);
  if (!Number.isFinite(retrieved)) return "age unavailable";
  const minutes = Math.max(0, Math.floor((now - retrieved) / 60_000));
  if (minutes < 1) return "less than 1 min old";
  if (minutes < 60) return `${minutes} min old`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} hr old`;
  return `${Math.floor(hours / 24)} d old`;
}
