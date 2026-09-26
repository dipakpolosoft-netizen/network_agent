"use client";

import { ArrowLeft, LoaderCircle, LogOut, Plus, Users } from "lucide-react";
import Link from "next/link";
import { type FormEvent, useEffect, useState } from "react";

import { api, type OperatorUser } from "@/lib/api";

export default function UsersPage() {
  const [current, setCurrent] = useState<OperatorUser | null>(null);
  const [users, setUsers] = useState<OperatorUser[]>([]);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<OperatorUser["role"]>("viewer");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    void api.me().then(async (session) => {
      if (session.user?.role !== "admin") {
        window.location.replace("/network-agent");
        return;
      }
      setCurrent(session.user);
      setUsers(await api.users());
    }).catch((cause) => setError(cause instanceof Error ? cause.message : "Unable to load users"));
  }, []);

  async function create(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const user = await api.createUser(email, password, role);
      setUsers((items) => [...items, user].sort((a, b) => a.email.localeCompare(b.email)));
      setEmail("");
      setPassword("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "User could not be created");
    } finally { setBusy(false); }
  }

  async function toggle(user: OperatorUser) {
    setBusy(true);
    setError("");
    try {
      const updated = await api.setUserActive(user.user_id, !user.active);
      setUsers((items) => items.map((item) => item.user_id === updated.user_id ? updated : item));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "User could not be updated");
    } finally { setBusy(false); }
  }

  return <main className="users-page">
    <header className="users-header"><Link href="/network-agent" className="button secondary"><ArrowLeft size={15} />Network Agent</Link><img src="/logos/forge-sec-logo.png" alt="ForgeSec" /><button className="button secondary" onClick={() => void api.logout().then(() => window.location.assign("/login"))}><LogOut size={15} />Sign out</button></header>
    <div className="users-content"><div className="users-title"><div><span className="eyebrow">ACCESS CONTROL</span><h1>Operators</h1></div><span>{users.length} users</span></div>
      {error && <div className="auth-error" role="alert">{error}</div>}
      <section className="users-section"><h2><Users size={17} />Access list</h2><div className="table-scroll"><table><thead><tr><th>Email</th><th>Role</th><th>Status</th><th>Created</th><th aria-label="Action" /></tr></thead><tbody>{users.map((user) => <tr key={user.user_id}><td><strong>{user.email}</strong>{user.user_id === current?.user_id && <small>You</small>}</td><td>{user.role}</td><td>{user.active ? "Active" : "Disabled"}</td><td>{new Date(user.created_at).toLocaleDateString()}</td><td><button className="button secondary compact" disabled={busy || user.user_id === current?.user_id} onClick={() => void toggle(user)}>{user.active ? "Disable" : "Enable"}</button></td></tr>)}</tbody></table></div></section>
      <section className="users-section"><h2><Plus size={17} />Add operator</h2><form className="users-form" onSubmit={(event) => void create(event)}><label>Email<input type="email" required value={email} onChange={(event) => setEmail(event.target.value)} /></label><label>Initial password<input type="password" minLength={12} required autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label><label>Role<select value={role} onChange={(event) => setRole(event.target.value as OperatorUser["role"])}><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option></select></label><button className="button primary" disabled={busy}>{busy ? <LoaderCircle className="spin" size={15} /> : <Plus size={15} />}Create user</button></form></section>
    </div>
  </main>;
}
