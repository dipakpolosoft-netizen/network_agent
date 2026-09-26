"use client";

import { ArrowLeft, LoaderCircle, LockKeyhole } from "lucide-react";
import Link from "next/link";
import { type FormEvent, useEffect, useState } from "react";

import { api } from "@/lib/api";

export default function AccountPage() {
  const [email, setEmail] = useState("");
  const [current, setCurrent] = useState("");
  const [replacement, setReplacement] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    void api.me().then((session) => {
      if (!session.auth_required) { window.location.replace("/network-agent"); return; }
      setEmail(session.user?.email ?? "");
    })
      .catch((cause) => setError(cause instanceof Error ? cause.message : "Session unavailable"));
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (replacement !== confirm) { setError("New passwords do not match"); return; }
    setBusy(true);
    setError("");
    try {
      await api.changePassword(current, replacement);
      window.location.assign("/login");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Password could not be changed");
      setBusy(false);
    }
  }

  return <main className="auth-page"><div className="auth-content">
    <Link className="button secondary" href="/network-agent"><ArrowLeft size={15} />Network Agent</Link>
    <div className="auth-heading account-heading"><span className="eyebrow">ACCOUNT</span><h1>Change password</h1><p>{email}</p></div>
    <form className="auth-form" onSubmit={(event) => void submit(event)}>
      <label>Current password<input type="password" autoComplete="current-password" required value={current} onChange={(event) => setCurrent(event.target.value)} /></label>
      <label>New password<input type="password" autoComplete="new-password" minLength={12} required value={replacement} onChange={(event) => setReplacement(event.target.value)} /></label>
      <label>Confirm new password<input type="password" autoComplete="new-password" minLength={12} required value={confirm} onChange={(event) => setConfirm(event.target.value)} /></label>
      {error && <div className="auth-error" role="alert"><LockKeyhole size={15} />{error}</div>}
      <button className="button primary full" type="submit" disabled={busy || !email}>{busy ? <LoaderCircle className="spin" size={15} /> : <LockKeyhole size={15} />}Update password</button>
    </form>
  </div></main>;
}
