"use client";

import { LoaderCircle, LockKeyhole, LogIn } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";

import { api } from "@/lib/api";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [checking, setChecking] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    void api.me().then(() => {
      window.location.replace("/network-agent");
    }).catch(() => setChecking(false));
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.login(email, password);
      const next = new URLSearchParams(window.location.search).get("next") || "/network-agent";
      window.location.assign(next.startsWith("/") && !next.startsWith("//") ? next : "/network-agent");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Sign-in failed");
      setBusy(false);
    }
  }

  return <main className="auth-page">
    <div className="auth-content">
      <img className="auth-logo" src="/logos/forge-sec-logo.png" alt="ForgeSec" />
      <div className="auth-heading"><span className="eyebrow">OPERATOR ACCESS</span><h1>Sign in to ForgeSec</h1><p>Network operations console</p></div>
      <form className="auth-form" onSubmit={(event) => void submit(event)}>
        <label>Email<input type="email" autoComplete="username" required value={email} onChange={(event) => setEmail(event.target.value)} disabled={checking || busy} /></label>
        <label>Password<input type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} disabled={checking || busy} /></label>
        {error && <div className="auth-error" role="alert"><LockKeyhole size={15} />{error}</div>}
        <button className="button primary full" type="submit" disabled={checking || busy}>{checking || busy ? <LoaderCircle className="spin" size={16} /> : <LogIn size={16} />}{checking ? "Checking session" : busy ? "Signing in" : "Sign in"}</button>
      </form>
    </div>
  </main>;
}
