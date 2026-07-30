"use client";

import type { FormEvent, ReactNode } from "react";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  type AuthSnapshot,
  type AuthView,
  authViewFor,
  BOOTSTRAP_PASSWORD_MIN_LENGTH,
  bootstrapPasswordError,
  meetsBootstrapPasswordMinimum,
  sessionRefreshDelay,
} from "../lib/auth";
import {
  AuthRequestError,
  authClient,
  LatestAuthSnapshotLoader,
  logoutAndRefresh,
} from "../lib/auth-client";

type SessionState =
  | { status: "checking" }
  | { status: "failed"; message: string }
  | { status: "ready"; snapshot: AuthSnapshot };

const formContent: Record<
  Exclude<AuthView, "workspace" | "bootstrap-unavailable">,
  {
    eyebrow: string;
    title: string;
    description: string;
    button: string;
    autocomplete: "current-password" | "new-password";
  }
> = {
  bootstrap: {
    eyebrow: "First-run setup",
    title: "Secure this workspace",
    description:
      "Create the local admin password. Use at least 15 characters; Mathews will require it before showing the workspace.",
    button: "Create password and continue",
    autocomplete: "new-password",
  },
  login: {
    eyebrow: "Protected workspace",
    title: "Welcome back",
    description: "Enter the local admin password to continue to Mathews.",
    button: "Sign in",
    autocomplete: "current-password",
  },
};

function messageFrom(error: unknown, fallback: string): string {
  if (error instanceof AuthRequestError) {
    return error.message;
  }
  if (error instanceof Error && error.message.startsWith("The control plane returned")) {
    return error.message;
  }
  return fallback;
}

function AuthForm({
  view,
  password,
  bootstrapToken,
  passwordConfirmation,
  error,
  pending,
  onPasswordChange,
  onBootstrapTokenChange,
  onPasswordConfirmationChange,
  onSubmit,
}: {
  view: Exclude<AuthView, "workspace" | "bootstrap-unavailable">;
  password: string;
  bootstrapToken: string;
  passwordConfirmation: string;
  error: string | null;
  pending: boolean;
  onPasswordChange: (password: string) => void;
  onBootstrapTokenChange: (token: string) => void;
  onPasswordConfirmationChange: (password: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  const content = formContent[view];

  return (
    <main className="auth-main">
      <section className="auth-card" aria-labelledby="auth-heading">
        <div className="auth-mark" aria-hidden="true">
          M
        </div>
        <p className="eyebrow">{content.eyebrow}</p>
        <h1 id="auth-heading">{content.title}</h1>
        <p className="auth-description">{content.description}</p>

        <form className="auth-form" onSubmit={onSubmit}>
          {view === "bootstrap" ? (
            <>
              <label htmlFor="bootstrap-token">One-time bootstrap token</label>
              <input
                id="bootstrap-token"
                name="bootstrap-token"
                type="password"
                autoComplete="one-time-code"
                value={bootstrapToken}
                onChange={(event) => onBootstrapTokenChange(event.currentTarget.value)}
                required
              />
            </>
          ) : null}
          <label htmlFor="password">Password</label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete={content.autocomplete}
            value={password}
            onChange={(event) => onPasswordChange(event.currentTarget.value)}
            required
            minLength={view === "bootstrap" ? BOOTSTRAP_PASSWORD_MIN_LENGTH : undefined}
            aria-describedby={view === "bootstrap" ? "bootstrap-password-policy" : undefined}
          />
          {view === "bootstrap" ? (
            <>
              <p className="auth-help" id="bootstrap-password-policy">
                Minimum 15 characters.
              </p>
              <label htmlFor="password-confirmation">Confirm password</label>
              <input
                id="password-confirmation"
                name="password-confirmation"
                type="password"
                autoComplete="new-password"
                value={passwordConfirmation}
                onChange={(event) => onPasswordConfirmationChange(event.currentTarget.value)}
                required
                minLength={BOOTSTRAP_PASSWORD_MIN_LENGTH}
              />
            </>
          ) : null}
          {error ? (
            <p className="auth-error" role="alert">
              {error}
            </p>
          ) : null}
          <button
            type="submit"
            disabled={
              pending ||
              password.length === 0 ||
              (view === "bootstrap" &&
                (bootstrapToken.length === 0 ||
                  !meetsBootstrapPasswordMinimum(password) ||
                  passwordConfirmation.length === 0))
            }
          >
            {pending ? "Checking…" : content.button}
          </button>
        </form>
        <p className="auth-footnote">Session state is verified by the local control plane.</p>
      </section>
    </main>
  );
}

export function AuthGate({ children }: { children: ReactNode }) {
  const [sessionState, setSessionState] = useState<SessionState>({ status: "checking" });
  const [password, setPassword] = useState("");
  const [bootstrapToken, setBootstrapToken] = useState("");
  const [passwordConfirmation, setPasswordConfirmation] = useState("");
  const [requestError, setRequestError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const sessionLoader = useRef<LatestAuthSnapshotLoader | null>(null);
  if (sessionLoader.current === null) {
    sessionLoader.current = new LatestAuthSnapshotLoader();
  }

  const loadSession = useCallback(async (signal?: AbortSignal): Promise<AuthSnapshot | null> => {
    setSessionState({ status: "checking" });
    try {
      const snapshot = await sessionLoader.current?.load(signal);
      if (!snapshot) {
        return null;
      }
      setSessionState({ status: "ready", snapshot });
      return snapshot;
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        return null;
      }
      setSessionState({
        status: "failed",
        message: messageFrom(error, "Unable to reach the control plane."),
      });
      return null;
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void loadSession(controller.signal);
    return () => controller.abort();
  }, [loadSession]);

  useEffect(() => {
    if (sessionState.status !== "ready" || sessionState.snapshot.session === null) {
      return;
    }

    const delay = sessionRefreshDelay(sessionState.snapshot.session.expires_at);
    const timeout = window.setTimeout(() => void loadSession(), delay);
    return () => window.clearTimeout(timeout);
  }, [loadSession, sessionState]);

  if (sessionState.status === "checking") {
    return (
      <main className="auth-main">
        <div className="auth-status" role="status" aria-live="polite">
          <span className="status-dot" aria-hidden="true" />
          Verifying session…
        </div>
      </main>
    );
  }

  if (sessionState.status === "failed") {
    return (
      <main className="auth-main">
        <section className="auth-card auth-card-compact" aria-labelledby="unavailable-heading">
          <p className="eyebrow">Control plane unavailable</p>
          <h1 id="unavailable-heading">Workspace locked</h1>
          <p className="auth-description">{sessionState.message}</p>
          <button
            className="auth-secondary-button"
            type="button"
            onClick={() => void loadSession()}
          >
            Try again
          </button>
        </section>
      </main>
    );
  }

  const view = authViewFor(sessionState.snapshot);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (
      view === "workspace" ||
      view === "bootstrap-unavailable" ||
      !password ||
      (view === "bootstrap" && (!bootstrapToken || !passwordConfirmation))
    ) {
      return;
    }

    if (view === "bootstrap") {
      const passwordError = bootstrapPasswordError(password, passwordConfirmation);
      if (passwordError) {
        setRequestError(passwordError);
        setPassword("");
        setBootstrapToken("");
        setPasswordConfirmation("");
        return;
      }
    }

    setPending(true);
    setRequestError(null);
    try {
      if (view === "bootstrap") {
        await authClient.bootstrap(bootstrapToken, password);
      } else {
        await authClient.login(password);
      }
      setPassword("");
      setBootstrapToken("");
      setPasswordConfirmation("");
      await loadSession();
    } catch (error) {
      setPassword("");
      setBootstrapToken("");
      setPasswordConfirmation("");
      setRequestError(messageFrom(error, "Authentication failed."));
    } finally {
      setPending(false);
    }
  }

  async function handleLogout() {
    sessionLoader.current?.invalidate();
    setSessionState({ status: "checking" });
    setPending(true);
    setRequestError(null);
    try {
      const result = await logoutAndRefresh(() => loadSession());
      if (result.error && result.snapshot?.session) {
        setRequestError(messageFrom(result.error, "Unable to sign out."));
      }
    } finally {
      setPending(false);
    }
  }

  if (view === "bootstrap-unavailable") {
    return (
      <main className="auth-main">
        <section className="auth-card auth-card-compact" aria-labelledby="bootstrap-heading">
          <p className="eyebrow">First-run setup</p>
          <h1 id="bootstrap-heading">Bootstrap unavailable</h1>
          <p className="auth-description">
            This workspace still needs an admin password, but the one-time bootstrap window is not
            available. Run <code>npm run auth:bootstrap-token</code> to issue one, then try again.
          </p>
          <button
            className="auth-secondary-button"
            type="button"
            onClick={() => void loadSession()}
          >
            Check again
          </button>
        </section>
      </main>
    );
  }

  if (view !== "workspace") {
    return (
      <AuthForm
        view={view}
        password={password}
        bootstrapToken={bootstrapToken}
        passwordConfirmation={passwordConfirmation}
        error={requestError}
        pending={pending}
        onPasswordChange={setPassword}
        onBootstrapTokenChange={setBootstrapToken}
        onPasswordConfirmationChange={setPasswordConfirmation}
        onSubmit={handleSubmit}
      />
    );
  }

  return (
    <div className="workspace-shell">
      <header className="session-bar">
        <div>
          <span className="session-indicator" aria-hidden="true" />
          Authenticated session
        </div>
        <button type="button" onClick={() => void handleLogout()} disabled={pending}>
          {pending ? "Signing out…" : "Sign out"}
        </button>
      </header>
      {requestError ? (
        <p className="session-error" role="alert">
          {requestError}
        </p>
      ) : null}
      {children}
    </div>
  );
}
