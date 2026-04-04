import { useState } from "react";

const apiBase = import.meta.env.VITE_API_BASE || "/api";

export default function App() {
  const [status, setStatus] = useState("idle");

  const triggerCollection = async () => {
    setStatus("triggering");
    const res = await fetch(`${apiBase}/fortiweb/collect`, { method: "POST" });
    const body = await res.json();
    setStatus(`Queued task ${body.task_id}`);
  };

  return (
    <main style={{ fontFamily: "sans-serif", maxWidth: 800, margin: "2rem auto" }}>
      <h1>SecurityPerspective</h1>
      <p>Containerized FortiWeb maturity assessment starter stack.</p>
      <button onClick={triggerCollection}>Trigger FortiWeb Collection</button>
      <p>Status: {status}</p>
    </main>
  );
}
