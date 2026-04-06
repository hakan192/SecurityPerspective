export default function App() {
  return (
    <main style={{ fontFamily: 'Arial, sans-serif', padding: '2rem' }}>
      <h1>Security Perspective</h1>
      <p>Phase 1 foundation is active.</p>
      <ul>
        <li>Backend: FastAPI</li>
        <li>Frontend: React (Vite)</li>
        <li>Database: PostgreSQL</li>
        <li>Queue/Scheduler: Redis + Celery</li>
      </ul>
      <p>Next: implement dashboard views for raw snapshots and maturity scoring.</p>
    </main>
  )
}
