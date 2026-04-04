import { useEffect, useState } from 'react';
import axios from 'axios';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import ScoreCard from './components/ScoreCard';

const api = axios.create({ baseURL: '/api/v1' });
const COLORS = ['#10b981', '#ef4444', '#f59e0b', '#3b82f6'];

export default function App() {
  const [snapshots, setSnapshots] = useState([]);
  const [selectedSnapshot, setSelectedSnapshot] = useState(null);
  const [assessment, setAssessment] = useState(null);
  const [rawJson, setRawJson] = useState('');

  const loadSnapshots = async () => {
    const { data } = await api.get('/fortiweb/snapshots');
    setSnapshots(data);
    if (data.length > 0 && !selectedSnapshot) {
      setSelectedSnapshot(data[0]);
    }
  };

  const collect = async () => {
    await api.post('/fortiweb/snapshots');
    await loadSnapshots();
  };

  const runAssessment = async () => {
    if (!selectedSnapshot) return;
    const { data } = await api.post(`/analysis/assess/${selectedSnapshot.id}`);
    setAssessment(data);
  };

  useEffect(() => {
    loadSnapshots();
  }, []);

  useEffect(() => {
    if (selectedSnapshot) {
      setRawJson(JSON.stringify(selectedSnapshot.raw_payload, null, 2));
      setAssessment(null);
    }
  }, [selectedSnapshot]);

  const categoryData = assessment
    ? Object.entries(assessment.category_scores).map(([name, value]) => ({ name, value: Math.round(value) }))
    : [];

  return (
    <div className="container">
      <h1>SecurityPerspective</h1>
      <p>FortiWeb configuration visibility and maturity assessment dashboard.</p>

      <div className="actions">
        <button onClick={collect}>Collect Snapshot</button>
        <button onClick={runAssessment} disabled={!selectedSnapshot}>Run Assessment</button>
      </div>

      <div className="layout">
        <section>
          <h2>Snapshots</h2>
          {snapshots.map((snapshot) => (
            <button
              key={snapshot.id}
              className={selectedSnapshot?.id === snapshot.id ? 'snapshot selected' : 'snapshot'}
              onClick={() => setSelectedSnapshot(snapshot)}
            >
              #{snapshot.id} - {new Date(snapshot.collected_at).toLocaleString()}
            </button>
          ))}
        </section>

        <section>
          <h2>Raw Response</h2>
          <pre>{rawJson || 'No data yet'}</pre>
        </section>

        <section>
          <h2>Maturity Analysis</h2>
          {assessment ? (
            <>
              <div className="cards">
                <ScoreCard title="Overall Score" value={`${assessment.overall_score}%`} />
                <ScoreCard title="Maturity Level" value={assessment.maturity_level} />
              </div>
              <div className="chart-wrapper">
                <ResponsiveContainer width="100%" height={240}>
                  <PieChart>
                    <Pie data={categoryData} dataKey="value" nameKey="name" outerRadius={85}>
                      {categoryData.map((entry, index) => (
                        <Cell key={entry.name} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </>
          ) : (
            <p>Run an assessment to view maturity scores.</p>
          )}
        </section>
      </div>
    </div>
  );
}
