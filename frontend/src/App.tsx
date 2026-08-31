import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import ConnectAgent from './pages/ConnectAgent';
import Dashboard from './pages/Dashboard';
import AgentHub from './pages/AgentHub';
import PolicyCenter from './pages/PolicyCenter';
import HITLReview from './pages/HITLReview';
import AuditLog from './pages/AuditLog';
import SecurityCenter from './pages/SecurityCenter';
import Sessions from './pages/Sessions';
import LiveSession from './pages/LiveSession';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Landing — connect an agent first */}
        <Route path="/connect" element={<ConnectAgent />} />

        {/* Live session — full-screen terminal + broker */}
        <Route path="/live/:runId" element={<LiveSession />} />

        {/* Dashboard & tools — accessible after connecting */}
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/agents" element={<AgentHub />} />
          <Route path="/policies" element={<PolicyCenter />} />
          <Route path="/hitl" element={<HITLReview />} />
          <Route path="/audit" element={<AuditLog />} />
          <Route path="/security" element={<SecurityCenter />} />
          <Route path="/sessions" element={<Sessions />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
