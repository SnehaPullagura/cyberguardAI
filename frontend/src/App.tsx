import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { DashboardPage } from './pages/DashboardPage';
import { EventsPage } from './pages/EventsPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { RulesPage } from './pages/RulesPage';
import { MLPage } from './pages/MLPage';
import { LoginPage } from './pages/LoginPage';
import { InvestigationPage } from './pages/InvestigationPage';
import { ComplianceReportsPage } from './pages/ComplianceReportsPage';
import { ThreatHuntingPage } from './pages/ThreatHuntingPage';
import { VulnerabilityPosturePage } from './pages/VulnerabilityPosturePage';

export const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(
    Boolean(localStorage.getItem('access_token') || localStorage.getItem('token'))
  );

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('token');
    setIsAuthenticated(false);
  };

  if (!isAuthenticated) {
    return <LoginPage onLoginSuccess={() => setIsAuthenticated(true)} />;
  }

  return (
    <Router>
      <div className="min-h-screen bg-slate-950 flex flex-col">
        <Navbar onLogout={handleLogout} />
        <div className="flex flex-1">
          <Sidebar />
          <main className="flex-1 p-6 overflow-y-auto">
            <Routes>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/events" element={<EventsPage />} />
              <Route path="/incidents" element={<IncidentsPage />} />
              <Route path="/investigations" element={<InvestigationPage />} />
              <Route path="/hunting" element={<ThreatHuntingPage />} />
              <Route path="/posture" element={<VulnerabilityPosturePage />} />
              <Route path="/compliance" element={<ComplianceReportsPage />} />
              <Route path="/rules" element={<RulesPage />} />
              <Route path="/ml" element={<MLPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </div>
    </Router>
  );
};

export default App;
