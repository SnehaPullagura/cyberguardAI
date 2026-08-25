import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Activity, AlertTriangle, Cpu, FileText, Settings } from 'lucide-react';

export const Sidebar: React.FC = () => {
  const navItems = [
    { label: 'Dashboard', path: '/', icon: LayoutDashboard },
    { label: 'Events Stream', path: '/events', icon: Activity },
    { label: 'Incidents Board', path: '/incidents', icon: AlertTriangle },
    { label: 'Detection Rules', path: '/rules', icon: Settings },
    { label: 'AI & ML Pipeline', path: '/ml', icon: Cpu },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-slate-900/50 p-4 flex flex-col justify-between hidden md:flex min-h-[calc(100vh-4rem)]">
      <nav className="space-y-1">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              `flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
                isActive
                  ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`
            }
          >
            <item.icon className="w-5 h-5" />
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800 text-xs text-slate-400 space-y-1">
        <div className="font-semibold text-slate-300">CyberGuard AI Engine</div>
        <div>v1.0.0 (FastAPI + PyTorch)</div>
        <div className="text-emerald-400">● 100% Ingestion Ready</div>
      </div>
    </aside>
  );
};
