import React from 'react';
import { Shield, Bell, User, LogOut } from 'lucide-react';

interface NavbarProps {
  onLogout: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ onLogout }) => {
  return (
    <header className="h-16 border-b border-slate-800 bg-slate-900/80 backdrop-blur px-6 flex items-center justify-between sticky top-0 z-40">
      <div className="flex items-center space-x-3">
        <Shield className="w-7 h-7 text-indigo-500" />
        <span className="font-bold text-xl tracking-tight bg-gradient-to-r from-indigo-400 to-cyan-400 bg-clip-text text-transparent">
          CyberGuard AI
        </span>
        <span className="ml-2 px-2.5 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          LIVE SOC ACTIVE
        </span>
      </div>

      <div className="flex items-center space-x-4">
        <button className="p-2 text-slate-400 hover:text-slate-200 rounded-lg hover:bg-slate-800 transition">
          <Bell className="w-5 h-5" />
        </button>
        <div className="h-5 w-px bg-slate-800" />
        <div className="flex items-center space-x-2 text-sm text-slate-300">
          <User className="w-4 h-4 text-indigo-400" />
          <span className="font-medium">admin</span>
        </div>
        <button
          onClick={onLogout}
          className="p-2 text-slate-400 hover:text-rose-400 rounded-lg hover:bg-rose-500/10 transition"
          title="Sign Out"
        >
          <LogOut className="w-5 h-5" />
        </button>
      </div>
    </header>
  );
};
