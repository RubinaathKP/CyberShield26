import { Activity, Shield, Target, Database, MessageSquare } from 'lucide-react'
import { PageKey } from '../App'

interface SidebarProps {
  activePage: PageKey
  onNavigate: (page: PageKey) => void
}

export default function Sidebar({ activePage, onNavigate }: SidebarProps) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="sidebar-brand-icon">
          <Shield size={22} strokeWidth={2.5} />
        </div>
        <div className="sidebar-brand-text">
          <h1>SyscallSentinel</h1>
          <span>Advanced Honeypot</span>
        </div>
      </div>
      
      <nav className="sidebar-nav">
        <div className="nav-section-label">Main</div>
        
        <div 
          className={`nav-item ${activePage === 'dashboard' ? 'active' : ''}`}
          onClick={() => onNavigate('dashboard')}
        >
          <Activity />
          Dashboard Overview
        </div>
        
        <div 
          className={`nav-item ${activePage === 'detection' ? 'active' : ''}`}
          onClick={() => onNavigate('detection')}
        >
          <Target />
          Live Detection
        </div>
        
        <div className="nav-section-label">System Logs</div>
        
        <div 
          className={`nav-item ${activePage === 'honeypot' ? 'active' : ''}`}
          onClick={() => onNavigate('honeypot')}
        >
          <Database />
          Honeypot Logs
        </div>
        
        <div className="nav-section-label">Settings</div>
        
        <div 
          className={`nav-item ${activePage === 'feedback' ? 'active' : ''}`}
          onClick={() => onNavigate('feedback')}
        >
          <MessageSquare />
          Alert Feedback
        </div>
      </nav>
      
      <div className="sidebar-footer">
        <div className="health-indicator">
          <div className="health-dot"></div>
          System Online
        </div>
      </div>
    </aside>
  )
}
