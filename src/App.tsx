import { useState } from 'react'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import LiveDetection from './pages/LiveDetection'
import HoneypotLogs from './pages/HoneypotLogs'
import Feedback from './pages/Feedback'
import DemoScenarios from './pages/DemoScenarios'
import Compare from './pages/Compare'

export type PageKey = 'dashboard' | 'detection' | 'honeypot' | 'feedback' | 'demo' | 'compare'

export default function App() {
  const [activePage, setActivePage] = useState<PageKey>('dashboard')

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard':
        return <Dashboard />
      case 'detection':
        return <LiveDetection />
      case 'honeypot':
        return <HoneypotLogs />
      case 'feedback':
        return <Feedback />
      case 'demo':
        return <DemoScenarios />
      case 'compare':
        return <Compare />
      default:
        return <Dashboard />
    }
  }

  return (
    <div className="app-layout">
      <Sidebar activePage={activePage} onNavigate={setActivePage} />
      <main className="main-content">
        {renderPage()}
      </main>
    </div>
  )
}
