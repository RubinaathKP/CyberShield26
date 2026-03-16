import { render, screen, waitFor } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import Dashboard from './Dashboard'
import { api } from '../api'

// Mock the Recharts module so its size calculations don't crash jsdom
vi.mock('recharts', async () => {
  const OriginalModule = await vi.importActual('recharts')
  return {
    ...OriginalModule as object,
    ResponsiveContainer: ({ children }: any) => <div>{children}</div>
  }
})

// Mock the API calls
vi.mock('../api', () => ({
  api: {
    getMetrics: vi.fn(),
    getHoneypotLog: vi.fn(),
  }
}))

describe('Dashboard Component', () => {
  it('renders loading state initially and then shows data', async () => {
    // Setup mock data
    const mockMetrics = {
      total_alerts: 100,
      honeypot_events: 50,
      honeypot_ip_count: 10,
      retrain_events: 5
    }
    const mockLogs = [
      { timestamp: 1600000000, event_type: 'rce_attempt', path: '/bin/sh' },
      { timestamp: 1600000100, event_type: 'sql_injection', path: '/api/login' },
    ]

    vi.mocked(api.getMetrics).mockResolvedValue(mockMetrics)
    vi.mocked(api.getHoneypotLog).mockResolvedValue(mockLogs)

    render(<Dashboard />)

    // Wait for the components to load data
    await waitFor(() => {
      expect(screen.getByText('Dashboard Overview')).toBeInTheDocument()
    })

    // Check if metric values rendered correctly
    expect(screen.getByText('100')).toBeInTheDocument()
    expect(screen.getByText('50')).toBeInTheDocument()
    expect(screen.getByText('10')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()

    // Check if the mock logs rendered
    expect(screen.getByText('rce_attempt')).toBeInTheDocument()
    expect(screen.getByText('sql_injection')).toBeInTheDocument()
    expect(screen.getByText('/bin/sh')).toBeInTheDocument()
  })

  it('handles API errors gracefully', async () => {
    vi.mocked(api.getMetrics).mockRejectedValue(new Error('API failed'))
    vi.mocked(api.getHoneypotLog).mockRejectedValue(new Error('API failed'))

    render(<Dashboard />)

    await waitFor(() => {
      // It should still render the main headings even if API fails
      expect(screen.getByText('Dashboard Overview')).toBeInTheDocument()
    })

    // It should render 0 for metrics since fallback is 0
    const zeroValues = screen.getAllByText('0')
    expect(zeroValues.length).toBeGreaterThan(0)

    // It should display empty state for logs
    expect(screen.getByText('No recent events found')).toBeInTheDocument()
  })
})
