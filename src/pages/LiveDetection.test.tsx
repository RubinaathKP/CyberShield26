import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, it, expect, vi } from 'vitest'
import LiveDetection from './LiveDetection'
import { api } from '../api'

vi.mock('../api', () => ({
  api: {
    analyzePayload: vi.fn(),
  }
}))

describe('LiveDetection Component', () => {
  it('renders initial form state correctly', () => {
    render(<LiveDetection />)
    expect(screen.getByText('Live Payload Detection')).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/Enter payload string/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Analyze Payload/i })).toBeInTheDocument()
    expect(screen.getByText('No Analysis Yet')).toBeInTheDocument()
  })

  it('allows payload analysis and displays malicious result', async () => {
    const user = userEvent.setup()
    
    // Mock the API response
    vi.mocked(api.analyzePayload).mockResolvedValue({
      is_threat: true,
      confidence: 0.99,
      threat_type: 'Path Traversal',
      explanation: 'Detected path traversal attempt ../../etc/passwd',
      seriousness_score: 8.5
    })

    render(<LiveDetection />)

    const textarea = screen.getByPlaceholderText(/Enter payload string/i)
    await user.clear(textarea)
    await user.type(textarea, '{"path": "../../etc/passwd"}')

    const analyzeBtn = screen.getByRole('button', { name: /Analyze Payload/i })
    await user.click(analyzeBtn)

    // Expect loading state theoretically, but vitest runs fast
    
    await waitFor(() => {
      expect(screen.getByText(/Conf: 99.0%/i)).toBeInTheDocument()
      expect(screen.getByText('Threat Detected')).toBeInTheDocument()
      expect(screen.getByText('Score: 8.5 / 10')).toBeInTheDocument()
      expect(screen.getByText('Path Traversal')).toBeInTheDocument()
      expect(screen.getByText('Detected path traversal attempt ../../etc/passwd')).toBeInTheDocument()
    })
  })

  it('handles clean payloads properly', async () => {
    const user = userEvent.setup()
    
    // Mock the API response
    vi.mocked(api.analyzePayload).mockResolvedValue({
      is_threat: false,
      confidence: 0.95,
      threat_type: 'Unknown',
      explanation: 'No malicious signatures found.',
      seriousness_score: 0.1
    })

    render(<LiveDetection />)

    const textarea = screen.getByPlaceholderText(/Enter payload string/i)
    await user.clear(textarea)
    await user.type(textarea, '{"username": "gooduser"}')

    await user.click(screen.getByRole('button', { name: /Analyze Payload/i }))

    await waitFor(() => {
      expect(screen.getByText('Payload Clean')).toBeInTheDocument()
      expect(screen.queryByText('Threat Type:')).not.toBeInTheDocument()
      expect(screen.getByText('No malicious signatures found.')).toBeInTheDocument()
    })
  })
})
