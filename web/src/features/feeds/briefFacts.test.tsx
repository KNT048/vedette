// The facts of a CVE brief as the CVE page and a finding's summary card show them.
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { esxiBrief } from './briefSamples'
import { BriefFacts } from './BriefParts'

describe('the exploit likelihood fact', () => {
  it('floors the percentile: a CVE in the top 0.1 % is "higher than 99%", never "higher than 100% of CVEs"', () => {
    render(<BriefFacts b={{ ...esxiBrief, epss: { ...esxiBrief.epss!, score: 0.951, percentile: 0.9996 } }} />)
    expect(screen.getByText(/higher than 99% of CVEs/)).toBeInTheDocument()
    expect(screen.queryByText(/100% of CVEs/)).toBeNull()
  })
})
