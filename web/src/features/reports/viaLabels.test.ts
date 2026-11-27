import { describe, expect, it } from 'vitest'
import reports from '@/locales/en/reports.json'
import { Via } from './contract'

// The security report's "Handled, by outcome" list names how each finding was handled (sr.via.<via>, SecurityReport): a way without
// its label shows the raw key in the report.
const labels = reports.sr.via as Record<string, string | undefined>

describe('every way a finding is handled has a report label', () => {
  for (const v of Via.options) {
    it(`${v} has a singular and a plural label`, () => {
      expect(labels[`${v}_one`]?.trim()).toBeTruthy()
      expect(labels[`${v}_other`]?.trim()).toBeTruthy()
    })
  }
})
