// Kiểu API module feeds — suy ra từ hợp đồng Zod (contract.ts), không khai tay.
import type { z } from 'zod'
import type * as C from './contract'

export type Vuln = z.infer<typeof C.Vuln>
export type YouHave = z.infer<typeof C.YouHave>
export type HotRow = z.infer<typeof C.HotRow>
export type FeedStatus = z.infer<typeof C.FeedStatus>
export type WeeklyItem = z.infer<typeof C.WeeklyItem>
export type MatchedAsset = z.infer<typeof C.MatchedAsset>
export type CveDetail = z.infer<typeof C.CveDetail>
export type IocHit = z.infer<typeof C.IocHit>
export type SearchResult = z.infer<typeof C.SearchResult>
export type HotResponse = z.infer<typeof C.HotResponse>
export type FeedKind = z.infer<typeof C.FeedKind>
export type FeedFormat = z.infer<typeof C.FeedFormat>
export type DateFormat = z.infer<typeof C.DateFormat>
export type FieldMap = z.infer<typeof C.FieldMap>
export type Parser = z.infer<typeof C.Parser>
export type FeedAuthType = z.infer<typeof C.FeedAuthType>
export type Feed = z.infer<typeof C.Feed>
export type FeedInput = z.infer<typeof C.FeedInput>
export type FeedPatch = z.infer<typeof C.FeedPatch>
export type ParseResult = z.infer<typeof C.ParseResult>
export type ParseRecord = z.infer<typeof C.ParseRecord>
