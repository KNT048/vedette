# Ids Contract

> Tier: tuỳ chọn (tắt mặc định, Preview) · Story: S-IDS-1 · Last verified: 2026-11-21 (mọi khẳng định đã đối chiếu với code)
> Nguồn hành vi thực tế: `web/src/features/detection/{contract,mocks}.ts`.

## Invariants (luôn đúng)
- **INV-1** Dòng log là dữ liệu không tin cậy (SYS-6): `Parse(kind, line)` tổng và có trần: dòng > 4 KiB, UTF-8 hỏng, dòng bị module logs cắt (`" ...[cut]"`) → không sự kiện; trường cần có viết hai lần, ngoặc kép lạc, địa chỉ không phải địa chỉ (có zone), cổng ngoài 0..65535, mức ưu tiên không đọc được → không sự kiện (fail closed, không đoán). Chữ ký ≤ 300 ký tự, nhóm ≤ 120, ký tự điều khiển/định dạng (bidi) thành dấu cách; ≤ 8 mã CVE mỗi sự kiện, dạng `CVE-YYYY-N{4,7}`, sắp theo năm rồi số. Regexp của Go chạy tuyến tính, mọi lượng từ có trần. Test: `FuzzParse`, `TestParseRefusesWhatIsNotSafeToRead`.
- **INV-1b** Nguồn syslog qua UDP (và TCP) chỉ được nhận diện bằng IP người gửi (logs FORBID-5): một máy trong LAN giả được IP của tường lửa và gửi dòng IPS giả, tạo cảnh báo, sự cố `intrusion` và trạng thái "under attack" giả. Nguồn TLS có ghim chứng chỉ khách (logs POST-1) thì không giả được. Vì vậy thông báo có trần mỗi giờ (POST-1) và trang nói nguồn của từng cảnh báo; khách nên dùng TLS cho tường lửa gửi sự kiện IPS.
- **INV-2** Định dạng đọc được, theo loại nguồn log (`profileKinds`): FortiGate (`type=utm subtype=ips`: `attack`, `attackid`, `severity`, `srcip`, `dstip`, `dstport`, `proto` số, `cve` khi FortiOS ghi), Suricata/Snort (dòng cảnh báo `[gid:sid:rev] msg [Classification: …] [Priority: n] {PROTO} src -> dst` của `alert-syslog`/`fast.log`, IPv6 không ngoặc với cổng sau dấu `:` cuối, ICMP không cổng; chỉ khi chương trình syslog là `suricata`/`snort`) và EVE JSON của Suricata (`event_type=alert`, `alert.metadata.cve` dạng `CVE_YYYY_N`), Sophos (`log_type="IDP"`), SonicWall (`m=608|609`), Palo Alto (THREAT `vulnerability|spyware`, vị trí trường 4, 5, 8, 9, 26, 30, 33 `tên(id)`, 35), Meraki (`security_event ids_alerted`). Mức ưu tiên 1..4: Snort/Suricata giữ nguyên (lớn hơn 4 → 4), mức chữ critical/high/medium/low(info) → 1/2/3/4. Mã CVE lấy từ trường CVE và từ tên chữ ký. Đếm theo profile: `TestCountIPSLinesPerProfile` (N dòng IPS → N cảnh báo, M có CVE; dòng không phải IPS → 0).
- **INV-3** Một cảnh báo mỗi (nguồn `log`, profile, chữ ký, sid, các mã CVE sự kiện nêu, địa chỉ nguồn, địa chỉ đích, giờ UTC) (`dedupe_key`; CVE nằm trong khoá nên tập CVE của một cảnh báo không bao giờ đổi, và khoá sự cố tính lại lúc đọc khớp khoá lúc mở; `ids_alert_cve` có trần `MaxCVEs` = 8 hàng mỗi cảnh báo); sự kiện lặp chỉ tăng `count`, nới `first_ts`/`last_ts`. `source` là từ vựng mở (`log` hôm nay; bộ máy trên hộp sau này thêm giá trị, không đổi bảng). `TestOneAlertPerSignatureSourceDestinationAndHour`.
- **INV-4** `Offer` (module logs gọi sau khi lô đã commit) không bao giờ ghi CSDL và không chờ người ghi của core (logs INV-12): chỉ đọc và gộp trong bộ nhớ, tối đa `MaxPending` = 2.000 cảnh báo chờ (sự kiện của cảnh báo thứ 2.001 bị bỏ và đếm, ghi WARN một lần mỗi lượt flush). Job `flush` (5 s) ghi một giao dịch mỗi lượt; lượt ghi lỗi trả cảnh báo về bộ đệm (gộp với cái mới tới, vẫn trong trần `MaxPending`, phần vượt bị đếm là bỏ) để lượt sau ghi lại. Dừng tiến trình mất tối đa 5 giây sự kiện chưa ghi (chấp nhận: dòng gốc vẫn ở `logs_events`). Module tắt: `Offer` không làm gì, dòng nhận lúc tắt không bao giờ được đọc lại. `TestNothingIsReadWhileTheModuleIsOffAndTheBufferIsBounded`.
- **INV-5** Thiết bị (`src_asset_id`, `dst_asset_id`) là thiết bị duy nhất có địa chỉ đó lúc sự kiện tới (IP trong danh sách, hoặc địa chỉ đọc SNMP người dùng gõ, như nguồn log); hai thiết bị cùng địa chỉ → không thiết bị. Tên đọc lúc trả lời. Gộp thiết bị → chuyển trong giao dịch của inventory (`DeviceMerged`); xoá thiết bị → khoá ngoại đặt NULL, cảnh báo giữ địa chỉ. `TestMergeMovesAndRetentionDeletes`.
- **INV-6** Lưu giữ: `RetentionDays` = 90 ngày sau sự kiện cuối, tối đa `MaxAlerts` = 50.000 hàng (xoá cũ nhất); job `purge` (Housekeeping) và mỗi lượt flush.
- **INV-7** Mức nghiêm trọng của cảnh báo tính lúc đọc: ưu tiên 1/2/3/4 → high/medium/low/info; **critical** khi thiết bị bị nhắm đang bị ảnh hưởng (một finding mở) bởi một CVE cảnh báo nêu. `findings` của cảnh báo là finding của `dst_device` cho các CVE đó, với trạng thái của findings (`Findings.Linked`).

## Postconditions
- **POST-1** Sau mỗi flush, cảnh báo đã ghi được phát `ids.alert.detected` (`AlertEvent`: `alert_id, source, target, title, what, action, severity, link, at, devices`); notify mở, đếm hay **nâng** sự cố kind `intrusion` khoá (`source` = địa chỉ tấn công, `target` = `cve:<các CVE>` hoặc `rule:<sid>:<chữ ký>`): một sự cố mỗi (CVE hoặc quy tắc, nguồn) khi còn lặp; critical khi thiết bị bị nhắm bị ảnh hưởng. `link` = `/detection/alerts/<id>`. Thứ tự cố định: nặng nhất trước (critical trước), rồi mới nhất, rồi địa chỉ nguồn, đích sự cố. Một khoá sự cố đã phát trong giờ đồng hồ này với mức bằng hay cao hơn thì không phát lại (hàng cảnh báo vẫn đếm sự kiện); mức tăng thì phát lại, và notify nâng sự cố đang mở lên mức đó với một tin riêng (`<id>-raised-<mức>`). Trần `AlertEventsPerHour` = 100 lần phát mỗi giờ đồng hồ (như `IocEventsPerHour` của logs): quá trần, cảnh báo vẫn lưu và hiện, và **một** sự cố tóm tắt mỗi giờ (`source=ids`, `target=more intrusion alerts <giờ>`, `link=/detection`, mức cao nhất trong phần không phát, tối thiểu medium); khi phần không phát ở một lượt sau trong cùng giờ có mức cao hơn mức tóm tắt đã phát (một cuộc tấn công vào thiết bị bị ảnh hưởng sau khi hết trần), tóm tắt được phát lại cùng khoá với mức mới và số đếm hiện tại, nên notify nâng nó và gửi tin nâng (tối đa vài tin mỗi giờ). `TestACriticalAlertAfterTheBudgetRaisesTheHoursSummary`. `TestAFloodOfForgedSourcesIsAnnouncedWithinTheHourlyBudgetMostSevereFirst`, `TestARepeatAtAnAffectedDeviceRaisesTheIncident`, `TestAFailedFlushKeepsItsAlertsAndFindingsAreReadOncePerPage`.
- **POST-2** `GET /detection/alerts` (viewer): cửa sổ `24h|7d|30d` theo sự kiện cuối (khác → 400 `bad_window`), `cve` (sai dạng → 400 `invalid_cve`), `device` (nguồn hoặc đích), `q` trên chữ ký, nhóm, địa chỉ, tên thiết bị, CVE; sắp `last` (mặc định) hay `count`, hoà theo id; `offset`/`limit` ≤ 200; `total` là số khớp mọi trang. `GET /detection/alerts/{id}` → 404 `not_found` khi không có. `incident` = sự cố intrusion mới nhất của khoá mở trước hoặc lúc sự kiện cuối (notify `IncidentOf`), `null` khi notify tắt.
- **POST-3** Cổng "CVE bị tấn công": `Attacked(ctx, since)` → mỗi (CVE, địa chỉ đích): thiết bị, lần đầu/cuối, số sự kiện, cảnh báo mới nhất. Module findings chưa đọc cổng này; người đọc duy nhất là bộ chuyển `idsFindings` (`cmd/vedette/ids.go`): finding mở của thiết bị mà một cảnh báo trong `AttackWindow` = 14 ngày nêu CVE (tại bất kỳ địa chỉ đích nào) có trạng thái `under_attack` trong `findings` của cảnh báo, finding mở khác `exploited`. `TestAttackedPortRaisesAnAffectedFindingToUnderAttack` (consumer giả), `cmd/vedette` `TestWiringFirewallIPSEventRaisesAnIntrusionIncidentAndTheFindingIsUnderAttack`.

## Forbidden
- **FORBID-1** Chặn hay sửa lưu lượng (phát hiện không bao giờ chặn); mở cổng, chạy tiến trình, gọi ra ngoài.
- **FORBID-2** Diễn giải nội dung dòng thành lệnh; rẽ nhánh trên văn bản `what`/`title` (chỉ để hiển thị).
- **FORBID-3** Đọc bảng của module khác: inventory, findings, notify chỉ qua cổng (`Inventory`, `Findings`, `Incidents`) do `cmd/vedette/ids.go` nối (địa chỉ → thiết bị qua `logsInventory` của `cmd/vedette/logs.go`, nên gồm cả địa chỉ đọc SNMP lấy từ sensor-active `ReadAddresses`).

## Endpoints owned (từ `contract.ts`)
| Method | Path | Vai tối thiểu | Story |
|---|---|---|---|
| GET | `/detection/alerts` | viewer | S-IDS-1 |
| GET | `/detection/alerts/{id}` | viewer | S-IDS-1 |

`GET /detection/overview` là của core (`cmd/vedette/detection.go`): trả lời cả khi module này tắt, đọc `Summarize` của nó.

## Tables owned
`ids_alert`, `ids_alert_cve` (cơ sở chính). Khoá ngoại tới `inv_asset` (`ON DELETE SET NULL`).

## Events
- **Phát**: `ids.alert.detected` (POST-1).
- **Nhận**: không (dòng log tới qua `logs.Config.Received`).

## Khi tắt module (SYS-5)
Không route `/detection/alerts*` (404), không job `flush`, `Offer` không làm gì; job `purge` (Housekeeping) vẫn xoá cảnh báo quá hạn. Dữ liệu giữ nguyên. Tổng quan nói watcher `ips_events` tắt.

## Dependencies
- **DEPENDS ON**: `core`, `inventory` (thiết bị của địa chỉ), `logs` (dòng nhận được). Mềm: `notify` (sự cố), `findings` (finding liên quan).
- **DEPENDED ON BY**: core (tổng quan Intrusion detection: `Summarize`, `NativeIPS`, `cmd/vedette/detection.go`). Module findings không import ids (xem POST-3).
