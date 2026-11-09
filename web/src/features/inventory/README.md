# features/inventory

Story: S-INV-1 (danh sách thiết bị, observation có nguồn + độ tin cậy, phạm vi quét, cảm biến của chính hộp), S-INV-2 (khai tay ≤3 bấm từ danh mục ~880 sản phẩm: toàn bộ CISA KEV + danh sách tuyển chọn; nhập/xuất CSV), S-INV-3 (chưa duyệt: duyệt / đánh dấu lạ / xoá, báo khi có thiết bị mới), S-INV-4 (osquery: token + script cài một dòng lệnh cho Linux và Windows Server; Wazuh: kéo qua API chỉ-đọc; cần module agent-intake).

Trang: `/devices`, `/devices/:id`, `/devices/setup` (admin). API: `/api/v1/inventory/…`, `/api/v1/install/*` (script cài, công khai), `/api/v1/intake/*` (osquery/Wazuh gửi về). Tài sản nằm ở `assetsStore` dùng chung; bảng riêng: `inv_meta`, `inv_obs`, `inv_notify`, `inv_settings`, `inv_sensors`, `inv_agent_tokens`, `inv_wazuh`.

Quyết định: giao diện chỉ tiếng Anh; không nhiều site; không văn bản đồng ý (một ô cam kết + dòng "as is"); dải mạng không có /prefix bị từ chối, không đoán; không Trivy, không macOS.
Slot tiêu thụ: `device.panels` (props `{ assetId }`) ở trang chi tiết thiết bị. Không cung cấp slot.
Quy ước: giá trị quan sát không ghi đè; sửa tay thêm observation nguồn "manual"; secret (token osquery, mật khẩu Wazuh) chỉ trả đầy đủ một lần / chỉ 4 ký tự cuối.
