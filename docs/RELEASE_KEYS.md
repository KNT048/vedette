# Khoá ký phát hành (D-256, D-257)

Ba khoá ký mọi thứ hộp Vedette tin khi cập nhật. Nửa công khai nhúng trong binary (`internal/release/keys.go`); nửa riêng chỉ ở chỗ người duy trì giữ, không bao giờ trong repo, trên hộp, trong log hay PR.

| Khoá | ID | Ký gì | Tệp riêng | Mật khẩu (Keychain, service) |
|---|---|---|---|---|
| minisign **đang dùng** | `7B78764E550D48D0` | `index.json` và mọi `release-manifest.json` | `~/.vedette-release-keys/minisign.key` | `vedette-release-minisign` |
| minisign **dự phòng** (ngoại tuyến) | `8DD38917AD864FAE` | chỉ index thu hồi một khoá (D-108); không bao giờ ký manifest | `~/.vedette-release-keys/minisign-backup.key` | `vedette-release-minisign-backup` |
| cosign (ECDSA P-256) | SHA-256 PKIX `CosignKeyID` | image (định dạng cũ, D-103) | `~/.vedette-release-keys/cosign.key` | `vedette-release-cosign` |

Account của mục Keychain là tên người dùng macOS (`kien`). Nửa công khai nằm cạnh (`*.pub`, đúng tên mà `RELEASE_KEYS` đọc); không đặt `RELEASE_KEYS` thì `scripts/release` dùng khoá biên dịch sẵn, cũng chính là ba khoá này.

## Nghi thức tạo khoá (2026-11-11)

`scripts/release/keygen.sh` trên Mac của người duy trì (chỉ macOS vì mật khẩu vào Keychain):

1. Kiểm `minisign` đúng bản ghim (`deploy/tools.env`, 0.12) và lấy cosign ghim v2.6.5 bằng `scripts/release/cosign.sh` (kiểm SHA-256; D-257).
2. Từ chối nếu đã có tệp khoá hay mục Keychain cùng tên (không bao giờ ghi đè khoá).
3. Mỗi khoá: mật khẩu ngẫu nhiên 256 bit (`openssl rand -hex 32`) vào biến shell, ghi thẳng vào Keychain qua `security -i` đọc từ stdin (không nằm trong argv, lịch sử shell hay tệp, không in ra); tạo khoá bằng công cụ ghim, mã hoá bằng mật khẩu đó (minisign: scrypt; cosign: scrypt + secretbox); thư mục `0700`, tệp `0600`.
4. Tự kiểm: mỗi khoá ký một tệp bỏ đi với mật khẩu **đọc lại từ Keychain** và chữ ký được kiểm bằng nửa công khai (chứng minh mục Keychain, khoá riêng, khoá công khai là một bộ); tệp bỏ đi bị xoá.
5. Chỉ in nửa công khai.

Sau đó mỗi khoá ký `internal/release/testdata/prod/proof.txt` (bằng chứng sở hữu, không phải tài liệu phát hành). `TestProductionKeysProofOfPossession` kiểm ba chữ ký đó bằng hằng nhúng, nên hằng bị sửa một ký tự hay dán nhầm ô sẽ đỏ trên CI chứ không phải ở bản phát hành đầu tiên.

## Ký một bản phát hành

Mật khẩu không bao giờ là đối số (D-164):

```bash
security find-generic-password -s vedette-release-minisign -a "$USER" -w | make release-sign MINISIGN_KEY=$HOME/.vedette-release-keys/minisign.key MINISIGN_BIN=$(command -v minisign) PASSPHRASE_STDIN=1
```

```bash
COSIGN_PASSWORD=$(security find-generic-password -s vedette-release-cosign -a "$USER" -w) $(scripts/release/cosign.sh) sign …   # đúng argv của make release-cosign-plan
```

Khoá dự phòng chỉ được lấy ra khi cần ký index thu hồi (`RELEASE_SLOT=backup`).

## kien cần làm (một lần, sớm)

1. Chép `~/.vedette-release-keys/` (ba tệp `.key` đã mã hoá và ba `.pub`) ra **hai nơi ngoại tuyến** khác nhau, ví dụ hai USB cất ở hai chỗ.
2. Chép **ba mật khẩu** từ Keychain (Keychain Access → tìm `vedette-release`, hoặc `security find-generic-password -s vedette-release-<tên> -a kien -w` trên terminal của chính kien) ra **giấy**, cất tách khỏi USB. Khoá đã mã hoá mà mất mật khẩu thì vô dụng; mật khẩu không kèm tệp khoá thì cũng vô dụng; tách hai thứ thì mất một nơi không lộ khoá.
3. Khoá dự phòng nên **rời Mac**: sau khi đã có hai bản ngoại tuyến, xoá `minisign-backup.key` và mục Keychain `vedette-release-minisign-backup` khỏi Mac (`security delete-generic-password -s vedette-release-minisign-backup -a kien`). Ý nghĩa của khoá dự phòng (D-103, D-108) là kẻ chiếm được máy ký không có nó. Khoá đang dùng và khoá cosign có thể ở lại Mac để phát hành; tuỳ chọn xoá luôn và chỉ cắm USB khi phát hành.
4. Kiểm lại một bản sao bằng cách ký thử một tệp từ USB (`minisign -S -s <usb>/minisign.key -m <tệp>` rồi `minisign -Vm <tệp> -p <usb>/minisign.pub`).

Thư mục khoá nằm ở thư mục nhà, ngoài iCloud Drive; Time Machine có thể sao lưu nó (khoá đã mã hoá, mật khẩu ở Keychain không đi cùng tệp).

## Xoay khoá và thu hồi (D-108, D-130)

- **Khoá đang dùng bị lộ hoặc mất:** lấy khoá dự phòng từ nơi ngoại tuyến; ký index có `revocations` `kind=key` cho `7B78764E550D48D0` bằng khoá **dự phòng** (`RELEASE_SLOT=backup`; chỉ index ký bằng khoá dự phòng thu hồi được khoá nhúng, và thu hồi được giữ mãi). Tạo khoá mới (`mv` cặp cũ vào `retired/`, xoá mục Keychain cũ sau khi đã có bản ngoại tuyến của nó, `scripts/release/keygen.sh minisign`), đổi `prodMinisignActive`, chuyển dòng cũ vào `prodMinisignRetired` (chỉ dùng để kiểm lại index đã lưu), PR có quyết định D mới, phát hành binary mới. Index ký bằng khoá dự phòng thu hồi người ký của index đã lưu được đặt lại `sequence` (D-108 M2).
- **Khoá cosign bị lộ:** thu hồi `kind=key` bằng `CosignKeyID` trong index ký bằng khoá dự phòng; có thể nhúng hai khoá cosign trong lúc chuyển (`Trust.Cosign` nhận 1–2 khoá).
- **Khoá dự phòng bị lộ:** không index nào thu hồi được khoá dự phòng (thiết kế, D-108); cần binary mới với khoá dự phòng mới, phát hành bằng khoá đang dùng (còn tin được). Cả hai khoá minisign cùng lộ là giới hạn đã ghi (update-manifest §13 (b)).
- Mất mật khẩu hay mọi bản sao của khoá đang dùng mà khoá dự phòng còn: như "bị lộ" ở trên. Mất cả hai khoá minisign: hộp đã cài không nhận cập nhật nào nữa; người dùng phải cài lại bằng `install.sh` mới.

Nguồn: D-103, D-108, D-130, `docs/specs/update-manifest.md` §5, §8, §13.
