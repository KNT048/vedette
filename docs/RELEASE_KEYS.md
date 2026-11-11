# Khoá ký phát hành (D-256, D-257, D-258)

Ba khoá ký mọi thứ hộp Vedette tin khi cập nhật. Nửa công khai nhúng trong binary (`internal/release/keys.go`); nửa riêng chỉ ở chỗ người duy trì giữ, không bao giờ trong repo, trên hộp, trong log hay PR.

| Khoá | ID | Ký gì | Tệp riêng | Mật khẩu (Keychain, service) |
|---|---|---|---|---|
| minisign **đang dùng** | `7B78764E550D48D0` | `index.json` và mọi `release-manifest.json` | `~/.vedette-release-keys/minisign.key` | `vedette-release-minisign` |
| minisign **dự phòng** (ngoại tuyến) | `8DD38917AD864FAE` | index thu hồi một khoá (D-108), và bản cứu sau khi khoá đang dùng lộ (D-258); không ký bản phát hành thường | `~/.vedette-release-keys/minisign-backup.key` | `vedette-release-minisign-backup` |
| cosign (ECDSA P-256) | SHA-256 PKIX `CosignKeyID` | image (định dạng cũ, D-103) | `~/.vedette-release-keys/cosign.key` | `vedette-release-cosign` |

Account của mục Keychain là tên người dùng macOS (`kien`). Mỗi mục **không tin ứng dụng nào** (`-T ""`): mọi lần đọc, bởi bất kỳ chương trình nào, hiện hộp thoại macOS cần mật khẩu đăng nhập, nên một tiến trình chạy dưới tài khoản kien (agent, script cài gói) không lấy được mật khẩu một cách im lặng. Bấm **Allow**, không bao giờ **Always Allow** (nó thêm chương trình đó vào danh sách tin cậy). Nửa công khai nằm cạnh (`*.pub`, đúng tên mà `RELEASE_KEYS` đọc); không đặt `RELEASE_KEYS` thì `scripts/release` dùng khoá biên dịch sẵn, cũng chính là ba khoá này.

## Nghi thức tạo khoá (2026-11-11)

`scripts/release/keygen.sh` trên Mac của người duy trì (chỉ macOS vì mật khẩu vào Keychain):

1. Kiểm `minisign` trong PATH đúng phiên bản `deploy/tools.env` (0.12; trên macOS là bản Homebrew, chỉ kiểm phiên bản, không ghim hash: binary ghim của `minisign.sh` chỉ có cho Linux) và lấy cosign v2.6.5 ghim SHA-256 bằng `scripts/release/cosign.sh` (D-257).
2. Từ chối nếu đã có tệp khoá hay mục Keychain cùng tên (không bao giờ ghi đè khoá).
3. Mỗi khoá: mật khẩu ngẫu nhiên 256 bit (`openssl rand -hex 32`) vào biến shell, ghi thẳng vào Keychain qua `security -i` đọc từ stdin (không nằm trong argv, lịch sử shell hay tệp, không in ra), mục không tin ứng dụng nào; tạo khoá, mã hoá bằng mật khẩu đó (minisign: scrypt; cosign: scrypt + secretbox; cosign nhận mật khẩu qua `COSIGN_PASSWORD`, tiến trình cùng tài khoản thấy được trong lúc cosign chạy); thư mục `0700`, tệp `0600`.
4. Tự kiểm: đọc lại mật khẩu từ Keychain (một hộp thoại mỗi khoá), so với bản vừa ghi, rồi mỗi khoá ký một tệp bỏ đi và chữ ký được kiểm bằng nửa công khai (chứng minh mục Keychain, khoá riêng, khoá công khai là một bộ); tệp bỏ đi bị xoá.
5. Chỉ in nửa công khai. Hỏng giữa chừng thì script nói còn sót tệp và mục Keychain nào, phải xoá trước khi chạy lại.

Ba khoá thật được tạo bằng bản đầu của script (mục Keychain khi đó tin công cụ `security`); sau rà soát cùng ngày, ba mục được tạo lại với cùng mật khẩu và `-T ""` (danh sách ứng dụng của quyền `decrypt` rỗng, đã kiểm bằng `security dump-keychain -a`).

Sau đó mỗi khoá ký `internal/release/testdata/prod/proof.txt` (bằng chứng sở hữu, không phải tài liệu phát hành). `TestProductionKeysProofOfPossession` kiểm ba chữ ký đó bằng hằng nhúng, nên hằng bị sửa một ký tự hay dán nhầm ô sẽ đỏ trên CI chứ không phải ở bản phát hành đầu tiên.

## Ký một bản phát hành

Mật khẩu không bao giờ là đối số (D-164); mỗi lệnh dưới đây hiện một hộp thoại Keychain:

```bash
security find-generic-password -s vedette-release-minisign -a "$USER" -w | make release-sign MINISIGN_KEY=$HOME/.vedette-release-keys/minisign.key MINISIGN_BIN=$(command -v minisign) PASSPHRASE_STDIN=1
```

```bash
COSIGN_PASSWORD=$(security find-generic-password -s vedette-release-cosign -a "$USER" -w) $(scripts/release/cosign.sh) sign …   # đúng argv của make release-cosign-plan
```

Khoá dự phòng chỉ được lấy ra khi cần ký index thu hồi (`RELEASE_SLOT=backup`) hay bản cứu (D-258).

## kien cần làm (một lần, **ngay**)

1. Chép `~/.vedette-release-keys/` (ba tệp `.key` đã mã hoá và ba `.pub`) ra **hai nơi ngoại tuyến** khác nhau, ví dụ hai USB cất ở hai chỗ.
2. Chép **ba mật khẩu** từ Keychain (Keychain Access → tìm `vedette-release` → Show password, hoặc `security find-generic-password -s vedette-release-<tên> -a kien -w` trên terminal của chính kien) ra **giấy**, cất tách khỏi USB. Khoá đã mã hoá mà mất mật khẩu thì vô dụng; mật khẩu không kèm tệp khoá thì cũng vô dụng; tách hai thứ thì mất một nơi không lộ khoá.
3. **Khoá dự phòng rời Mac ngay** sau khi có hai bản ngoại tuyến: xoá `minisign-backup.key` và mục Keychain `vedette-release-minisign-backup` (`security delete-generic-password -s vedette-release-minisign-backup -a kien`). Ý nghĩa của khoá dự phòng (D-103, D-108) là kẻ chiếm được máy ký không có nó; mà một mình nó ký được index và manifest hộp nhận (D-258), nên để nó trên Mac là để cả hai khoá ở một chỗ. Khoá đang dùng và khoá cosign có thể ở lại Mac để phát hành; tuỳ chọn xoá luôn và chỉ cắm USB khi phát hành.
4. Kiểm lại một bản sao bằng cách ký thử một tệp từ USB (`minisign -S -s <usb>/minisign.key -m <tệp>` rồi `minisign -Vm <tệp> -p <usb>/minisign.pub`).
5. **Time Machine**: nó sao lưu cả `~/.vedette-release-keys` lẫn `login.keychain-db`, nên ai có đĩa sao lưu chỉ cần thêm mật khẩu đăng nhập của kien. Hoặc loại thư mục khoá khỏi Time Machine (`tmutil addexclusion ~/.vedette-release-keys`; hai USB đã là bản sao), hoặc chỉ dùng đĩa Time Machine mã hoá.

Thư mục khoá nằm ở thư mục nhà, ngoài iCloud Drive.

## Xoay khoá và thu hồi (D-108, D-130, D-258)

- **Khoá đang dùng bị lộ hoặc mất:** hộp đã cài chỉ tin hai khoá nhúng, nên bản cứu phải đi qua khoá **dự phòng** (D-258). Lấy khoá dự phòng từ nơi ngoại tuyến. Tạo khoá đang dùng mới (`mv` cặp cũ vào `retired/`, xoá mục Keychain cũ sau khi đã có bản ngoại tuyến của nó, `scripts/release/keygen.sh minisign`), đổi `prodMinisignActive`, chuyển dòng cũ vào `prodMinisignRetired` (chỉ dùng để kiểm lại index đã lưu), PR có quyết định D mới, dựng bản cứu. Khoá **dự phòng** ký index của bản cứu (có `revocations` `kind=key` cho `7B78764E550D48D0`; chỉ index ký bằng khoá dự phòng thu hồi được khoá nhúng, thu hồi được giữ mãi, và được đặt lại `sequence`, D-108 M2) **và** manifest của bản cứu; bộ xác minh của hộp đã nhận manifest ký bằng khoá dự phòng. **Hôm nay `scripts/release sign -slot backup` chỉ ký index** (chế độ ký bản cứu là việc để sau, `.ai/deferred/feat-release-keys.md`); tới khi có nó, hộp đã cài chỉ được cứu bằng cách cài lại (`install.sh` mới).
- **Khoá cosign bị lộ:** thu hồi `kind=key` bằng `CosignKeyID` trong index ký bằng khoá dự phòng, và phát hành binary với khoá cosign mới. Bộ xác minh nhận 1–2 khoá cosign (`Trust.Cosign`), nhưng `Embedded()` hôm nay chỉ dựng từ một hằng `prodCosign`: nhúng hai khoá trong lúc chuyển cần sửa mã.
- **Khoá dự phòng bị lộ:** nghiêm trọng như lộ cả hai: một mình nó ký được index và manifest hộp nhận, và thu hồi vĩnh viễn được khoá đang dùng. Không index nào thu hồi được khoá dự phòng (thiết kế, D-108). Phản ứng: phát hành ngay bằng khoá đang dùng một binary với khoá dự phòng mới, trước khi kẻ giữ khoá kịp thu hồi khoá đang dùng; hộp nào đã nhận index thu hồi của kẻ đó chỉ cứu được bằng cài lại. Cả hai khoá minisign cùng lộ là giới hạn đã ghi (update-manifest §13 (b)).
- Mất mật khẩu hay mọi bản sao của khoá đang dùng mà khoá dự phòng còn: như "bị lộ" ở trên. Mất cả hai khoá minisign: hộp đã cài không nhận cập nhật nào nữa; người dùng phải cài lại bằng `install.sh` mới.

Nguồn: D-103, D-108, D-130, D-258, `docs/specs/update-manifest.md` §5, §8, §13.
