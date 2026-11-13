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

0. Thử trước một lần: `security dump-keychain -a ~/Library/Keychains/login.keychain-db > /dev/null` phải thoát 0 (chỉ đọc danh sách quyền, không có mật khẩu). Script dùng lệnh này để kiểm mục vừa tạo không tin ứng dụng nào (D-259); lệnh này hỏng thì script dừng.
1. Kiểm `minisign` trong PATH đúng phiên bản `deploy/tools.env` (0.12; trên macOS là bản Homebrew, chỉ kiểm phiên bản, không ghim hash: binary ghim của `minisign.sh` chỉ có cho Linux) và lấy cosign v2.6.5 ghim SHA-256 bằng `scripts/release/cosign.sh` (D-257).
2. Từ chối nếu đã có tệp khoá hay mục Keychain cùng tên (không bao giờ ghi đè khoá).
3. Mỗi khoá: mật khẩu ngẫu nhiên 256 bit (`openssl rand -hex 32`) vào biến shell, ghi thẳng vào Keychain qua `security -i` đọc từ stdin (không nằm trong argv, lịch sử shell hay tệp, không in ra), mục không tin ứng dụng nào; tạo khoá, mã hoá bằng mật khẩu đó (minisign: scrypt; cosign: scrypt + secretbox; cosign nhận mật khẩu qua `COSIGN_PASSWORD`, tiến trình cùng tài khoản thấy được trong lúc cosign chạy); thư mục `0700`, tệp `0600`.
4. Tự kiểm: đọc lại mật khẩu từ Keychain (một hộp thoại mỗi khoá), so với bản vừa ghi, rồi mỗi khoá ký một tệp bỏ đi và chữ ký được kiểm bằng nửa công khai (chứng minh mục Keychain, khoá riêng, khoá công khai là một bộ); tệp bỏ đi bị xoá.
5. Chỉ in nửa công khai. Hỏng giữa chừng thì script nói còn sót tệp và mục Keychain nào, phải xoá trước khi chạy lại.

Ba khoá thật được tạo bằng bản đầu của script (mục Keychain khi đó tin công cụ `security`); sau rà soát cùng ngày, ba mục được tạo lại với cùng mật khẩu và `-T ""` (danh sách ứng dụng của quyền `decrypt` rỗng, đã kiểm bằng `security dump-keychain -a`).

Sau đó mỗi khoá ký `internal/release/testdata/prod/proof.txt` (bằng chứng sở hữu, không phải tài liệu phát hành). `TestProductionKeysProofOfPossession` kiểm ba chữ ký đó bằng hằng nhúng, nên hằng bị sửa một ký tự hay dán nhầm ô sẽ đỏ trên CI chứ không phải ở bản phát hành đầu tiên.

## Ký một bản phát hành

Thứ tự đầy đủ: `docs/plans/2026-11-12-wp08k-release-job.md` §1. Trước khi ký:

- [ ] kien tag `v<v>` **trước**, rồi mới dựng image và `.deb` từ bản clone sạch ở đúng tag: `.deb` dựng trước tag mang commit và phiên bản khác, `release-gates` dựng lại ở tag và từ chối (bản v0.1.0-beta.1 phải dựng lại `.deb`).
- [ ] `podman login ghcr.io` (token `write:packages`); `gh auth refresh -s read:packages` để `gh` liệt kê được package.
- [ ] Tổ chức KNT048 cho phép package Public (Settings → Packages); sau `release-push` lần đầu, bốn package `vedette-core`, `-sensor`, `-scan`, `-honeypot` đặt Public và nối với repo (plan §3 bước 3).

Mật khẩu không bao giờ là đối số (D-164); mỗi lệnh dưới đây hiện một hộp thoại Keychain:

```bash
security find-generic-password -s vedette-release-minisign -a "$USER" -w | make release-sign MINISIGN_KEY=$HOME/.vedette-release-keys/minisign.key MINISIGN_BIN=$(command -v minisign) PASSPHRASE_STDIN=1
```

```bash
make -s release-cosign-plan COSIGN_KEY=$HOME/.vedette-release-keys/cosign.key > dist/cosign-plan.sh && less dist/cosign-plan.sh   # chỉ in lệnh (cosign đã ghim); đọc lại
COSIGN_PASSWORD=$(security find-generic-password -s vedette-release-cosign -a "$USER" -w) scripts/release/cosign-auth.sh sh -eu dist/cosign-plan.sh
```

Kế hoạch bắt đầu bằng `cd` về gốc repo, rồi `cosign sign` cho từng image (ghi `dist/release/cosign/<service>.{payload.json,sig}` cho `release-manifest`), rồi `cosign attest --type cyclonedx` cho từng SBOM theo kiến trúc (`dist/sbom` của `make sbom RELEASE=1 IMAGE_TAG=<v>`), tải lên ghcr cạnh digest của kiến trúc đó. Mỗi SBOM phải là SBOM của đúng image đã đẩy: `aquasecurity:trivy:ImageID` của trivy phải bằng config digest mà `release-push` ghi cho kiến trúc đó trong `images.json` (dựng lại image sau khi đẩy thì SBOM mới bị từ chối). cosign cần đăng nhập ghcr và đọc nó như Docker (`$DOCKER_CONFIG/config.json`, rồi `~/.docker/config.json`; chỉ khi cả hai không có mới đọc `auth.json` của podman), nên một `~/.docker/config.json` không có ghcr che mất `podman login ghcr.io`: `scripts/release/cosign-auth.sh` trỏ `DOCKER_CONFIG` vào thư mục tạm (0700) có `config.json` là liên kết tới `auth.json` của podman (`$REGISTRY_AUTH_FILE`, hoặc `~/.config/containers/auth.json` trên macOS), chạy kế hoạch rồi xoá thư mục; không chép, không in thông tin đăng nhập. Chạy lại sau lỗi: `--replace` thay attestation CycloneDX cũ của cùng digest (chưa đo trên ghcr; `.ai/deferred/feat-release-cosign-plan.md`) (D-457, phần C).

Khoá dự phòng chỉ được lấy ra khi cần ký index thu hồi (`RELEASE_SLOT=backup`) hay bản cứu (D-258).

## kien cần làm (một lần, **ngay**)

1. Chép `~/.vedette-release-keys/` (ba tệp `.key` đã mã hoá và ba `.pub`) ra **hai nơi ngoại tuyến** khác nhau, ví dụ hai USB cất ở hai chỗ.
2. Chép **ba mật khẩu** từ Keychain (Keychain Access → tìm `vedette-release` → Show password, hoặc `security find-generic-password -s vedette-release-<tên> -a kien -w` trên terminal của chính kien) ra **giấy**, cất tách khỏi USB. Khoá đã mã hoá mà mất mật khẩu thì vô dụng; mật khẩu không kèm tệp khoá thì cũng vô dụng; tách hai thứ thì mất một nơi không lộ khoá.
3. **Khoá dự phòng rời Mac ngay** sau khi có hai bản ngoại tuyến: xoá `minisign-backup.key` và mục Keychain `vedette-release-minisign-backup` (`security delete-generic-password -s vedette-release-minisign-backup -a kien`). Ý nghĩa của khoá dự phòng (D-103, D-108) là kẻ chiếm được máy ký không có nó; mà một mình nó ký được index và manifest hộp nhận (D-258), nên để nó trên Mac là để cả hai khoá ở một chỗ. Khoá đang dùng và khoá cosign có thể ở lại Mac để phát hành; tuỳ chọn xoá luôn và chỉ cắm USB khi phát hành.
4. Kiểm lại một bản sao bằng cách ký thử một tệp từ USB (`minisign -S -s <usb>/minisign.key -m <tệp>` rồi `minisign -Vm <tệp> -p <usb>/minisign.pub`).
5. **Time Machine**: nó sao lưu cả `~/.vedette-release-keys` lẫn `login.keychain-db`, nên ai có đĩa sao lưu chỉ cần thêm mật khẩu đăng nhập của kien. Hoặc loại thư mục khoá khỏi Time Machine (`tmutil addexclusion ~/.vedette-release-keys`; hai USB đã là bản sao), hoặc chỉ dùng đĩa Time Machine mã hoá.

Thư mục khoá nằm ở thư mục nhà, ngoài iCloud Drive.

## Xoay khoá và thu hồi (D-108, D-130, D-258)

- **Khoá đang dùng bị lộ hoặc mất:** hộp đã cài chỉ tin hai khoá nhúng, nên bản cứu phải đi qua khoá **dự phòng** (D-258). Các bước ở mục "Bản cứu" ngay dưới (D-259).
- **Khoá cosign bị lộ:** thu hồi `kind=key` bằng `CosignKeyID` trong index ký bằng khoá dự phòng, và phát hành binary với khoá cosign mới. Bộ xác minh nhận 1–2 khoá cosign (`Trust.Cosign`), nhưng `Embedded()` hôm nay chỉ dựng từ một hằng `prodCosign`: nhúng hai khoá trong lúc chuyển cần sửa mã.
- **Khoá dự phòng bị lộ:** nghiêm trọng như lộ cả hai: một mình nó ký được index và manifest hộp nhận, và thu hồi vĩnh viễn được khoá đang dùng. Không index nào thu hồi được khoá dự phòng (thiết kế, D-108). Phản ứng: phát hành ngay bằng khoá đang dùng một binary với khoá dự phòng mới, trước khi kẻ giữ khoá kịp thu hồi khoá đang dùng; hộp nào đã nhận index thu hồi của kẻ đó chỉ cứu được bằng cài lại. Cả hai khoá minisign cùng lộ là giới hạn đã ghi (update-manifest §13 (b)).
- Mất mật khẩu hay mọi bản sao của khoá đang dùng mà khoá dự phòng còn: như "bị lộ" ở trên. Mất cả hai khoá minisign: hộp đã cài không nhận cập nhật nào nữa; người dùng phải cài lại bằng `install.sh` mới.

## Bản cứu sau khi khoá đang dùng lộ (D-258, D-259)

**Hộp tìm chữ ký ở đâu.** Hộp nhận **một** chữ ký cho mỗi tài liệu, ở đúng chỗ như mọi bản: `index.json.minisig` và `release-manifest.json.minisig` (`container.pull` có `index_sig`/`manifest_sig`; cài đặt đầu dùng `-index-sig`/`-manifest-sig`). Bộ xác minh của hộp nhận chữ ký của **bất kỳ** khoá nào trong hai khoá nhúng. Vì vậy bản cứu đăng chữ ký của khoá **dự phòng** ở chính hai tệp đó, và không đăng chữ ký nào của khoá đang dùng (hộp sẽ từ chối nó vì khoá đó đã bị thu hồi). Mã phía hộp không đổi dòng nào. `<tệp>.backup.minisig` (`-slot backup`) vẫn chỉ là chữ ký thêm để `verify` kiểm; hộp không bao giờ tải nó.

**Các bước** (máy người duy trì, khoá dự phòng lấy từ USB):

1. Giữ một thư mục có ba nửa công khai **cũ** (`minisign.pub` là khoá vừa lộ, `minisign-backup.pub`, `cosign.pub`): đó là thứ các hộp đã cài đang tin. Mọi lệnh dưới đây chạy với `-keys-dir` trỏ vào đó, vì khoá biên dịch trong bản cứu đã là khoá mới.
2. Tạo khoá đang dùng mới: chuyển cặp cũ vào `retired/`, `scripts/release/keygen.sh minisign`. Đổi `prodMinisignActive`, chuyển dòng cũ vào `prodMinisignRetired` (D-130), ghi D mới, merge, dựng image và `.deb` của bản cứu.
3. **Index nền là bản lưu của chính người duy trì**, không tải lại từ GitHub: kẻ giữ khoá lộ có thể đã đăng index của nó, và mọi thứ trong `-prev-index` (kênh, advisory, thu hồi, `keys`) đi vào index mà khoá dự phòng sắp ký. Dùng bản sao index cuối cùng mình đăng (so SHA-256 với bản đã ghi lúc đăng), và đọc lại phần được mang theo trước khi ký.
4. `release manifest` như mọi bản (`-prev-index` là bản lưu đó, `-keys-dir` cũ).
5. `release index … -prev-index <bản lưu> -keys-dir <khoá cũ> -revoke-key <ID khoá lộ> -revoke-reason "<lý do>"`: thêm dòng thu hồi `kind=key` (`-revoke-key` không chạy khi thiếu `-prev-index`: index không nền sẽ bỏ mất kênh, advisory và thu hồi đã có). Thu hồi khoá được giữ mãi; hộp chỉ nhận nó khi index do khoá dự phòng ký (D-108 M1), và khi đó `sequence` được phép thấp hơn index kẻ giữ khoá lộ có thể đã đưa cho hộp (D-108 M2).
6. `release sign -slot rescue -key <usb>/minisign-backup.key -prev-index <bản lưu> -keys-dir <khoá cũ> …` (hoặc `make release-sign RELEASE_SLOT=rescue RELEASE_PREV_INDEX=… RELEASE_KEYS=…`): khoá dự phòng ký `index.json` (cùng mọi `index.v<N>.json`) **và** `release-manifest.json` vào `<tệp>.minisig`. Công cụ từ chối khi thiếu manifest, khi thư mục đã có chữ ký của lượt khác, khi index không thu hồi khoá đang dùng của bộ khoá cũ, hoặc khi index nền đã thu hồi khoá đó (mỗi khoá lộ chỉ một bản cứu). Ký xong nó chạy `verify`; không ra `RESCUE` (ví dụ ký nhầm bằng khoá khác) thì xoá hết chữ ký của lượt đó.
7. `release verify -dir … -prev-index <bản lưu> -keys-dir <khoá cũ>`: chạy đúng bộ xác minh của hộp, dòng kết quả ghi `RESCUE`. Manifest ký bằng khoá dự phòng chỉ qua khi index cũng do khoá dự phòng ký, thu hồi khoá đang dùng của bộ khoá được kiểm, và index nền chưa thu hồi nó. Kiểm với khoá biên dịch mới thì bị từ chối.
8. **Khách chỉ-container** (D-451, D-410): bốn tệp `vedette.env`, `compose*.yaml` của bản cứu cũng ký bằng khoá dự phòng, còn khách chỉ có `vedette.pub` (khoá vừa lộ) sẽ thấy `FAILED`. Ghi chú phát hành và trang GitHub release phải ghi rõ "rescue release" và bảo họ kiểm bằng `vedette-backup.pub` (nửa công khai của khoá dự phòng, `8DD38917AD864FAE`, từ repository: `docs/INSTALL-CONTAINER.md` §1 đã bảo lưu nó, §5 nói cách dùng). `cosign.pub` không đổi trừ khi chính khoá cosign lộ.
9. Đăng, rồi cất khoá dự phòng lại ngoại tuyến. Bản thường kế tiếp dùng khoá mới, `-prev-index` là index của bản cứu, khoá biên dịch mới; thu hồi khoá cũ đi tiếp trong mọi index sau.

**Cửa sổ của bản cứu.** Hộp tải `index.json` hiện hành. Hộp còn binary cũ chỉ đọc được index do khoá dự phòng ký; index kế tiếp (bản làm mới hằng tuần D-150, hay bản thường) do khoá mới ký thì hộp cũ từ chối, không tới được manifest cứu. Vậy hộp nào chưa nhận bản cứu (tắt máy, lỗi mạng) trước index kế tiếp phải cài lại bằng `install.sh` mới. Để cửa sổ dài nhất: index cứu `-valid-days 14`, và không đăng index nào khác trong 14 ngày trừ khi có bản vá gấp (index hết hạn chỉ cảnh báo, D-104, nên hộp cũ vẫn nhận index cứu sau đó). Không chọn: khoá dự phòng ký luôn các bản làm mới trong một thời gian (khoá ngoại tuyến phải ra ngoài nhiều lần, D-258 (3)).

Quy tắc "khoá dự phòng chỉ ký bản cứu" nằm ở công cụ (`sign`, `verify`), không ở hộp: hộp nhận manifest do khoá dự phòng ký vì khoá đó không bao giờ bị thu hồi (D-108). Vì thế nó phải ở ngoại tuyến.

Nguồn: D-103, D-108, D-130, D-258, D-259, `docs/specs/update-manifest.md` §5, §8, §13.
