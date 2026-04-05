# Hardest-Encryption

`Hardest-Encryption` là một dự án CLI Python để mã hóa văn bản và file bằng AES-256. Nó hỗ trợ mã hóa dựa trên mật khẩu, file khóa `.ckey` có thể tái sử dụng, và mã hóa streaming chunk cho các file lớn như video, ảnh, archive, và tài liệu.

## Các Tính Năng

- AES-256-GCM, AES-256-CBC + HMAC, và AES-256-SIV
- Argon2id và PBKDF2-SHA256 key derivation
- Quy trình làm việc dựa trên mật khẩu hoặc file khóa
- Mã hóa streaming cho các file lớn
- Định dạng file khóa nhị phân `.ckey` với bảo vệ mật khẩu tùy chọn
- Vòng lặp menu tương tác với quay lại menu chính
- Giao diện terminal phong phú với bảng, bảng điều khiển, thanh tiến trình, và kết quả benchmark
- Bộ kiểm thử tích hợp trong `tests.py`

## Cấu Trúc Dự Án

```text
Hardest-Encryption/
|-- cryptool.py         # Điểm vào Typer CLI chính
|-- _crypto_engine.py   # Các nguyên thủy mã hóa cốt lõi, định dạng header, logic KDF
|-- _file_streamer.py   # Mã hóa/giải mã file chunk cho các file lớn
|-- _key_manager.py     # Định dạng file khóa .ckey, trợ giúp save/load/list
|-- tests.py            # Trình chạy kiểm thử độc lập
|-- requirements.txt    # Các phụ thuộc Python
|-- README.md           # Tài liệu dự án (tiếng Anh)
|-- README_VN.md        # Tài liệu dự án (tiếng Việt)
|-- AGENTS.md           # Hướng dẫn cho agent mã hóa/người đóng góp
`-- .idea/              # Siêu dữ liệu IDE
```

## Yêu Cầu

- Python 3.10+
- Pip

Các phụ thuộc từ `requirements.txt`:

- `cryptography>=41.0.0`
- `rich>=13.0.0`
- `typer>=0.9.0`
- `argon2-cffi>=23.0.0`

## Cài Đặt

```bash
python -m venv .venv
```

**Windows:**

```bash
.venv\Scripts\activate
pip install -r requirements.txt
```

**macOS/Linux:**

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## Bắt Đầu Nhanh

Chạy menu tương tác:

```bash
python cryptool.py
```

Hoặc mở nó một cách rõ ràng:

```bash
python cryptool.py menu
```

Mã hóa văn bản bằng mật khẩu:

```bash
python cryptool.py encrypt --text "hello world" --password "StrongPass!123"
```

Giải mã ciphertext Base64:

```bash
python cryptool.py decrypt --text "<base64-ciphertext>" --password "StrongPass!123"
```

Mã hóa một file:

```bash
python cryptool.py encrypt --file secret.pdf --password "StrongPass!123"
```

Giải mã một file:

```bash
python cryptool.py decrypt --file secret.pdf.enc --password "StrongPass!123"
```

Tạo file khóa có thể tái sử dụng:

```bash
python cryptool.py key generate --save mykey.ckey --protect --desc "Primary backup key"
```

Mã hóa bằng file khóa:

```bash
python cryptool.py encrypt --file video.mp4 --key-file mykey.ckey --key-pass "KeyPass!123"
```

## Các Lệnh CLI

### `menu`

Chạy vòng lặp menu tương tác. Sau mỗi thao tác, chương trình đợi Enter và quay lại menu chính.

```bash
python cryptool.py menu
```

### `encrypt`

Mã hóa văn bản rõ ràng hoặc một file.

Các tùy chọn phổ biến:

- `-t, --text` nhập văn bản rõ ràng
- `-f, --file` nhập file
- `-o, --output` đường dẫn file đầu ra
- `-p, --password` nhập mật khẩu
- `--key-file` sử dụng file `.ckey` thay vì mật khẩu
- `--key-pass` mật khẩu cho các file `.ckey` được bảo vệ
- `-a, --algo` `gcm | cbc | siv`
- `-k, --kdf` `argon2 | pbkdf2`
- `--chunk-mb` kích thước chunk streaming tính bằng MB
- `--stream-from` sử dụng streaming khi kích thước file ít nhất X MB
- `--delete-src` xóa file gốc sau khi mã hóa

Ví dụ:

```bash
python cryptool.py encrypt -f archive.zip -p "StrongPass!123" -a gcm -k argon2
python cryptool.py encrypt -t "confidential note" -p "StrongPass!123" -a siv
python cryptool.py encrypt -f movie.mkv --key-file media.ckey --key-pass "KeyPass!123"
```

### `decrypt`

Giải mã ciphertext Base64 hoặc các file `.enc`.

Các tùy chọn phổ biến:

- `-t, --text` ciphertext Base64
- `-f, --file` nhập file được mã hóa
- `-o, --output` đường dẫn file đầu ra
- `-p, --password` nhập mật khẩu
- `--key-file` sử dụng file `.ckey`
- `--key-pass` mật khẩu cho các file `.ckey` được bảo vệ

Ví dụ:

```bash
python cryptool.py decrypt -f archive.zip.enc -p "StrongPass!123"
python cryptool.py decrypt -f movie.mkv.enc --key-file media.ckey --key-pass "KeyPass!123"
```

### `key generate`

Tạo khóa AES-256 mới và lưu nó dưới dạng file `.ckey`.

Các tùy chọn:

- `--save` đường dẫn file đầu ra `.ckey`
- `--protect` bảo vệ file khóa bằng mật khẩu
- `--key-pass` mật khẩu bảo vệ
- `--desc` mô tả ngắn về khóa
- `-a, --algo` thuật toán mặc định
- `-k, --kdf` KDF mặc định
- `--tags` các tag siêu dữ liệu được phân tách bằng dấu phẩy

Ví dụ:

```bash
python cryptool.py key generate --save backup.ckey --protect --desc "Backup vault key" --tags backup,archive
```

### `key info`

Hiển thị siêu dữ liệu về file `.ckey`.

```bash
python cryptool.py key info backup.ckey
python cryptool.py key info backup.ckey --key-pass "KeyPass!123" --fingerprint
```

### `key list`

Liệt kê đệ quy các file `.ckey` trong một thư mục.

```bash
python cryptool.py key list .
```

### `info`

Kiểm tra siêu dữ liệu file được mã hóa hoặc ciphertext Base64 mà không giải mã nó.

```bash
python cryptool.py info --file archive.zip.enc
python cryptool.py info --text "<base64-ciphertext>"
```

### `benchmark`

Chạy một benchmark mã hóa cục bộ.

```bash
python cryptool.py benchmark
python cryptool.py benchmark --size 128
```

### `pipe`

Đọc từ `stdin` và ghi vào `stdout`.

```bash
echo secret | python cryptool.py pipe encrypt -p pass | python cryptool.py pipe decrypt -p pass
```

## Kiến Trúc

### 1. Lớp CLI

`cryptool.py` hiển thị ứng dụng Typer và các lệnh hướng tới người dùng. Nó điều phối các lệnh nhập mật khẩu, tải khóa, đặt tên đầu ra, và hiển thị tiến trình Rich.

### 2. Công Cụ Mã Hóa

`_crypto_engine.py` định nghĩa:

- Enum thuật toán AES và nhãn
- Enum KDF và nhãn
- Header ciphertext toàn cầu 80 byte
- Trợ giúp dẫn xuất mật khẩu
- Mã hóa/giải mã văn bản/dữ liệu nhỏ
- Trợ giúp kiểm tra siêu dữ liệu ciphertext

### 3. Lớp Streaming

`_file_streamer.py` xử lý quy trình làm việc với file lớn:

- Mã hóa AES-GCM dựa trên chunk
- Dẫn xuất nonce cho mỗi chunk
- Ràng buộc AAD cho mỗi chunk để ngăn chặn sắp xếp lại
- HMAC stream cuối để toàn vẹn
- Phát hiện loại file và định dạng kích thước

### 4. Quản Lý Khóa

`_key_manager.py` triển khai định dạng nhị phân `.ckey`, bảo vệ mật khẩu tùy chọn cho các file khóa, và siêu dữ liệu như dấu vân tay, mô tả, tag, và thuật toán/KDF mặc định.

## Định Dạng File

### Header Ciphertext

Blob được mã hóa bắt đầu bằng một header cố định 80 byte chứa:

- magic bytes `CRYPTOOL`
- phiên bản
- id thuật toán
- id KDF
- flags
- muối
- nonce hoặc IV
- authentication tag
- kích thước gốc

### File Được Mã Hóa Streaming

Các file `.enc` streaming chứa:

1. Header toàn cầu 80 byte
2. Header stream 56 byte
3. Các chunk được mã hóa lặp lại
4. HMAC stream cuối cùng

### File `.ckey`

Các file khóa sử dụng magic header `CKEYFILE` và lưu trữ:

- phiên bản và chế độ bảo vệ
- thuật toán và KDF mặc định
- dấu thời gian tạo
- muối và nonce bảo vệ khi được bật
- slot khóa được mã hóa hoặc khóa thô
- siêu dữ liệu JSON

## Kiểm Thử

Chạy bộ kiểm thử tích hợp:

```bash
python tests.py
```

Các kiểm thử hiện tại bao gồm:

- vòng mã hóa-giải mã giữa các thuật toán và KDF
- bác bỏ mật khẩu sai và giả mạo
- hành vi flag/header streaming
- tạo khóa, lưu/tải, dấu vân tay, và siêu dữ liệu
- trợ giúp quy trình làm việc với file

## Ghi Chú

- Mã hóa dựa trên mật khẩu dẫn xuất một khóa mới từ muối ngẫu nhiên cho mỗi lần mã hóa.
- Chế độ streaming được sử dụng cho các file lớn hơn và khi các file khóa thô được cung cấp.
- CLI hiện tại trộn các định danh tiếng Anh với văn bản hướng tới người dùng tiếng Việt.
- Kho lưu trữ hiện không bao gồm siêu dữ liệu đóng gói như `pyproject.toml` hoặc `setup.py`.

## Giấy Phép

Hiện chưa có file giấy phép trong kho lưu trữ. Thêm một file trước khi xuất bản hoặc tái sử dụng dự án bên ngoài.

## Hỗ Trợ

Nếu bạn gặp vấn đề hoặc có câu hỏi, vui lòng kiểm tra:

1. Tệp `README.md` tiếng Anh để biết thêm chi tiết kỹ thuật
2. `AGENTS.md` để hiểu kiến trúc mã hóa
3. `tests.py` để xem các ví dụ sử dụng

Chúc bạn sử dụng CrypTool v2 vui vẻ! 🔐

