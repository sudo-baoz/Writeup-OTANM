# Writeup chi tiết — bộ reverse engineering demo

## 0. Tổng quan

Thư mục gồm 10 artifact: 5 ELF Linux, 3 PE Windows và 2 APK. Các bước dưới đây phân tích mã tĩnh, disassembly, dữ liệu nhúng và bytecode DEX. Máy phân tích là ARM64 nên ELF x86-64 không chạy trực tiếp; các PE được đọc tĩnh. Phần giải mã và băm được tái tạo bằng script Python.

| Artifact | Kết quả |
|---|---|
| `WhatIsMyPassword` | `Flag{The_password_is_P4sSw0rD}` |
| `IForgetMyPassAgain` | Flag dài ở mục 2 |
| `InfiniteXOR` | Không có flag/ciphertext đích trong binary; phép biến đổi dùng key 6 byte `D0m41n` |
| `RevPY` | `CTF{pY7h0n_345y_R3v}` |
| `trytodebugme` | `CTF{Byp455_4nt1_D3bUg}` |
| `win/Guessing.exe` | `CTF{90e8f2c958a19840510acff379cf19c553c49420c137c2ffab936b2702b68e2b}` |
| `win/bypassantidebug.exe` | Bản PE giải mã ra chuỗi lỗi `CRF{Byp44_4.472r74Dg}`; flag có khả năng là ý đồ của challenge được suy ra ở mục 7 |
| `win/giothieuanti.exe` | Cùng flag dài với `IForgetMyPassAgain` |
| `apk/basicapk.apk` | `CTF{SUp3r_Bas1c_R3v3rs3_Apk!!!}` |
| `apk/PinChecker.apk` | `CTF{fr1da_h00k_otp_e4sy!}` |

Các công cụ hữu ích để tái hiện: `file`, `strings -a`, `rabin2 -I`, `rabin2 -zz`, `r2 -A`, JADX/`apktool`, `pyinstxtractor` và `xdis`. Với radare2, `afl` liệt kê hàm, `pdf @ main` xem disassembly, `axt @ <địa chỉ>` tìm nơi dữ liệu được dùng. Vì có nhiều file, mỗi mục dưới đây nêu riêng điểm nhận dạng và bước tính flag.

## 1. WhatIsMyPassword

### Phân tích

1. `file WhatIsMyPassword` xác nhận đây là ELF x86-64.
2. Dùng `strings -a WhatIsMyPassword` để lấy nhanh chuỗi hiển thị; sau đó mở `r2 -A WhatIsMyPassword`, tìm `main` bằng `afl` và xem `pdf @ main`.
3. `main` đọc input, kiểm tra độ dài 8, rồi gọi `strcmp` với chuỗi literal `P4sSw0rD`. Nhánh thành công in flag; không có phép biến đổi mật mã nào khác.

### Flag

```text
Flag{The_password_is_P4sSw0rD}
```

## 2. IForgetMyPassAgain và win/giothieuanti.exe

Hai file chứa cùng bài toán. Chương trình yêu cầu password đúng 21 byte. Nó giải mã password nhúng trong chương trình, so sánh với input, rồi dùng password đó XOR lặp để giải secret. Bản Windows có import `IsDebuggerPresent` và mã rác do build MSVC; dữ liệu password/secret cho cùng kết quả như bản ELF.

### 2.1. Khôi phục password

Trong `main`, độ dài input được so với `0x15` (21). Hàm giải mã password dựng một mảng 21 byte từ các hằng số ghi vào stack. Một phần ghi sau đè lên ba byte cuối của phần trước. Dựng mảng sau cùng theo đúng thứ tự ghi:

```text
0a e8 d1 69 26 fd e7 3a 00 4a f2 ef 1c 6d a9 b9 2f 23 1d 9d 02
```

Trong mỗi vòng lặp, các phép tính `junk1`/`junk2` triệt tiêu nhau. Phần còn lại ở từng byte là:

```text
x = ciphertext[i] XOR ((37*i + 19) & 0xff)
password[i] = ((ROL8(x, 5) XOR 0x77) - 57*i) & 0xff
```

Script tái tạo cả thao tác ghi chồng lẫn phép biến đổi:

```python
enc = bytearray(21)
enc[:8] = bytes.fromhex("0ae8d16926fde73a")
enc[8:16] = bytes.fromhex("004af2ef1c6da9b9")
enc[13:21] = bytes.fromhex("6da9b92f231d9d02")  # ghi đè byte 13..15

def rol8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xff

password = bytes(
    ((rol8(c ^ ((37 * i + 19) & 0xff), 5) ^ 0x77) - 57 * i) & 0xff
    for i, c in enumerate(enc)
)
print(password.decode())
```

Kết quả là `T4t_c4_cH1_la_C0n9_cU`.

### 2.2. Giải secret

ELF giữ secret 487 byte tại VA `0x4060`, tương ứng file offset `0x3060`. Mỗi byte ciphertext được XOR với password lặp theo chu kỳ 21 byte. Có thể tái tạo toàn bộ kết quả bằng:

```python
from pathlib import Path

password = b"T4t_c4_cH1_la_C0n9_cU"
binary = Path("IForgetMyPassAgain").read_bytes()
ciphertext = binary[0x3060:0x3060 + 487]
secret = bytes(c ^ password[i % len(password)] for i, c in enumerate(ciphertext))
print(secret.decode("utf-8"))
```

Bản Windows thực hiện cùng vòng XOR trên 487 byte trong vùng `.data` (VA `0x14001f000`). Flag chung:

```text
Flag{Cu01_cung_m01_c0_m07_b0_4n1m3_m4_nh4n_v4t_ch1nh_dung_chu4n_h1nh_m4u_ly_tu0ng_cu4_t40._M0t_k3_l4nh_lung_v4_1t_n01._D4m_b4n_kh0ng_h13u_t41_540_t40_tr0_n3n_1m_l4ng_v4_lu0n_du0c_5_d13m_b41_k13m_tr4._Chung_n0_kh0ng_b13t_n4ng_luc_thuc_5u_cu4_t40_v4_kh0ng_h3_b13t_t40_xu4t_chung_t01_muc_n40._T40_ch4ng_c01_chung_l4_g1_ng04i_c0ng_cu._T40_u0c_m1nh_c0_th3_v40_tr0ng_th3_giới_4n1m3_v4_b0c_l0_c0n_ngu01_thuc_5u_cu4_m1nh._T40_t1n_ch4c_r4ng_t40_ch1nh_l4_h04_th4n_ng04i_d01_thuc_cu4_Ay4n0k0uj1.}
```

## 3. InfiniteXOR

### Phân tích mã

1. `strings -a InfiniteXOR` cho thấy đây là chương trình tương tác: in lời nhắc, đọc `%s`, biến đổi rồi in lại input. Không có chuỗi flag hay ciphertext cố định trong `.rodata`.
2. `pdf @ main` cho thấy key được tạo bằng hai phép ghi little-endian:
   - `mov dword ..., 0x346d3044` tạo byte `44 30 6d 34`, tức `D0m4`.
   - `mov word ..., 0x6e31` ghi tiếp byte `31 6e`, tức `1n`.
   - Sáu byte liền nhau do đó là `D0m41n`.
3. Hằng số nhân `0xaaaaaaaaaaaaaaab`, các phép shift và phép trừ trong vòng lặp tính phần dư `i % 6`. Vòng lặp xử lý đúng 100 vị trí: `i = 0..99`.
4. Mỗi vị trí được cập nhật tại chỗ: `input[i] ^= key[i % 6]`. Sau đó chương trình in buffer. Không có nhánh kiểm tra đáp án, không so sánh output với flag và không có ciphertext đích để đảo ngược.

Phép biến đổi là XOR nên có thể giải bất kỳ ciphertext đi kèm từ nguồn khác như sau:

```python
key = b"D0m41n"
plaintext = bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext))
```

Artifact hiện có không chứa `ciphertext`; vì vậy không tồn tại một flag duy nhất để suy ra chỉ từ file này. `scanf("%s")` cũng không giới hạn độ dài, còn vòng lặp luôn chạy 100 lần, nên input ngắn có thể khiến buffer chứa dữ liệu chưa khởi tạo sau byte NUL. Đây là lỗi input/bộ nhớ của demo, không phải một bước kiểm flag.

## 4. RevPY

### Trích xuất và nhận diện thuật toán

1. `file RevPY`/strings cho biết đây là executable PyInstaller. Dùng `pyinstxtractor.py RevPY` để lấy CArchive.
2. Bytecode được tạo bởi Python 3.13; dùng `xdis` hoặc decompiler hỗ trợ đúng phiên bản để xem hàm `checkflag`.
3. `checkflag` giới hạn flag 20 ký tự và so sánh từng ký tự sau phép biến đổi. Các mảng key, IV và AES ciphertext đều được XOR với mask `0x36` trước khi dùng.
4. Giải XOR mask cho key và IV:

```text
KEY_DATA = (5,87,3,79,113,67,5,69,3,7,88,81,93,5,79,23)
IV_DATA  = (69,67,70,83,68,69,83,85,68,83,66,95,64,8,12,5)
mask     = 0x36
AES key  = 3a5yGu3s51ngk3y!
IV       = supersecretiv>:3
```

AES-CBC ciphertext sau khi unmask:

```text
b4ed512ca51986be2a7f9b31ac775bb6f6149b5a919668388f6d516b1f37faec
```

Sau AES-CBC và bỏ PKCS#7 padding, chương trình so sánh mỗi byte `t[i]` với `((ord(flag[i]) ^ 0x36) + 3*i) & 0xff`. Đảo theo thứ tự ngược: trừ `3*i` theo modulo 256 rồi XOR `0x36`.

### Script giải

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

mask = 0x36
key_data = (5,87,3,79,113,67,5,69,3,7,88,81,93,5,79,23)
iv_data  = (69,67,70,83,68,69,83,85,68,83,66,95,64,8,12,5)
key = bytes(x ^ mask for x in key_data)
iv = bytes(x ^ mask for x in iv_data)
ct = bytes.fromhex(
    "b4ed512ca51986be2a7f9b31ac775bb6"
    "f6149b5a919668388f6d516b1f37faec"
)
transformed = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
flag = bytes((((x - 3*i) & 0xff) ^ mask) for i, x in enumerate(transformed))
print(flag.decode())
```

Flag: `CTF{pY7h0n_345y_R3v}`.

## 5. trytodebugme

### Phân tích và giải mã

Binary đọc `/proc/self/status`, lấy `TracerPid`, rồi kiểm tra danh sách tiến trình để tìm tên debugger như `gdb-multiarch`, `lldb`, `radare2`, `ida64`, `ghidra` và `cheatengine`. Những kiểm tra này cản trở chạy dưới debugger nhưng không che được mảng byte tĩnh.

Hàm in thông điệp XOR từng byte của mảng dưới đây với `0xf9`:

```text
ba ad bf 82 bb 80 89 cd cc cc a6 cd 97 8d c8 a6 bd ca 9b ac 9e 84
```

Tái tạo bằng Python:

```python
enc = bytes.fromhex(
    "ba ad bf 82 bb 80 89 cd cc cc a6 cd "
    "97 8d c8 a6 bd ca 9b ac 9e 84"
)
print(bytes(x ^ 0xf9 for x in enc).decode())
```

Flag: `CTF{Byp455_4nt1_D3bUg}`.

## 6. win/Guessing.exe

### Phân tích và tạo chuỗi được băm

1. Strings trong PE cho thấy yêu cầu đoán 100 vòng và thông báo thành công định dạng `YOUR FLAG IS: CTF{%s}`.
2. Disassembly gọi `rand()` 100 lần. Binary không import/gọi `srand()`, vì vậy MSVC CRT dùng seed mặc định 1.
3. Mỗi giá trị là `1000 + rand() % 9000`, tức số 4 chữ số.
4. Chương trình băm SHA-256 các số dạng thập phân, nối bằng dấu phẩy (không có dấu phẩy cuối). Digest được in ở dạng hex chữ thường.

MSVC `rand()` dùng recurrence `state = state * 214013 + 2531011 (mod 2^32)` và trả `(state >> 16) & 0x7fff`. Script:

```python
import hashlib

state = 1
numbers = []
for _ in range(100):
    state = (state * 214013 + 2531011) & 0xffffffff
    r = (state >> 16) & 0x7fff
    numbers.append(1000 + r % 9000)

message = ",".join(str(x) for x in numbers).encode()
digest = hashlib.sha256(message).hexdigest()
print("CTF{" + digest + "}")
```

Vài giá trị đầu là `1041, 1467, 7334, 9500, 2169`; năm giá trị cuối là `4538, 8118, 3082, 5929, 8541`. SHA-256 là `90e8f2c958a19840510acff379cf19c553c49420c137c2ffab936b2702b68e2b`.

Flag:

```text
CTF{90e8f2c958a19840510acff379cf19c553c49420c137c2ffab936b2702b68e2b}
```

## 7. win/bypassantidebug.exe

### Phân tích bytecode PE

Hàm kiểm tra anti-debug thử `IsDebuggerPresent`, cờ `BeingDebugged` trong PEB, `CheckRemoteDebuggerPresent`, `NtGlobalFlag`, sau đó quét process list để tìm debugger. Nếu phát hiện debugger, chương trình đi vào nhánh lỗi/`int3`. Khi các kiểm tra sạch, ba lần gọi hàm trả lần lượt `0x5a`, `0x3c`, `0x9f`; `main` XOR ba giá trị này:

```text
0x5a XOR 0x3c XOR 0x9f = 0xf9
```

Mảng byte được XOR với khóa đó:

```text
ba ab bf 82 bb 80 89 cd cd a6 cd d7 cd ce cb 8b ce cd bd 9e 84
```

Kết quả thực tế của PE là:

```text
CRF{Byp44_4.472r74Dg}
```

Chuỗi này có vẻ sai dữ liệu: nó không mở đầu bằng `CTF` và thân flag bị hỏng. Binary `trytodebugme` trong cùng thư mục có thông điệp cùng chủ đề anti-debug, giải mã thành `CTF{Byp455_4nt1_D3bUg}`. So sánh byte cho thấy mảng mã hóa của Windows khác với mảng cần thiết để tạo flag đó; do đó flag hợp lý theo ý đồ của bộ challenge là:

```text
CTF{Byp455_4nt1_D3bUg}
```

Đây là suy luận dựa trên binary Linux liên quan. Output đúng theo byte hiện tại của `bypassantidebug.exe` vẫn là chuỗi `CRF{Byp44_4.472r74Dg}` phía trên. Không thể khẳng định PE đã đóng gói đúng flag nếu không có bản binary/source khác.

## 8. apk/basicapk.apk

### Tìm key, IV và giải AES

1. Mở APK bằng JADX, tìm `MainActivity` và listener của nút kiểm tra.
2. Listener gọi hàm `decrypt` với ciphertext Base64 hardcode.
3. `decrypt` dùng `AES/CBC/PKCS5Padding`. Key và IV được truyền dưới dạng chuỗi ASCII 16 byte.

```text
ciphertext Base64 = E1QN7PnxJsb6s21SpV1e95tL9E8STO9WOF7M7DXWEA4=
key               = s3cr3tk3y!!!!!!!
IV                = s3cretIv!!!!!!!!
```

Giải mã bằng PyCryptodome:

```python
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ct = b64decode("E1QN7PnxJsb6s21SpV1e95tL9E8STO9WOF7M7DXWEA4=")
pt = AES.new(b"s3cr3tk3y!!!!!!!", AES.MODE_CBC, b"s3cretIv!!!!!!!!").decrypt(ct)
print(unpad(pt, 16).decode())
```

Flag: `CTF{SUp3r_Bas1c_R3v3rs3_Apk!!!}`.

## 9. apk/PinChecker.apk

### Đọc logic và brute force PIN

1. Mở `classes3.dex` bằng JADX, xem luồng của `MainActivity` và `CryptoHelper`.
2. UI chỉ yêu cầu chuỗi PIN dài 6 ký tự.
3. Key AES là `SHA256(pin || "CTF_SALT_2026")[:16]`; IV là `1234567890123456`; ciphertext được Base64 nhúng trong DEX.
4. Thử toàn bộ `000000` đến `999999`. Chấp nhận kết quả khi padding PKCS#7 hợp lệ và plaintext bắt đầu bằng `CTF{`.

```python
from base64 import b64decode
from hashlib import sha256
from Crypto.Cipher import AES

ct = b64decode("h86dPZchLKJiVIIGLJhAIoGNN9VAkVGj/pxtUZk4n3s=")
iv = b"1234567890123456"
salt = b"CTF_SALT_2026"

for n in range(1_000_000):
    pin = f"{n:06d}".encode()
    key = sha256(pin + salt).digest()[:16]
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    pad = pt[-1]
    if (pt.startswith(b"CTF{") and 1 <= pad <= 16
            and pt.endswith(bytes([pad]) * pad)):
        print("PIN:", pin.decode())
        print("Flag:", pt[:-pad].decode())
        break
```

Kết quả: PIN `641888`, flag `CTF{fr1da_h00k_otp_e4sy!}`. DEX có thêm `PinGenerator.generateCurrentPin`, nhưng luồng nút kiểm tra không gọi hàm đó; PIN sinh từ seed trong hàm này là decoy, không mở được ciphertext.

## 10. Các flag còn thiếu và giới hạn dữ liệu

- **Flag anti-debug dự kiến:** `CTF{Byp455_4nt1_D3bUg}` được xác nhận trực tiếp bởi `trytodebugme`; `bypassantidebug.exe` có mảng mã hóa lệch nên output nguyên bản là chuỗi lỗi nêu ở mục 7.
- **InfiniteXOR:** đã xác nhận key/thuật toán, nhưng file chỉ XOR input tùy ý rồi in output. Nó không chứa flag hay ciphertext cần giải và không có kiểm tra flag. Để suy ra một flag cụ thể cần ciphertext/output hoặc file phụ từ đề bài; không có dữ liệu đó trong thư mục hiện tại.

