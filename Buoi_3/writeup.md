# Writeup chi tiết bằng IDA và GDB — bộ reverse engineering demo

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

Writeup này ưu tiên thao tác bằng IDA và GDB. Trong môi trường làm bài hiện tại có `gdb-multiarch` nhưng không có IDA; mình đã dùng GDB để xác nhận disassembly x86-64, còn các bước IDA bên dưới mô tả thao tác GUI tương ứng để người mới làm lại. Máy hiện tại là ARM64 và không có x86-64 loader, nên GDB chỉ đọc/disassemble ELF được tại đây. Muốn chạy chương trình dưới debugger, dùng máy Linux x86-64 hoặc QEMU user mode cùng sysroot x86-64.

### Quy trình IDA cơ bản

1. Mở IDA, chọn **New** rồi chọn file. Với ELF/PE x86-64, chọn processor `metapc` và bitness 64 nếu IDA hỏi. Chờ autoanalysis hoàn tất.
2. Mở cửa sổ **Functions** và tìm `main`. Binary chưa strip thường có tên hàm; file stripped sẽ có tên kiểu `sub_...`. Với stripped binary, bắt đầu ở Entry point rồi lần theo các lời gọi hàm.
3. Mở **Strings** (thường là `Shift+F12`), tìm các chuỗi gợi ý như `password`, `flag`, `Wrong`, `Enter` hoặc `secret`. Nhấp đôi chuỗi để đến địa chỉ dữ liệu.
4. Đứng trên chuỗi rồi nhấn `X` để mở **Cross references**. Chọn tham chiếu từ code để đi đến hàm đang in hoặc so sánh chuỗi đó.
5. Trong disassembly, `Space` đổi giữa Text view và Graph view; `G` đi đến địa chỉ/hàm; `Esc` quay lại vị trí trước. Tìm các lệnh `call`, `cmp`, `test`, `je/jne` để thấy chương trình chọn nhánh thành công hay thất bại.
6. Nếu có Hex-Rays, nhấn `F5` để xem pseudocode. Nếu không có decompiler, vẫn có thể lần theo assembly; IDA chỉ là giao diện giúp đọc/xref và không bắt buộc phải có pseudocode.

Khi đọc lệnh: `mov` chép giá trị, `lea` thường tính địa chỉ, `call` gọi hàm, `cmp` so sánh hai giá trị, còn `test reg,reg` thường kiểm tra một giá trị có bằng 0 không. `je`/`jz` nhảy khi bằng/0; `jne` nhảy khi khác/không 0. Hằng số có `0x` là hệ thập lục phân: ví dụ `0x15` là 21. Trên x86, byte ở bộ nhớ little-endian nên immediate `0x346d3044` được lưu thành `44 30 6d 34`.

### Quy trình GDB cơ bản

GDB chạy chương trình từng lệnh; IDA chủ yếu giúp đọc cấu trúc chương trình mà không cần chạy. Ví dụ, GDB multiarch có thể đọc hàm `main` của ELF x86-64 ngay cả trên ARM:

```text
gdb-multiarch -q ./WhatIsMyPassword
(gdb) set disassembly-flavor intel
(gdb) info functions main
(gdb) disassemble main
```

Các lệnh thường dùng:

```text
break main       đặt breakpoint tại main
run              chạy chương trình
continue         chạy tiếp đến breakpoint kế tiếp
nexti            chạy một lệnh máy, không đi vào hàm được gọi
stepi            chạy một lệnh máy và đi vào hàm được gọi
disassemble      xem assembly quanh vị trí hiện tại
info registers   xem thanh ghi
x/s ADDRESS      đọc bộ nhớ như chuỗi C kết thúc bằng NUL
x/32bx ADDRESS   xem 32 byte dưới dạng hex
finish           chạy đến khi hàm hiện tại return
quit             thoát GDB
```

Khi gõ `run`, chương trình bắt đầu chạy. Nếu chương trình in lời nhắc, nhập dữ liệu của challenge ở đó; chỉ khi debugger dừng mới nhập lệnh bắt đầu bằng `(gdb)`. `RIP` là địa chỉ lệnh đang chạy, `RSP` là stack pointer, `RBP` thường là frame pointer, còn `RAX` thường chứa kết quả hàm. `cmp`/`test` cập nhật cờ CPU; `je`/`jz` nhảy khi điều kiện bằng/zero, còn `jne` nhảy khi khác/nonzero. Các nhánh đó cho biết input đúng đi tiếp hay rẽ sang lỗi.

Trong Linux x86-64, sáu đối số nguyên/con trỏ đầu tiên thường đi lần lượt qua `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`; giá trị trả về nằm trong `RAX`. Vì vậy tại `strcmp(a,b)`, `x/s $rdi` và `x/s $rsi` cho thấy hai chuỗi đang được so sánh. Khi file có symbols, dùng `break main` thay vì đoán địa chỉ. Với file stripped/PIE, trong IDA lấy địa chỉ hàm, rồi trong GDB chạy `starti`, gõ `info proc mappings` và tìm mapping của chính file có file offset `0`. Gọi địa chỉ đầu mapping là `B`; địa chỉ runtime tương ứng bằng `B + địa chỉ IDA` (ELF này có image base 0). Sau đó đặt breakpoint bằng `break *(B + 0xADDR)`. Ví dụ `trytodebugme` có entry hàm chính khoảng `0x3858` trong IDA, vậy breakpoint runtime là `B + 0x3858`.

Nếu đang dùng ARM64 mà có sẵn sysroot x86-64, có thể chạy QEMU user mode và nối GDB từ terminal khác:

```text
qemu-x86_64 -L /path/to/x86_64-sysroot -g 1234 ./WhatIsMyPassword
gdb-multiarch -q ./WhatIsMyPassword
(gdb) target remote :1234
(gdb) break main
(gdb) continue
```

Sysroot cần có `/lib64/ld-linux-x86-64.so.2` và thư viện x86-64 của chương trình. Trong môi trường phân tích này chưa có loader đó, nên chỉ dùng GDB để xem disassembly; không nên nhầm lỗi môi trường với lỗi của challenge. Với `.exe`, dùng IDA để phân tích PE; GDB thường chỉ phù hợp nếu đang ở Windows toolchain/debugger hoặc thiết lập Wine tương thích. Với APK/Python, dùng JADX/`apktool` và `pyinstxtractor`/`xdis` cho phần Java/bytecode; GDB không thay thế được các công cụ đó.

Các mục dưới đây ghi rõ điểm cần tìm trong IDA và điểm có thể quan sát bằng GDB.

## 1. WhatIsMyPassword

### Phân tích

1. `file WhatIsMyPassword` xác nhận đây là ELF x86-64.
2. Mở file trong IDA, chờ autoanalysis rồi vào hàm `main` ở Functions. Trong pseudocode hoặc disassembly sẽ thấy lời gọi đọc input, lời gọi `strcmp`, rồi nhánh `jne`/`jz` tới thông báo đúng/sai.
3. Mở Strings, tìm `P4sSw0rD` hoặc chuỗi flag. Nhấn `X` trên string để xem xref. Xref password dẫn về lời gọi so sánh; xref flag dẫn về nhánh thành công. Nhìn lệnh ngay sau `strcmp`: `test eax,eax`; giá trị trả về bằng 0 nghĩa là hai chuỗi giống nhau.
4. `main` kiểm tra input dài 8 ký tự rồi so sánh với literal `P4sSw0rD`. Không có phép biến đổi mật mã nào khác.

### Quan sát bằng GDB

Trên Linux x86-64, hoặc qua QEMU có sysroot phù hợp, đặt breakpoint ngay tại lệnh gọi `strcmp`:

```text
gdb -q ./WhatIsMyPassword
(gdb) set disassembly-flavor intel
(gdb) break *(main+72)
(gdb) run
Enter Password (8 characters): P4sSw0rD
(gdb) x/s $rdi
(gdb) x/s $rsi
(gdb) nexti
(gdb) p/d $eax
```

`main+72` là offset của lệnh `call strcmp` trong file này. Trước lệnh gọi, Linux x86-64 đặt đối số đầu tiên ở `RDI` (input) và đối số thứ hai ở `RSI` (password đã lưu). Sau `nexti`, `EAX` bằng 0 khi password khớp. Nếu địa chỉ thay đổi ở bản khác, trong IDA tìm lại lệnh `call strcmp` rồi dùng địa chỉ/offset của bản đó.

### Flag

```text
Flag{The_password_is_P4sSw0rD}
```

## 2. IForgetMyPassAgain và win/giothieuanti.exe

Hai file chứa cùng bài toán. Chương trình yêu cầu password đúng 21 byte. Nó giải mã password nhúng trong chương trình, so sánh với input, rồi dùng password đó XOR lặp để giải secret. Bản Windows có import `IsDebuggerPresent` và mã rác do build MSVC; dữ liệu password/secret cho cùng kết quả như bản ELF.

### Theo dấu bằng IDA

1. Mở `IForgetMyPassAgain`, vào `main`, rồi đọc các lời gọi theo thứ tự. Hàm đầu tiên kiểm tra `strlen(input) == 0x15`; nhánh sai in lỗi và thoát.
2. Theo lời gọi kế tiếp sang `decryptPass`. Trong hàm này, tìm vùng gán hằng số byte vào buffer stack. Ghi lại thứ tự gán vì có phép ghi sau đè lên các phần tử trước.
3. Tìm vòng lặp chạy 21 lần. Dùng lệnh `cmp` giới hạn vòng lặp và các phép XOR/add/sub/rotate để rút gọn công thức byte như phần dưới.
4. Quay về `main`: sau `decryptPass` có `strcmp(input, decoded_password)`. Nhánh bằng 0 mới gọi `getSecret`.
5. Trong `getSecret`, lần theo vùng secret tĩnh dài 487 byte và vòng lặp XOR từng byte với password theo `i % 21`.

Nếu Hex-Rays có mặt, F5 làm dễ đọc cấu trúc vòng lặp; nếu không, các lệnh `mov`, `xor`, `add`, `sub`, `rol/ror` và nhánh vòng lặp vẫn đủ để viết lại thuật toán. Bản Windows lớn và nhiều nhiễu hơn nhưng dùng đúng cách làm tương tự: vào hàm logic từ xref của chuỗi prompt, bỏ qua các phép tính không ảnh hưởng đầu ra, tập trung vào array byte và vòng lặp.

Với `win/giothieuanti.exe`, làm cụ thể như sau: mở Strings, tìm `Enter the password to release the secret:` rồi bấm `X` để về hàm xử lý chính. Ở đó sẽ thấy phép so sánh độ dài với `0x15`, lời gọi hàm giải password, phép so sánh input và nhánh gọi phần lấy secret. Tiếp tục mở hàm tạo password; các phép ghi byte ở stack trùng bộ ciphertext 21 byte phía trên. Hàm giải secret đọc 487 byte ở vùng `.data` và XOR theo byte password lặp. Windows x64 dùng `RCX/RDX/R8/R9` cho đối số; khi đọc pseudocode cần nhớ không áp dụng thứ tự thanh ghi Linux `RDI/RSI` cho PE.

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

### Quan sát bằng GDB

File ELF có symbols cho `main`, `decryptPass` và `getSecret`, nên trên môi trường x86-64 có thể dừng trực tiếp ở các hàm:

```text
gdb -q ./IForgetMyPassAgain
(gdb) set disassembly-flavor intel
(gdb) break decryptPass
(gdb) break getSecret
(gdb) run
Enter the password to release the secret: T4t_c4_cH1_la_C0n9_cU
(gdb) finish
(gdb) x/s $rax
(gdb) continue
(gdb) finish
(gdb) x/s $rax
```

Trước đó đã đặt cả hai breakpoint. Khi dừng ở `decryptPass`, dùng `disassemble decryptPass` hoặc `display/i $pc` để chạy từng lệnh. `finish` chạy đến khi hàm return; ở bản ELF này hàm trả về con trỏ tới chuỗi đã giải mã, nên `x/s $rax` hiện password. Vì input đã là password đúng, `continue` đi qua `strcmp` và dừng ở `getSecret`; `finish` lần nữa rồi `x/s $rax` sẽ hiện secret plaintext. Nếu cần nhìn byte thô, dùng `x/21bx ADDRESS` cho password hoặc `x/32bx ADDRESS` cho phần đầu secret.

Trong máy ARM64 hiện tại, các breakpoint vẫn có thể được đặt và hàm có thể disassemble, nhưng `run` không hoạt động vì thiếu x86-64 loader. Dùng x86-64 Linux hoặc QEMU+sysroot như phần hướng dẫn đầu file để làm dynamic debugging.

## 3. InfiniteXOR

### Phân tích mã

1. `strings -a InfiniteXOR` cho thấy đây là chương trình tương tác: in lời nhắc, đọc `%s`, biến đổi rồi in lại input. Không có chuỗi flag hay ciphertext cố định trong `.rodata`.
2. Trong IDA, mở `main` và theo các lệnh đầu hàm để thấy key được tạo bằng hai phép ghi little-endian:
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

### Quan sát bằng GDB

Trong IDA, hai phép ghi key nằm ngay đầu `main`, sau đó vòng lặp có nhánh `jbe` khi chỉ số còn `<= 0x63` (99). Trong GDB x86-64, đặt breakpoint sau khi `scanf` đọc xong để xem buffer và key:

```text
$ python3 -c 'print("A" * 100)' > /tmp/xor_input.txt
$ gdb -q ./InfiniteXOR
(gdb) set disassembly-flavor intel
(gdb) break *(main+98)
(gdb) break *(main+191)
(gdb) run < /tmp/xor_input.txt
(gdb) x/6cb $rbp-0xa
(gdb) x/32bx $rbp-0x70
(gdb) continue
(gdb) x/100bx $rbp-0x70
(gdb) disassemble main
```

`x/6cb` hiển thị 6 byte key như ký tự và hex; vùng input bắt đầu tại `$rbp-0x70`. GDB dừng ở `main+98` sau `scanf`, trước vòng lặp XOR; breakpoint thứ hai ở `main+191` dừng sau 100 vòng và trước `printf`, nên lệnh `x/100bx` đọc được buffer đã đổi. Cần nhập đủ 100 byte vì code luôn xử lý 100 vị trí; input ngắn làm các byte phía sau NUL không xác định.

Artifact hiện có không chứa `ciphertext`; vì vậy không tồn tại một flag duy nhất để suy ra chỉ từ file này. `scanf("%s")` cũng không giới hạn độ dài, còn vòng lặp luôn chạy 100 lần, nên input ngắn có thể khiến buffer chứa dữ liệu chưa khởi tạo sau byte NUL. Đây là lỗi input/bộ nhớ của demo, không phải một bước kiểm flag.

## 4. RevPY

### Trích xuất và nhận diện thuật toán

1. `file RevPY`/strings cho biết đây là executable PyInstaller. Trong IDA, có thể xem PE/ELF bootstrap và tìm dấu hiệu archive, nhưng phần chính là Python bytecode đã đóng gói. Dùng `pyinstxtractor.py RevPY` để lấy CArchive.
2. Bytecode được tạo bởi Python 3.13; dùng `xdis` hoặc decompiler hỗ trợ đúng phiên bản để xem hàm `checkflag`.
3. `checkflag` giới hạn flag 20 ký tự và so sánh từng ký tự sau phép biến đổi. Các mảng key, IV và AES ciphertext đều được XOR với mask `0x36` trước khi dùng.
4. Trong IDA không nên nhầm code bootloader với logic Python. Sau khi extract, đọc bytecode của module `RevPY` bằng `xdis`/decompiler rồi tìm hàm `checkflag`. GDB không giúp đọc bytecode; dùng nó chỉ để kiểm tra native bootloader nếu thật sự cần. Giải XOR mask cho key và IV:

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

### Lần theo trong IDA

File này đã strip, nên Functions có thể không hiện tên `main`. Vào Entry point, rồi dùng Strings tìm `/proc/self/status` hoặc `TracerPid:`. Nhấn `X` trên string để đến hàm đọc status. Tiếp tục lần các lời gọi từ entry point tới hàm kiểm tra process; các chuỗi `gdb-multiarch`, `lldb`, `radare2`, `ida64`, `ghidra` và `cheatengine` cho biết chương trình dò tên debugger nào. Từ xref của thông báo/chuỗi flag, mở hàm tạo output và tìm phép XOR trên từng byte.

Binary đọc `/proc/self/status`, lấy `TracerPid`, rồi kiểm tra danh sách tiến trình để tìm tên debugger. Những kiểm tra này cản trở chạy dưới debugger nhưng không che được mảng byte tĩnh.

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

GDB có thể tự làm thay đổi kết quả của bài này: khi tiến trình đang chạy dưới GDB, `TracerPid` thường khác 0. Nếu chạy trong GDB mà thấy nhánh anti-debug hoặc output khác dự kiến, đó là hành vi của check chứ chưa phải bằng chứng flag sai. Với bài này, xem array và XOR trong IDA là cách ổn định để lấy flag. Trên máy x86-64 có thể dùng GDB để dừng ở hàm đọc `/proc/self/status`, nhưng không cần thiết cho phép giải.

## 6. win/Guessing.exe

### Phân tích và tạo chuỗi được băm

1. Strings trong PE cho thấy yêu cầu đoán 100 vòng và thông báo thành công định dạng `YOUR FLAG IS: CTF{%s}`.
2. Disassembly gọi `rand()` 100 lần. Binary không import/gọi `srand()`, vì vậy MSVC CRT dùng seed mặc định 1.
3. Mỗi giá trị là `1000 + rand() % 9000`, tức số 4 chữ số.
4. Chương trình băm SHA-256 các số dạng thập phân, nối bằng dấu phẩy (không có dấu phẩy cuối). Digest được in ở dạng hex chữ thường.

### Thao tác trong IDA

Mở `Guessing.exe` và chờ autoanalysis. Trong Strings tìm `YOUR FLAG IS`, mở xref để về hàm in flag; tìm thêm chuỗi hướng dẫn đoán 100 vòng để xác định loop trong `main`. Mở Imports, thấy `rand` và các API Crypto của Windows như `CryptAcquireContext`, `CryptCreateHash`, `CryptHashData`, `CryptGetHashParam`. Trong graph view lần nhánh kiểm tra số đoán đúng, vòng gọi `rand`, cách định dạng số thành chuỗi và dữ liệu gửi vào hàm hash. Windows x64 truyền các đối số hàm qua `RCX`, `RDX`, `R8`, `R9`; quy tắc này khác SysV Linux.

GDB trên máy ARM này không chạy PE. Để giải bài không cần chạy chương trình: disassembly IDA cho biết thuật toán, còn script bên dưới tái tạo dãy số và SHA-256.

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

### Phân tích PE

Trong IDA, mở `bypassantidebug.exe`, vào `main` nếu IDA nhận diện được. Tìm Strings `Your flag is Flag:` và mở xref để xác định vùng in cuối. Trong Imports tìm `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `CreateToolhelp32Snapshot`, `Process32FirstW` và `Process32NextW`; mở xref từng import để lần vào hàm anti-debug. Trên đường chạy sạch, ghi ba giá trị trả về theo từng đối số gọi, sau đó xem lệnh `xor dil, al` trong `main`: nó gộp ba kết quả thành byte dùng giải array.

Mảng byte được đặt trên stack ngay trước lệnh in. Đọc các immediate little-endian theo thứ tự byte thấp trước, ghép lại rồi dừng ở byte NUL. Có thể đưa các byte vào Python Console của IDA hoặc script Python bên ngoài để XOR. GDB không phù hợp với PE trong môi trường ARM này; ngoài ra chương trình chủ động chặn khi phát hiện debugger.

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

IDA/GDB không phải đường ngắn nhất với APK: DEX là bytecode Dalvik/Java, không phải mã máy x86. Nếu muốn giữ quy trình reverse, giải nén APK, mở `classes3.dex` trong JADX, rồi lần từ button listener sang hàm decrypt và constants. IDA chỉ hữu ích nếu phiên bản/cấu hình đang dùng nhận DEX; GDB cần Android emulator/device và không giúp khôi phục key hardcode.

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

GDB không cần cho brute force này: script Python tái tạo trực tiếp KDF, AES và điều kiện kiểm tra. Trong JADX, bước quan trọng là xác định đúng salt, IV, ciphertext và điều kiện chấp nhận plaintext trước khi viết vòng lặp.

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



