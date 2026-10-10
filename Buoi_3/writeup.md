# Hướng dẫn giải bộ CTF dịch ngược cho người mới hoàn toàn

Tài liệu này hướng dẫn giải các file trong thư mục `chall`. Bạn có thể bắt đầu khi chưa biết IDA, GDB hay assembly. Bài đầu được giải chậm từng bước; những bài sau dùng lại các kiến thức đã giới thiệu.

Nếu mới hoàn toàn, đọc mục 1–4 trước và tự làm bài `WhatIsMyPassword`. Sau đó làm từng bài theo đường đọc ở mục 16. Khi cần tìm một bài cụ thể, dùng `Ctrl+F` và gõ tên file; bảng đáp án nằm ở mục 15.

Mục tiêu của mỗi bài là tìm **flag**: chuỗi đáp án mà hệ thống CTF yêu cầu, thường có dạng `CTF{...}` hoặc `Flag{...}`. Bạn cần giữ nguyên chữ hoa, chữ thường, dấu câu và ký tự đặc biệt khi nộp.

**Về kết quả phân tích:** các byte, công thức và kết quả giải mã bên dưới được lấy từ những file hiện có. Phiên phân tích dùng Linux ARM64 và `gdb-multiarch` để đọc disassembly tĩnh; chưa thực hiện phiên thao tác GUI trong IDA hoặc chạy ELF x86-64 dưới GDB vì thiếu môi trường chạy phù hợp. Các bước IDA là hướng dẫn để bạn làm trên máy của mình; các phiên GDB động cần Linux x86-64 có thư viện phù hợp. Những phần không thể xác nhận như flag dự kiến của một file Windows được ghi rõ.

## 1. Trước khi giải: hiểu mình đang làm gì

### 1.1. Dịch ngược là gì?

Bình thường, người lập trình viết mã nguồn, rồi công cụ biên dịch biến nó thành chương trình chạy được. Trong bài CTF này, bạn có chương trình nhưng không có mã nguồn.

Dịch ngược là đọc chương trình để tìm hiểu nó hoạt động ra sao. Chẳng hạn, một chương trình yêu cầu nhập mật khẩu. Bạn sẽ tìm:

1. Chỗ chương trình đọc thứ bạn nhập.
2. Chỗ nó kiểm tra dữ liệu đó.
3. Điều kiện để đi vào nhánh thành công.
4. Chỗ nó tạo hoặc in flag.

Không cần hiểu mọi hàm trong file. Một executable còn chứa mã khởi động, mã thư viện và nhiều phần không tham gia kiểm tra đáp án. Ta bắt đầu từ lời nhắc trên màn hình, rồi lần đến đoạn xử lý liên quan.

### 1.2. Ba loại file trong thư mục

| Loại | File trong bộ này | Cách đọc chính |
|---|---|---|
| ELF | Các file Linux không có đuôi `.exe` | IDA để đọc; GDB để quan sát lúc chạy |
| PE | Các file `win/*.exe` | IDA để đọc mã máy Windows |
| APK | Hai file `apk/*.apk` | JADX để đọc mã Java/Dalvik |

`RevPY` cũng là ELF, nhưng nó đóng gói chương trình Python bằng PyInstaller. Muốn đọc logic của bài đó, phải lấy mã Python đã đóng gói ra trước.

**IDA** cho bạn xem cấu trúc chương trình, lệnh máy và dữ liệu mà không cần chạy file. Đây là **phân tích tĩnh**.

**GDB** cho bạn chạy chương trình, tạm dừng rồi xem dữ liệu đang có trong bộ nhớ. Đây là **phân tích động**.

**JADX** chuyển bytecode Android thành mã gần giống Java. Nó giúp đọc APK thuận tiện hơn việc xem từng lệnh máy.

### 1.3. Terminal, GDB và Python là ba nơi nhập lệnh khác nhau

Mở terminal rồi chuyển vào thư mục bài:

```bash
cd /home/kali/Desktop/hacker_lord/chall
```

Trong tài liệu này:

- Khối `bash` là lệnh nhập ở terminal.
- Khối có `(gdb)` là thao tác bên trong GDB. Chỉ gõ phần sau `(gdb)`.
- Khối `python` là mã lưu vào file `.py` rồi chạy bằng Python.
- Khối ghi “kết quả” là dữ liệu bạn mong thấy; không phải lệnh cần gõ.

Ví dụ:

```text
(gdb) disassemble main
```

Bạn chỉ nhập `disassemble main`. GDB tự in `(gdb)` ở đầu dòng.

Khi chương trình đang chạy và hiện `Enter Password...`, dữ liệu bạn gõ lúc đó là mật khẩu gửi cho chương trình. Khi GDB đã dừng và hiện `(gdb)`, dữ liệu bạn gõ là lệnh gửi cho debugger.

### 1.4. Cách lưu và chạy các script giải trong tài liệu

Ví dụ một mục yêu cầu lưu script thành `solve_password.py`:

1. Mở trình soạn thảo.
2. Tạo file `solve_password.py` trong thư mục `chall`.
3. Dán nguyên khối mã Python của mục đó vào file.
4. Lưu file.
5. Trong terminal đang ở thư mục `chall`, chạy:

```bash
python3 solve_password.py
```

Có thể dùng `nano` nếu muốn soạn ngay trong terminal:

```bash
nano solve_password.py
```

Dán mã, nhấn `Ctrl+O` rồi Enter để lưu, sau đó `Ctrl+X` để thoát.

Các bài AES cần thư viện PyCryptodome. Tạo môi trường Python riêng và cài thư viện:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome
```

Sau khi kích hoạt môi trường, chạy script bằng `python solve_ten_bai.py`. Nếu gặp `No module named Crypto`, kiểm tra bạn đã kích hoạt `.venv` trong terminal đang dùng chưa.

## 2. Những kiến thức đủ để đọc các bài này

### 2.1. Byte, hex, ký tự và địa chỉ

Một **byte** chứa số từ 0 đến 255. Các công cụ dịch ngược thường hiển thị byte bằng hệ thập lục phân, gọi tắt là **hex**.

| Giá trị hex | Giá trị thập phân | Ý nghĩa trong ví dụ |
|---|---:|---|
| `0x15` | 21 | Độ dài mật khẩu |
| `0x36` | 54 | Mặt nạ XOR trong RevPY |
| `0x63` | 99 | Chỉ số cuối của vòng lặp 100 phần tử |
| `0xff` | 255 | Giữ lại 8 bit thấp của một số |

`0x` báo rằng số đang viết ở hệ hex. IDA có thể viết `15h` thay vì `0x15`; chúng là cùng một số.

Một ký tự có thể được biểu diễn bằng một byte. Ví dụ, theo ASCII:

```text
'C' = 0x43
'T' = 0x54
'F' = 0x46
```

Một **địa chỉ** cho biết dữ liệu hoặc lệnh nằm ở đâu. Hãy hình dung bộ nhớ là dãy ngăn có đánh số; địa chỉ là số của ngăn. Số `0x202c` ở cạnh chuỗi trong IDA chỉ vị trí của chuỗi, không phải nội dung chuỗi.

Một **con trỏ** là giá trị chứa địa chỉ. Nếu thanh ghi chứa địa chỉ của chuỗi, ta phải đọc bộ nhớ tại địa chỉ đó mới thấy chữ.

### 2.2. Thanh ghi là gì?

CPU có một số ô chứa dữ liệu nhỏ gọi là **thanh ghi**. Với các bài x86-64:

| Thanh ghi | Điều cần nhớ |
|---|---|
| `RIP` | Địa chỉ lệnh máy tiếp theo sẽ thực hiện |
| `RAX` | Thường chứa giá trị hàm trả về |
| `RDI`, `RSI` | Thường chứa đối số thứ nhất và thứ hai trên Linux x86-64 |
| `RSP` | Chỉ vị trí hiện tại của stack |
| `RBP` | Thường được dùng làm mốc truy cập biến trong hàm |

**Stack** là vùng bộ nhớ chương trình thường dùng cho biến cục bộ và thông tin gọi hàm. Biểu thức `[rbp-0x70]` nghĩa là đọc bộ nhớ ở vị trí cách mốc `RBP` một khoảng `0x70` byte về phía địa chỉ thấp hơn.

`RAX` là thanh ghi 64 bit. `EAX` là phần 32 bit thấp của nó; `AL` là phần 8 bit thấp. Vì vậy `test eax,eax` đang kiểm tra giá trị trong phần `EAX`.

### 2.3. Đọc một số lệnh assembly thường gặp

Assembly là cách viết dễ đọc hơn của lệnh máy. Trong tài liệu dùng cú pháp Intel: thường viết đích trước, nguồn sau.

| Lệnh | Đọc bằng lời |
|---|---|
| `mov eax, 5` | Đặt EAX bằng 5 |
| `mov eax, [rbp-4]` | Đọc giá trị ở bộ nhớ rbp-4 vào EAX |
| `lea rdi, [rbp-0x40]` | Đặt RDI bằng địa chỉ rbp-0x40 |
| `call strcmp` | Gọi hàm strcmp |
| `ret` | Kết thúc hàm và quay về nơi đã gọi |
| `cmp eax, 21` | So sánh EAX với 21 |
| `test eax, eax` | Với mẫu này, kiểm tra EAX có bằng 0 không |
| `je` / `jz` | Nhảy nếu phép kiểm tra trước cho điều kiện bằng/zero |
| `jne` / `jnz` | Nhảy nếu phép kiểm tra trước cho điều kiện khác/không zero |
| `xor eax, 0x36` | XOR giá trị EAX với 0x36 |
| `add eax, 3` | Cộng 3 |
| `sub eax, 3` | Trừ 3 |

Dấu ngoặc vuông rất quan trọng:

```text
mov rax, [rbp-8]   -> lấy nội dung trong bộ nhớ
lea rax, [rbp-8]   -> lấy địa chỉ vùng bộ nhớ
```

Bạn sẽ thường gặp mẫu:

```asm
call strcmp
test eax, eax
jne wrong_password
```

`strcmp(a, b)` so sánh hai chuỗi. Nó trả **0 khi hai chuỗi giống nhau**. Vì vậy mẫu trên có nghĩa:

```text
So sánh hai chuỗi.
Nếu kết quả khác 0, đi đến nhánh mật khẩu sai.
Nếu kết quả bằng 0, tiếp tục xuống nhánh thành công.
```

Đừng hiểu `0` ở đây là “sai”. Ý nghĩa của số trả về phụ thuộc vào hàm đang gọi.

### 2.4. XOR: phép biến đổi gặp nhiều nhất trong bộ này

XOR là phép toán trên từng bit. Trong Python và nhiều ngôn ngữ, nó được viết bằng `^`.

Tính chất dùng để giải bài:

```text
Nếu ciphertext = plaintext XOR key
thì plaintext = ciphertext XOR key.
```

Ví dụ:

```python
original = ord("C")       # 0x43
encrypted = original ^ 0xf9
recovered = encrypted ^ 0xf9

print(hex(encrypted))    # 0xba
print(chr(recovered))    # C
```

XOR lần nữa với cùng khóa khôi phục dữ liệu ban đầu.

Khi khóa có nhiều byte, chương trình có thể dùng lại khóa từ đầu:

```text
Vị trí dữ liệu:  0 1 2 3 4 5 6 7 ...
Vị trí khóa:    0 1 2 3 4 5 0 1 ...
```

Đó là ý nghĩa của `i % 6`: lấy phần dư khi chia chỉ số `i` cho 6. Ví dụ `7 % 6 = 1`.

`& 0xff` giữ lại phần giá trị vừa trong một byte. Ví dụ `260 & 0xff = 4`. Trong các bài này, nó mô phỏng phép tính bị giới hạn ở 8 bit.

### 2.5. Little-endian: đọc hằng số theo đúng thứ tự byte

Trên x86-64, một số nhiều byte được lưu với byte thấp trước. Quy tắc này gọi là **little-endian**.

Ví dụ lệnh ghi số `0x346d3044` vào bộ nhớ sẽ tạo:

```text
Số:           0x346d3044
Byte lưu:     44 30 6d 34
Ký tự ASCII:  D  0  m  4
```

Nếu đọc nhầm thứ tự `34 6d 30 44`, bạn sẽ lấy sai chuỗi. Khi lấy mảng byte từ những lệnh `mov` trong IDA, luôn kiểm tra độ rộng của phép ghi và thứ tự byte.

## 3. Làm quen IDA và GDB trước khi giải bài đầu

### 3.1. Mở một file trong IDA

1. Mở IDA.
2. Chọn mở file mới, rồi chọn `WhatIsMyPassword`.
3. Để IDA nhận diện loại file. Với executable x86-64, processor thường là `metapc` và chế độ 64 bit.
4. Chờ quá trình tự phân tích hoàn tất.
5. Mở cửa sổ **Functions** để xem danh sách hàm.

Tên menu có thể khác đôi chút giữa các bản IDA. Những cửa sổ cần dùng thường nằm trong **View → Open subviews**.

Bạn sẽ dùng các thao tác sau:

| Thao tác | Công dụng |
|---|---|
| `Shift+F12` | Mở danh sách Strings |
| Nhấp đôi một string | Đi đến nơi chứa string |
| `X` khi con trỏ ở string/tên dữ liệu | Xem nơi nào tham chiếu đến nó |
| Nhấp đôi một xref | Đi đến nơi sử dụng dữ liệu |
| `G` | Đi đến tên hàm hoặc địa chỉ |
| `Esc` | Quay về vị trí trước |
| `Space` trong cửa sổ disassembly | Chuyển giữa sơ đồ nhánh và dạng văn bản |
| `F5` | Xem mã giả nếu có decompiler phù hợp |

**String** là chuỗi chữ, ví dụ `Enter Password`. **Xref**, viết đầy đủ là cross reference, là nơi dùng đến một hàm hoặc dữ liệu.

Tưởng tượng bạn tìm thấy tờ giấy ghi “Mật khẩu sai”. Xref giúp tìm đoạn chương trình nào có thể đưa tờ giấy đó ra màn hình. Từ đó, bạn lần ngược đến điều kiện khiến chương trình báo sai.

**Pseudocode**, hay mã giả, là cách công cụ viết lại logic gần giống C. Nó không phải mã nguồn gốc. Tên biến có thể là `v1`, `v2`; kiểu dữ liệu cũng có thể cần xem lại.

Nếu `F5` không hoạt động vì không có decompiler, vẫn làm được các bước tìm string, xref và đọc assembly trong tài liệu.

### 3.2. Mở file trong GDB để xem mã mà chưa chạy

Nhập ở terminal:

```bash
gdb-multiarch -q ./WhatIsMyPassword
```

Sau đó nhập từng lệnh trong GDB:

```text
(gdb) set disassembly-flavor intel
(gdb) info functions main
(gdb) disassemble main
```

`-q` làm phần chào đầu ngắn hơn. `set disassembly-flavor intel` chọn cú pháp assembly giống các ví dụ. `disassemble main` hiện lệnh máy của hàm `main`.

`main` là nơi bắt đầu logic chính của nhiều chương trình C/C++. File còn giữ tên hàm được gọi là có **symbol**. File đã xóa thông tin tên có thể được mô tả là **stripped**; IDA khi đó thường đặt tên `sub_...`.

Lệnh xem mã không yêu cầu chạy chương trình. Vì vậy `gdb-multiarch` vẫn đọc được ELF x86-64 trên máy ARM64.

### 3.3. Dừng chương trình và đọc dữ liệu

**Breakpoint** là điểm bạn yêu cầu debugger tạm dừng. Breakpoint dừng **trước khi thực hiện lệnh tại địa chỉ đó**.

| Lệnh GDB | Ý nghĩa |
|---|---|
| `break main` | Dừng khi vào main |
| `run` | Bắt đầu chạy, hoặc chạy lại từ đầu |
| `continue` | Chạy tiếp từ chỗ đang dừng |
| `nexti` | Chạy một lệnh máy; nếu là call, chờ hàm đó chạy xong |
| `stepi` | Chạy một lệnh máy; nếu là call, đi vào hàm đó |
| `finish` | Chạy đến khi hàm hiện tại trả về |
| `info registers` | Xem các thanh ghi |
| `x/s $rsi` | Đọc bộ nhớ mà RSI trỏ tới như chuỗi |
| `x/16bx $rsi` | Đọc 16 byte ở đó, viết theo hex |
| `p/d $eax` | In EAX theo số thập phân |
| `info breakpoints` | Liệt kê breakpoint |
| `delete 1` | Xóa breakpoint số 1 |
| `quit` | Thoát GDB |

Lệnh `x/16bx` được đọc là: examine memory, 16 phần tử, mỗi phần tử một byte (`b`), hiển thị hex (`x`). `x/s` đọc đến byte `00`, là dấu kết thúc chuỗi C. Nếu dữ liệu nhị phân có byte `00` ở giữa, dùng `x/...bx` để xem đủ dữ liệu.

Dấu `$` trước tên thanh ghi, như `$rax`, là cách GDB nói rằng bạn muốn dùng **giá trị hiện tại trong thanh ghi**.

### 3.4. Biết đối số của hàm đang ở đâu

Đối số là dữ liệu gửi vào hàm. Ví dụ `strcmp(input, password)` có hai đối số.

| Nền tảng trong bộ bài | Các đối số nguyên/con trỏ đầu tiên | Giá trị trả về |
|---|---|---|
| Linux x86-64 | RDI, RSI, RDX, RCX, R8, R9 | RAX, hoặc phần thấp như EAX |
| Windows x64 | RCX, RDX, R8, R9 | RAX, hoặc phần thấp |

Vì vậy, **ngay trước** `call strcmp` trên Linux, xem `RDI` và `RSI` để lấy hai chuỗi. Trên Windows, phải xem `RCX` và `RDX`.

Đừng áp dụng quy tắc này cho mọi vị trí trong hàm: các thanh ghi có thể được dùng lại. Ta quan sát chúng đúng ở thời điểm chương trình chuẩn bị gọi hàm.

### 3.5. Điều kiện để các lệnh “run” hoạt động

Những phiên GDB chạy ELF trong tài liệu cần Linux x86-64 và các thư viện tương thích với binary. Dùng `gdb` thông thường trên máy đó:

```bash
gdb -q ./WhatIsMyPassword
```

Nếu máy ARM64 báo thiếu `/lib64/ld-linux-x86-64.so.2`, đó là thiếu môi trường chạy x86-64. Chỉ cài `gdb-multiarch` chưa đủ để chạy.

Nếu đã có sysroot x86-64 chứa loader và thư viện, có thể dùng QEMU. Đây là lựa chọn bổ sung; người mới nên bắt đầu trên Linux x86-64 phù hợp.

Terminal thứ nhất:

```bash
qemu-x86_64 -L /path/to/x86_64-sysroot -g 1234 ./WhatIsMyPassword
```

`/path/to/x86_64-sysroot` là chỗ giữ bộ thư viện thật trên máy bạn; cần thay đường dẫn này.

Terminal thứ hai:

```bash
gdb-multiarch -q ./WhatIsMyPassword
```

Trong GDB:

```text
(gdb) target remote :1234
(gdb) break main
(gdb) continue
```

Ở cách nối QEMU này, dùng `continue` để tiếp tục chương trình đã được QEMU khởi tạo. Không dùng lại `run` như phiên GDB chạy trực tiếp. Khi chương trình yêu cầu nhập password, nhập ở terminal thứ nhất.

## 4. Bài đầu: WhatIsMyPassword

**Mục tiêu:** tìm mật khẩu mà chương trình so sánh với input, rồi lấy flag.

Đây là bài nên làm đầu tiên. Password nằm nguyên dạng chữ trong file, nên bạn có thể giải bằng IDA trước, sau đó dùng GDB để hiểu việc so sánh xảy ra như thế nào.

### Bước 1: Tìm lời nhắc và password bằng IDA

1. Mở `WhatIsMyPassword`, chờ phân tích.
2. Nhấn `Shift+F12` để mở Strings.
3. Tìm lời nhắc `Enter Password (8 characters):`.
4. Nhấp đôi lời nhắc.
5. Đặt con trỏ trên tên chuỗi và nhấn `X`.
6. Mở tham chiếu từ mã chương trình để đến hàm `main`.

Trong cùng danh sách Strings, bạn còn có thể thấy:

```text
P4sSw0rD
Access Granted
Access Denied
Flag{The_password_is_P4sSw0rD}
```

Đã nhìn thấy chuỗi không có nghĩa mọi chuỗi đều là đáp án thật. Ta xem xref của `P4sSw0rD` để xác nhận nó được đưa vào phép so sánh.

### Bước 2: Hiểu đoạn kiểm tra

Các vị trí liên quan trong đúng file này:

| Vị trí | Vai trò |
|---|---|
| `main` tại `0x1169` | Hàm chính |
| `0x202c` | Chuỗi password `P4sSw0rD` |
| `0x11b1`, tức `main+72` | Lệnh gọi strcmp |
| `0x2048` | Chuỗi flag |

Đoạn quyết định đúng/sai là:

```asm
call strcmp
test eax, eax
jne  nhánh_sai
```

Có thể viết lại logic bằng lời:

```text
Đọc input bằng scanf với định dạng "%8s".
So sánh input với "P4sSw0rD".
Nếu giống nhau: in "Access Granted", sau đó in flag.
Nếu khác nhau: in "Access Denied".
```

`%8s` giới hạn lần đọc này ở tối đa 8 ký tự không phải khoảng trắng. Không có bước `strlen(input) == 8` riêng trong hàm `main`; password so sánh có 8 ký tự. Đây là lý do nên đọc phép kiểm tra thật, thay vì chỉ dựa vào lời nhắc.

### Bước 3: Quan sát password trong GDB

Trên Linux x86-64 phù hợp, mở GDB:

```bash
gdb -q ./WhatIsMyPassword
```

Nhập:

```text
(gdb) set disassembly-flavor intel
(gdb) disassemble main
(gdb) break *(main+72)
(gdb) run
```

`main+72` nghĩa là địa chỉ đầu `main` cộng 72 **byte**; không phải dòng 72. Dấu `*` yêu cầu đặt breakpoint tại địa chỉ lệnh.

Khi chương trình hỏi password, thử nhập `aaaaaaaa`:

```text
Enter Password (8 characters): aaaaaaaa
```

Chương trình dừng ngay trước `strcmp`. Gõ:

```text
(gdb) x/s $rdi
(gdb) x/s $rsi
```

Bạn sẽ thấy nội dung tương ứng:

```text
RDI trỏ đến: "aaaaaaaa"
RSI trỏ đến: "P4sSw0rD"
```

Địa chỉ cụ thể ở đầu dòng có thể khác trên máy bạn. Phần cần đọc là chuỗi nằm trong dấu ngoặc kép.

Chạy qua phép so sánh:

```text
(gdb) nexti
(gdb) p/d $eax
```

Kết quả khác 0 vì hai chuỗi khác nhau. Không cần dự đoán chính xác số âm hay dương; bài chỉ kiểm tra nó có bằng 0 không.

Chạy hết lần thử:

```text
(gdb) continue
```

Chạy lại:

```text
(gdb) run
```

Lần này nhập:

```text
Enter Password (8 characters): P4sSw0rD
```

Breakpoint vẫn còn. Nhập:

```text
(gdb) nexti
(gdb) p/d $eax
(gdb) continue
```

Lần này `EAX` bằng 0, chương trình đi vào nhánh đúng và in:

```text
Flag{The_password_is_P4sSw0rD}
```

Điều học được từ bài này: tìm string → xem xref → tìm phép so sánh → xem hai đối số trước phép so sánh. Đây là quy trình dùng lại ở nhiều bài khác.


## 5. IForgetMyPassAgain: password được che đi, flag được mã hóa

**Mục tiêu:** lấy password 21 ký tự, rồi dùng nó để giải flag.

Khác bài trước, bạn không nhìn thấy password nguyên dạng chữ trong Strings. Chương trình chứa các byte đã biến đổi, rồi khôi phục password lúc chạy.

Luồng xử lý của bài:

```text
Đọc input
    ↓
Kiểm tra input dài 21 byte
    ↓
decryptPass() tạo password đúng
    ↓
strcmp(input, password đúng)
    ↓ nếu bằng nhau
getSecret(input) giải flag
    ↓
In flag
```

`decryptPass` và `getSecret` là tên hàm còn có trong file này. Có thể tìm trực tiếp trong Functions của IDA hoặc dùng `disassemble decryptPass` trong GDB.

### Bước 1: Tìm hàm kiểm tra trong IDA

1. Mở file `IForgetMyPassAgain`.
2. Trong Functions, nhấp đôi `main`.
3. Nếu chưa tìm được, dùng Strings → tìm `Enter the password to release the secret:` → `X` → mở xref.
4. Tìm lời gọi `strlen`.
5. Ngay sau đó có phép so sánh với `0x15`.

`strlen` đếm số byte trước dấu kết thúc chuỗi. Với password ASCII của bài này, số byte cũng là số ký tự. `0x15 = 21`, nên phải nhập đúng 21 ký tự để chương trình đi đến `decryptPass`.

Đoạn đã đọc từ file:

```asm
call strlen
cmp  rax, 0x15
je   nhánh_đủ_21_byte
```

Nhánh không đủ độ dài in lỗi và kết thúc. Nhánh đủ độ dài gọi `decryptPass`, sau đó `strcmp`. Chỉ khi `strcmp` trả 0 mới gọi `getSecret`.

### Bước 2: Cách dễ quan sát nhất bằng GDB

Nếu chạy được ELF trên máy của bạn, có thể để chương trình tự giải password rồi đọc kết quả. Bạn chưa cần hiểu công thức giải mã để làm bước này.

Mở GDB:

```bash
gdb -q ./IForgetMyPassAgain
```

Nhập:

```text
(gdb) set disassembly-flavor intel
(gdb) break decryptPass
(gdb) run
```

Ở lời nhắc, nhập đúng 21 chữ A dưới đây:

```text
Enter the password to release the secret: AAAAAAAAAAAAAAAAAAAAA
```

Input này chỉ nhằm vượt qua kiểm tra độ dài. Nó chưa phải password đúng.

GDB dừng ở `decryptPass`. Nhập:

```text
(gdb) finish
(gdb) x/s $rax
```

Vì sao hai lệnh này cho thấy password?

1. `finish` để hàm `decryptPass` chạy xong và trả về.
2. Trong file này, hàm trả về **địa chỉ** của chuỗi password.
3. Địa chỉ trả về nằm trong `RAX`.
4. `x/s $rax` đọc chuỗi ở địa chỉ đó.

Kết quả cần thấy:

```text
"T4t_c4_cH1_la_C0n9_cU"
```

Cho lần chạy thử kết thúc:

```text
(gdb) continue
```

Chương trình báo sai vì input vẫn là 21 chữ A. Ta đã lấy được password để dùng ở lần chạy sau.

### Bước 3: Dừng sau hàm giải flag

Trong cùng phiên GDB, xóa breakpoint đầu tiên và đặt breakpoint ở `getSecret`:

```text
(gdb) delete 1
(gdb) break getSecret
(gdb) run
```

`delete 1` áp dụng cho phiên trên, trong đó `decryptPass` là breakpoint số 1. Nếu đã tự đặt thêm breakpoint, xem `info breakpoints` rồi xóa đúng số.

Nhập password vừa tìm được:

```text
Enter the password to release the secret: T4t_c4_cH1_la_C0n9_cU
```

Lần này chương trình vượt qua phép so sánh và dừng ở `getSecret`. Nhập:

```text
(gdb) finish
(gdb) x/s $rax
```

Ở file này, `getSecret` cũng trả về con trỏ tới chuỗi kết quả. Bạn sẽ thấy flag dài được ghi ở cuối mục này.

`continue` cho chương trình tiếp tục đến phần in kết quả.

### Bước 4: Hiểu password được tạo ra như thế nào

Phần này là cách giải tĩnh, dùng được khi không chạy được file. Mở `decryptPass` trong IDA; dùng `F5` nếu có decompiler.

Hàm dựng một mảng 21 byte bằng nhiều lần ghi hằng số. Một lần ghi sau đè lên một phần dữ liệu đã ghi trước. **Ta cần mảng sau khi tất cả các lần ghi hoàn tất.**

Mảng cuối cùng là:

```text
0a e8 d1 69 26 fd e7 3a 00 4a f2 ef 1c 6d a9 b9 2f 23 1d 9d 02
```

`00` ở giữa là byte dữ liệu của mảng mã hóa. Không dùng nó làm điểm dừng khi chép đủ 21 byte.

Sau khi rút gọn những phép tính không ảnh hưởng kết quả, mỗi byte password được tính như sau:

```text
x = enc[i] XOR ((37*i + 19) & 0xff)
password[i] = ((ROL8(x, 5) XOR 0x77) - 57*i) & 0xff
```

Đọc công thức theo thứ tự:

1. `i` là vị trí byte, bắt đầu từ 0.
2. Lấy byte mã hóa tại vị trí đó.
3. XOR với số thay đổi theo vị trí: `37*i + 19`, giữ trong một byte.
4. Xoay trái giá trị 8 bit đi 5 vị trí.
5. XOR tiếp với `0x77`.
6. Trừ `57*i`, rồi giữ kết quả trong một byte.

**Xoay trái** khác dịch trái: các bit đi ra bên trái được vòng lại bên phải. Hàm `rol8` trong script thực hiện đúng thao tác đó.

Thử riêng byte đầu tiên để thấy công thức không phải một “hộp đen”:

```text
i = 0, enc[0] = 0x0a
37*0 + 19 = 19 = 0x13
0x0a XOR 0x13 = 0x19
ROL8(0x19, 5) = 0x23
0x23 XOR 0x77 = 0x54
0x54 - 57*0 = 0x54
0x54 là ký tự 'T'
```

Đó là chữ đầu của password.

Lưu đoạn sau thành `solve_iforget_password.py`:

```python
# Tạo mảng 21 byte ban đầu bằng 0.
enc = bytearray(21)

# Mô phỏng đúng thứ tự ghi của chương trình.
enc[0:8] = bytes.fromhex("0ae8d16926fde73a")
enc[8:16] = bytes.fromhex("004af2ef1c6da9b9")
enc[13:21] = bytes.fromhex("6da9b92f231d9d02")
# Lần ghi cuối đè lên các vị trí 13, 14, 15.

def rol8(value, count):
    left = value << count
    wrapped = value >> (8 - count)
    return (left | wrapped) & 0xff

password = bytearray()

for i in range(21):
    changing_key = (37 * i + 19) & 0xff
    x = enc[i] ^ changing_key
    x = rol8(x, 5)
    x = x ^ 0x77
    x = (x - 57 * i) & 0xff
    password.append(x)

print(password.decode("ascii"))
```

Chạy:

```bash
python3 solve_iforget_password.py
```

Kết quả:

```text
T4t_c4_cH1_la_C0n9_cU
```

`bytes.fromhex` chuyển chữ biểu diễn hex thành byte thật. `bytearray` là mảng byte có thể sửa từng phần tử. `decode("ascii")` chuyển các byte ký tự thành chữ để in.

### Bước 5: Giải flag bằng password

Trong IDA, mở `getSecret`. Hàm đọc 487 byte mã hóa và XOR với password được dùng lặp lại:

```text
secret[i] = ciphertext[i] XOR password[i % 21]
```

Độ dài flag lớn hơn password, nên sau byte password thứ 21, chương trình quay về byte password đầu tiên.

Trong ELF này:

- Dữ liệu mã hóa nằm ở địa chỉ ảo `0x4060`.
- Trong file trên đĩa, dữ liệu bắt đầu ở offset `0x3060`.
- Độ dài cần đọc là 487 byte.

**Địa chỉ ảo và file offset không phải cùng một thứ.** Địa chỉ ảo mô tả vị trí sau khi các vùng của file được ánh xạ vào bộ nhớ; file offset là số byte tính từ đầu file trên đĩa. Script đọc file phải dùng `0x3060`.

Lưu thành `solve_iforget_secret.py`:

```python
from pathlib import Path

password = b"T4t_c4_cH1_la_C0n9_cU"

# Đọc file trên đĩa; cần chạy từ thư mục chall.
binary = Path("IForgetMyPassAgain").read_bytes()

start = 0x3060
length = 487
ciphertext = binary[start:start + length]

secret = bytearray()

for i in range(len(ciphertext)):
    key_byte = password[i % len(password)]
    secret.append(ciphertext[i] ^ key_byte)

print(secret.decode("utf-8"))
```

Chạy:

```bash
python3 solve_iforget_secret.py
```

Chữ `b` trong `b"..."` tạo chuỗi byte. Ở đây dùng `utf-8` khi đọc kết quả vì flag có ký tự có dấu.

Flag đầy đủ:

```text
Flag{Cu01_cung_m01_c0_m07_b0_4n1m3_m4_nh4n_v4t_ch1nh_dung_chu4n_h1nh_m4u_ly_tu0ng_cu4_t40._M0t_k3_l4nh_lung_v4_1t_n01._D4m_b4n_kh0ng_h13u_t41_540_t40_tr0_n3n_1m_l4ng_v4_lu0n_du0c_5_d13m_b41_k13m_tr4._Chung_n0_kh0ng_b13t_n4ng_luc_thuc_5u_cu4_t40_v4_kh0ng_h3_b13t_t40_xu4t_chung_t01_muc_n40._T40_ch4ng_c01_chung_l4_g1_ng04i_c0ng_cu._T40_u0c_m1nh_c0_th3_v40_tr0ng_th3_giới_4n1m3_v4_b0c_l0_c0n_ngu01_thuc_5u_cu4_m1nh._T40_t1n_ch4c_r4ng_t40_ch1nh_l4_h04_th4n_ng04i_d01_thuc_cu4_Ay4n0k0uj1.}
```

Giữ nguyên chữ `giới` có dấu trong flag. Nó thuộc dữ liệu đã giải mã.

## 6. win/giothieuanti.exe: cùng thuật toán, trên Windows

**Mục tiêu:** nhận ra phiên bản Windows của bài vừa giải.

File này chứa cùng dữ liệu password và secret với `IForgetMyPassAgain`. Password và flag là những chuỗi ở mục 5.

### Bước 1: Đi đến logic chính trong IDA

1. Mở `win/giothieuanti.exe`.
2. Mở Strings.
3. Tìm `Enter the password to release the secret:`.
4. Nhấn `X` trên chuỗi, rồi mở tham chiếu từ code.
5. Tìm phép kiểm tra độ dài `0x15`.
6. Theo lời gọi hàm tạo password.
7. Quay lại nơi so sánh input với password.
8. Theo nhánh thành công đến hàm giải secret.

Không cần thấy tên `decryptPass` trong PE để nhận ra vai trò của hàm. Hãy xác định bằng **dữ liệu đi vào, dữ liệu đi ra và nơi gọi nó**.

### Bước 2: Nhận ra phần giống bài Linux

Trong hàm tạo password, tìm mảng mã hóa 21 byte đã nêu ở mục 5 và các phép XOR, xoay bit, trừ. Trong hàm giải secret, tìm vòng lặp XOR dữ liệu với password lặp lại.

Secret trong PE nằm ở vùng `.data`, tại địa chỉ ảo `0x14001f000`, dài 487 byte. `.data` là một vùng dữ liệu trong executable. Địa chỉ này thuộc PE; không dùng offset `0x3060` của ELF để đọc PE.

### Bước 3: Hiểu phần anti-debug và mã phụ

File import `IsDebuggerPresent`, một hàm Windows kiểm tra chương trình có đang được debugger theo dõi hay không. Mã được tạo bởi trình biên dịch MSVC còn có nhiều phần hỗ trợ chạy chương trình.

Nếu thấy nhiều hàm khó hiểu, quay lại chuỗi prompt và nhánh kiểm tra password. Chỉ theo những hàm thực sự tạo password và secret.

Các đối số đầu trên Windows x64 nằm ở `RCX/RDX/R8/R9`. Những ví dụ đọc `RDI/RSI` của mục 4 áp dụng cho Linux, không áp dụng cho PE này.

Trong môi trường hiện tại, phần PE được phân tích tĩnh. Để lấy flag, dùng dữ liệu và công thức giống mục 5; không cần chạy PE trong GDB.

## 7. InfiniteXOR: tìm được thuật toán, nhưng thiếu dữ liệu flag

**Mục tiêu:** hiểu chương trình XOR input như thế nào và xác định có đủ dữ liệu để tìm flag hay chưa.

File này chỉ nhận dữ liệu bạn nhập, XOR rồi in lại. Trong binary hiện có, không tìm thấy flag nhúng, ciphertext đích hoặc phép so sánh đáp án.

### Bước 1: Tìm khóa trong IDA

Mở `main`. Gần đầu hàm có hai phép ghi:

```asm
mov DWORD PTR [rbp-0xa], 0x346d3044
mov WORD PTR [rbp-0x6], 0x6e31
```

`DWORD` là 4 byte; `WORD` là 2 byte. Đây là hai lần ghi vào vùng liền nhau.

Đọc little-endian:

```text
0x346d3044 -> 44 30 6d 34 -> D0m4
0x6e31     -> 31 6e       -> 1n

Ghép lại: D0m41n
```

Khóa có **6 byte**, chính xác là `D0m41n`.

### Bước 2: Nhận ra vòng lặp

Trong `main`:

- `scanf` đọc input vào vùng bắt đầu tại `rbp-0x70`.
- Chỉ số vòng lặp bắt đầu bằng 0.
- Vòng lặp tiếp tục khi chỉ số không vượt `0x63`.
- `0x63 = 99`, nên có 100 lần xử lý: từ 0 đến 99.

Chương trình được biên dịch thành một đoạn nhân/shift để tính phần dư. Bạn có thể thấy hằng số `0xaaaaaaaaaaaaaaab` thay cho lệnh chia dễ nhận diện.

Cách hiểu đoạn này: nó tính thương của `i / 6`, nhân thương với 6, rồi trừ khỏi `i`. Vì `số dư = i - 6 * thương`, kết quả chính là `i % 6`.

Logic đã rút gọn:

```text
Với mỗi i từ 0 đến 99:
    input[i] = input[i] XOR key[i % 6]
```

### Bước 3: Xem dữ liệu trước và sau bằng GDB

Tạo input 100 chữ A ở terminal:

```bash
python3 -c 'print("A" * 100)' > /tmp/xor_input.txt
gdb -q ./InfiniteXOR
```

Nhập trong GDB:

```text
(gdb) set disassembly-flavor intel
(gdb) disassemble main
(gdb) break *(main+98)
(gdb) break *(main+191)
(gdb) run < /tmp/xor_input.txt
```

Dấu `<` gửi nội dung file vào input của chương trình. Hai breakpoint trong đúng binary này:

| Breakpoint | Thời điểm |
|---|---|
| `main+98`, tại `0x11bb` | scanf vừa xong, chưa XOR |
| `main+191`, tại `0x1218` | Vòng lặp XOR đã xong, chưa in |

Ở breakpoint đầu, xem khóa:

```text
(gdb) x/6cb $rbp-0xa
```

`c` là cách hiển thị dưới dạng ký tự; `b` là kích thước một byte. Bạn sẽ thấy các ký tự `D 0 m 4 1 n`.

Xem input trước biến đổi:

```text
(gdb) x/12bx $rbp-0x70
```

Các byte đầu đều là `0x41`, mã ASCII của chữ A.

Chạy đến breakpoint thứ hai:

```text
(gdb) continue
(gdb) x/12bx $rbp-0x70
```

Sáu byte đầu sau biến đổi:

```text
05 71 2c 75 70 2f
```

Chúng được tính từ:

```text
0x41 XOR 0x44 = 0x05
0x41 XOR 0x30 = 0x71
0x41 XOR 0x6d = 0x2c
0x41 XOR 0x34 = 0x75
0x41 XOR 0x31 = 0x70
0x41 XOR 0x6e = 0x2f
```

Sau đó sáu giá trị này lặp lại vì input đều là A và khóa lặp mỗi 6 byte.

Dùng `x/100bx $rbp-0x70` để xem toàn bộ 100 byte. Kết quả XOR có thể chứa ký tự không in được, nên xem dạng byte dễ hiểu hơn nhìn output chữ.

### Bước 4: Vì sao chưa có flag?

Muốn giải XOR để lấy một flag cụ thể, cần có:

1. Khóa và quy tắc dùng khóa.
2. Các byte ciphertext của flag.

Ta có mục 1, nhưng file này không cung cấp mục 2. Mỗi input khác nhau đều tạo một output khác nhau; không có dữ liệu nào chỉ ra output nào thuộc flag.

Nếu đề bổ sung file ciphertext, có thể dùng script dạng sau. Ví dụ đặt tên file dữ liệu là `ciphertext.bin`:

```python
from pathlib import Path

ciphertext = Path("ciphertext.bin").read_bytes()
key = b"D0m41n"

plaintext = bytearray()
for i in range(len(ciphertext)):
    plaintext.append(ciphertext[i] ^ key[i % len(key)])

print(bytes(plaintext))
```

`ciphertext.bin` **chưa có trong thư mục hiện tại**. Đây là mẫu giải cho dữ liệu cần được bổ sung, không phải script tạo được flag từ binary đang có.

Lưu ý khi quan sát: chương trình luôn xử lý 100 byte, dù input ngắn hơn. Khi dùng input ngắn, các byte sau dấu kết thúc có thể chưa được khởi tạo. Bước GDB phía trên dùng 100 chữ A để quan sát vùng dữ liệu xác định.


## 8. trytodebugme: chương trình phát hiện debugger

**Mục tiêu:** lấy mảng byte mã hóa và khóa XOR, rồi giải trực tiếp.

**Anti-debug** là các phép kiểm tra nhằm phát hiện debugger. Nếu bị phát hiện, chương trình có thể dừng hoặc đi sang nhánh khác.

Bài này có anti-debug, nhưng flag vẫn được tạo từ một mảng byte có sẵn trong file. Ta có thể đọc và giải mảng đó mà không cần chạy chương trình.

### Bước 1: Tìm nơi kiểm tra debugger trong IDA

File đã stripped, nên bạn có thể không thấy tên `main` trong Functions.

1. Mở Strings bằng `Shift+F12`.
2. Tìm `/proc/self/status` hoặc `TracerPid:`.
3. Nhấp đôi chuỗi, nhấn `X`, mở tham chiếu từ code.
4. Đọc hàm sử dụng chuỗi đó.

Trên Linux, `/proc/self/status` chứa thông tin về chính tiến trình. Dòng `TracerPid` cho biết PID của tiến trình đang theo dõi nó; giá trị 0 nghĩa là không có tracer tại thời điểm đó.

Bạn cũng sẽ thấy các tên:

```text
gdb-multiarch
lldb
radare2
ida64
ghidra
cheatengine
```

Hàm khác tìm tên công cụ trong danh sách tiến trình. Đó là thêm một cách phát hiện môi trường phân tích.

### Bước 2: Tìm phần tạo output

Trong đúng binary này, các địa chỉ tĩnh hữu ích là:

| Địa chỉ | Vai trò |
|---|---|
| `0x31e0` | Entry point của ELF |
| `0x3858` | Hàm xử lý chính được xác định từ luồng gọi |
| `0x3787` | Hàm kiểm tra anti-debug |
| `0x37b9` | Hàm giải/in thông điệp |

Trong IDA, dùng `G` rồi nhập địa chỉ để đi đến vùng tương ứng. Nếu file đang được hiển thị với base khác, xem lại địa chỉ theo base của database.

Ở hàm giải output, tìm vòng lặp XOR từng byte với `0xf9`. Mảng cần giải gồm 22 byte:

```text
ba ad bf 82 bb 80 89 cd cc cc a6 cd 97 8d c8 a6 bd ca 9b ac 9e 84
```

Ta đã có đủ hai phần: dữ liệu mã hóa và khóa.

### Bước 3: Giải bằng Python

Lưu thành `solve_trytodebugme.py`:

```python
encrypted = bytes.fromhex(
    "ba ad bf 82 bb 80 89 cd cc cc a6 cd "
    "97 8d c8 a6 bd ca 9b ac 9e 84"
)

key = 0xf9
decoded = bytearray()

for byte in encrypted:
    decoded.append(byte ^ key)

print(decoded.decode("ascii"))
```

Chạy:

```bash
python3 solve_trytodebugme.py
```

Kết quả:

```text
CTF{Byp455_4nt1_D3bUg}
```

Bạn có thể kiểm tra vài byte đầu bằng tay:

```text
0xba XOR 0xf9 = 0x43 -> C
0xad XOR 0xf9 = 0x54 -> T
0xbf XOR 0xf9 = 0x46 -> F
0x82 XOR 0xf9 = 0x7b -> {
```

Bốn ký tự `CTF{` giúp kiểm tra rằng ta đã chép đúng byte và dùng đúng khóa.

### GDB giúp gì trong bài này?

GDB có thể đọc disassembly tĩnh mà không tạo một tiến trình challenge đang chạy:

```bash
gdb-multiarch -q ./trytodebugme
```

Trong GDB:

```text
(gdb) set disassembly-flavor intel
(gdb) x/30i 0x37b9
```

`x/30i` xem 30 lệnh máy, bắt đầu ở địa chỉ chỉ định. Nó giúp đối chiếu đoạn giải mã với IDA.

Nếu chạy challenge dưới GDB trên máy tương thích, chính debugger có thể làm `TracerPid` khác 0. Khi đó, chương trình phát hiện debugger là hành vi dự kiến của bài.

Ta đã giải được flag từ dữ liệu tĩnh, nên không cần sửa nhánh anti-debug để lấy đáp án này.

## 9. win/bypassantidebug.exe: đọc đúng cả khi output có dấu hiệu lỗi

**Mục tiêu:** xác định khóa và chuỗi mà bản PE hiện tại tạo ra.

Bài này có ý tưởng giống bài Linux ở mục 8, nhưng dữ liệu nhúng trong hai file khác nhau. Vì thế phải tính theo byte thật của từng file.

### Bước 1: Tìm nơi in kết quả

1. Mở `win/bypassantidebug.exe` trong IDA.
2. Mở Strings, tìm `Your flag is Flag:`.
3. Dùng `X` để đến nơi in chuỗi.
4. Tìm các lần gọi hàm kiểm tra trước đoạn in.
5. Theo các phép XOR gộp giá trị trả về thành một byte khóa.

Hàm chính được xác định tại `0x1400014b0`. Hàm kiểm tra tại `0x140001330`.

### Bước 2: Hiểu các kiểm tra anti-debug

Trong Imports hoặc code, bạn sẽ gặp:

| Kiểm tra | Ý nghĩa |
|---|---|
| `IsDebuggerPresent` | Hỏi Windows chương trình có đang bị debug không |
| `CheckRemoteDebuggerPresent` | Một API khác để kiểm tra debugger |
| `PEB.BeingDebugged` | Đọc trực tiếp cờ trạng thái trong thông tin tiến trình |
| `NtGlobalFlag`, các bit `0x70` | Kiểm tra một số cờ có thể liên quan môi trường debug |
| `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW` | Liệt kê tiến trình để tìm tên debugger |

**PEB** là vùng thông tin về tiến trình Windows. Bạn không cần học toàn bộ cấu trúc PEB để giải bài này; chỉ cần nhận ra những đoạn đó quyết định nhánh “phát hiện debugger”.

Nếu phát hiện, chương trình có thể đi đến nhánh lỗi hoặc `int3`. `int3` là lệnh tạo ngắt thường dùng cho breakpoint.

### Bước 3: Tính khóa của đường chạy không phát hiện debugger

Ở nhánh không phát hiện debugger, ba lần gọi với các đối số 0, 1 và 2 trả về:

```text
0x5a
0x3c
0x9f
```

Hàm chính XOR chúng:

```text
0x5a XOR 0x3c XOR 0x9f = 0xf9
```

Lệnh `xor dil, al` trong đoạn gộp kết quả là XOR hai phần thanh ghi 8 bit. Nó góp phần tạo khóa cuối cùng.

Đây là kết quả đọc từ nhánh code tương ứng, không phải một phiên chạy PE đã được quan sát trong môi trường hiện tại.

### Bước 4: Giải mảng của chính PE

Dữ liệu được ghi lên stack bằng các hằng số. Đọc đúng little-endian và độ rộng từng lần ghi, ta lấy được:

```text
ba ab bf 82 bb 80 89 cd cd a6 cd d7 cd ce cb 8b ce cd bd 9e 84
```

Có một byte `00` kết thúc mảng sau các byte này. Vòng in dừng khi gặp byte kết thúc đó; không XOR thêm nó vào chuỗi.

Lưu thành `solve_windows_antidebug.py`:

```python
encrypted = bytes.fromhex(
    "ba ab bf 82 bb 80 89 cd cd a6 cd "
    "d7 cd ce cb 8b ce cd bd 9e 84"
)

key = 0x5a ^ 0x3c ^ 0x9f

print("Key:", hex(key))
print("Output:", bytes(byte ^ key for byte in encrypted).decode("ascii"))
```

Chạy:

```bash
python3 solve_windows_antidebug.py
```

Kết quả:

```text
Key: 0xf9
Output: CRF{Byp44_4.472r74Dg}
```

### Bước 5: Đọc kết quả mà không tự sửa đáp án

Chuỗi tính theo dữ liệu PE là:

```text
CRF{Byp44_4.472r74Dg}
```

Nó có dấu hiệu dữ liệu lỗi vì không theo mẫu `CTF{...}` của các bài liên quan. Chẳng hạn, byte thứ hai là `0xab`:

```text
0xab XOR 0xf9 = 0x52 -> R
```

Nếu muốn tạo chữ T với cùng khóa, byte mã hóa phải là `0xad`. Nhưng bản PE này chứa `0xab`. Vì vậy không thể viết rằng PE hiện tại giải ra `CTF{...}`.

Bài Linux `trytodebugme` giải ra:

```text
CTF{Byp455_4nt1_D3bUg}
```

Đây là **flag dự kiến có thể được tác giả muốn dùng cho bài Windows**, suy ra từ bài Linux cùng chủ đề. Chưa có bản nguồn hoặc bản PE khác để xác nhận ý đồ đó.

Điều cần nhớ: nếu kết quả không đẹp, kiểm tra lại công thức và byte. Khi chúng đã khớp, báo đúng kết quả và phần chưa chắc chắn; không thay ký tự chỉ để giống mẫu flag.

## 10. win/Guessing.exe: số “ngẫu nhiên” và SHA-256

**Mục tiêu:** tái tạo 100 số mà chương trình sinh ra, ghép đúng định dạng rồi băm để tạo flag.

Có hai khái niệm mới:

- **Số giả ngẫu nhiên:** một dãy được sinh bằng công thức. Nếu biết trạng thái khởi đầu và công thức, có thể tạo lại cùng dãy.
- **Hàm băm SHA-256:** biến dữ liệu thành kết quả 32 byte. Cùng dữ liệu đầu vào tạo cùng kết quả. Ở bài này, ta tái tạo dữ liệu đầu vào rồi băm; không cần tìm cách đảo SHA-256.

### Bước 1: Tìm nhánh tạo flag trong IDA

1. Mở `win/Guessing.exe`.
2. Trong Strings, tìm `YOUR FLAG IS`.
3. Mở xref để đến vùng in kết quả.
4. Tìm vòng đoán số 100 lần và các lời gọi `rand`.
5. Xem cách chương trình tạo chuỗi đưa vào hàm hash.

Hàm chính được xác định tại `0x140001140`.

Trong Imports hoặc những lời gọi liên quan, có thể thấy các API Windows Crypto:

```text
CryptAcquireContext
CryptCreateHash
CryptHashData
CryptGetHashParam
```

`CryptHashData` nhận dữ liệu cần băm. `CryptGetHashParam` lấy kết quả băm. Mã thuật toán `0x800c` tương ứng SHA-256 trong phần xử lý này.

### Bước 2: Xác định dãy số

Chương trình gọi `rand()` nhưng không khởi tạo seed bằng `srand()` trong logic đã phân tích. Với MSVC CRT của bài này, trạng thái mặc định bắt đầu từ 1.

Seed là giá trị khởi đầu của bộ sinh số. Mỗi lần lấy số sẽ cập nhật trạng thái:

```text
state = (state * 214013 + 2531011) & 0xffffffff
r = (state >> 16) & 0x7fff
number = 1000 + r % 9000
```

Giải thích:

1. `& 0xffffffff` giữ giá trị ở phạm vi 32 bit.
2. `>> 16` dịch phải 16 bit.
3. `& 0x7fff` lấy phần giá trị mà hàm rand của CRT này trả về.
4. `r % 9000` cho số từ 0 đến 8999.
5. Cộng 1000 tạo số từ 1000 đến 9999.

Không thay bằng `random.randint` của Python. Đó là một bộ sinh khác, nên sẽ cho dãy khác.

### Bước 3: Xác định đúng chuỗi được băm

Chương trình tạo dạng:

```text
1041,1467,7334,9500,2169,...
```

Cụ thể, số đầu dùng định dạng `%d`; những số tiếp theo dùng `,%d`. Vì vậy:

- Có dấu phẩy giữa hai số.
- Không có dấu cách.
- Không có dấu phẩy ở cuối.
- Không thêm ký tự xuống dòng vào dữ liệu băm.

Chỉ thêm một dấu cách cũng làm SHA-256 khác. Định dạng chuỗi là một phần của lời giải.

### Bước 4: Tái tạo bằng Python

Lưu thành `solve_guessing.py`:

```python
import hashlib

state = 1
numbers = []

for _ in range(100):
    state = (state * 214013 + 2531011) & 0xffffffff
    r = (state >> 16) & 0x7fff
    number = 1000 + r % 9000
    numbers.append(number)

# join đặt dấu phẩy giữa các phần tử, không thêm ở cuối.
message = ",".join(str(number) for number in numbers)

# encode chuyển chuỗi thành byte trước khi băm.
digest = hashlib.sha256(message.encode("ascii")).hexdigest()

print("5 số đầu:", numbers[:5])
print("5 số cuối:", numbers[-5:])
print("Flag:", "CTF{" + digest + "}")
```

Chạy:

```bash
python3 solve_guessing.py
```

Kết quả:

```text
5 số đầu: [1041, 1467, 7334, 9500, 2169]
5 số cuối: [4538, 8118, 3082, 5929, 8541]
Flag: CTF{90e8f2c958a19840510acff379cf19c553c49420c137c2ffab936b2702b68e2b}
```

`hexdigest()` biểu diễn 32 byte hash thành 64 ký tự hex chữ thường. Đây là phần được đặt trong `CTF{...}`.

Phần PE được đọc tĩnh; script tái tạo quy tắc được xác định từ chương trình. Không cần chơi đủ 100 lượt để tìm chuỗi flag.


## 11. RevPY: chương trình Python đóng gói thành executable

**Mục tiêu:** lấy logic Python đã đóng gói, giải dữ liệu AES rồi đảo phép biến đổi trên flag.

Bài này có nhiều lớp hơn. Có thể hình dung:

```text
Executable Linux
    chứa chương trình Python
        chứa dữ liệu AES đã che bằng XOR
            chứa các byte dùng kiểm tra flag
```

### Bước 1: Hiểu vì sao chỉ mở IDA chưa đủ

PyInstaller gom chương trình Python và các thành phần cần thiết vào executable. Phần mã máy bạn nhìn thấy đầu tiên trong IDA chủ yếu làm việc khởi động Python và đọc gói dữ liệu.

**Bytecode Python** là các lệnh của máy ảo Python, khác với lệnh x86-64. File `.pyc` chứa dạng bytecode này.

Để tìm logic kiểm tra flag, ta lấy `.pyc` ra rồi đọc bằng công cụ hỗ trợ bytecode. IDA/GDB vẫn có thể đọc phần native, nhưng bước đó không trực tiếp cho thấy hàm Python `checkflag`.

### Bước 2: Lấy bytecode ra

Có thể dùng [PyInstaller Extractor](https://github.com/extremecoders-re/pyinstxtractor), công cụ hỗ trợ trích xuất executable PyInstaller, gồm cả ELF Linux.

Một cách lấy công cụ vào thư mục tạm:

```bash
git clone https://github.com/extremecoders-re/pyinstxtractor.git /tmp/ctf-pyinstxtractor
```

Nếu thư mục đó đã tồn tại từ lần làm trước, dùng bản đã có. Không cần clone lại.

Chạy từ thư mục `chall`:

```bash
python3 /tmp/ctf-pyinstxtractor/pyinstxtractor.py RevPY
```

Công cụ thường tạo thư mục `RevPY_extracted`. Xem các file đã lấy ra:

```bash
rg --files RevPY_extracted
```

Tìm module chính chứa hàm `checkflag`, thường tương ứng tên bài; bỏ qua module khởi động như `pyiboot01_bootstrap` khi tìm logic challenge.

Bytecode của file này là **Python 3.13**. Tác giả công cụ khuyến nghị chạy extractor bằng cùng phiên bản Python với executable để tránh lỗi đọc PYZ. Nếu máy đã có Python 3.13, dùng:

```bash
python3.13 /tmp/ctf-pyinstxtractor/pyinstxtractor.py RevPY
```

Nếu công cụ báo không đọc được PYZ do khác phiên bản, kiểm tra phiên bản này trước. Không có nghĩa file challenge bị hỏng.

### Bước 3: Đọc bytecode bằng xdis

[xdis](https://github.com/rocky/python-xdis) hỗ trợ đọc bytecode của nhiều phiên bản Python. Trong môi trường Python riêng đã tạo ở mục 1:

```bash
source .venv/bin/activate
python -m pip install xdis
```

Với đường dẫn module chính đã tìm ở bước trước, dùng:

```bash
python -m xdis RevPY_extracted/RevPY.pyc > /tmp/revpy_bytecode.txt
```

`RevPY_extracted/RevPY.pyc` là đường dẫn cần kiểm tra theo kết quả trích xuất; nếu module chính có tên khác, thay bằng đường dẫn thật.

Đọc file output bằng trình soạn thảo và tìm `checkflag`:

```bash
nano /tmp/revpy_bytecode.txt
```

Bytecode có các tên lệnh như `LOAD_CONST`, `LOAD_FAST`, `BINARY_OP`. Bạn có thể hiểu sơ bộ:

- `LOAD_CONST` lấy một giá trị cố định, như số hoặc mảng byte.
- `LOAD_FAST` lấy biến cục bộ, như chỉ số vòng lặp.
- `BINARY_OP` thực hiện phép toán, như cộng hoặc XOR.

`xdis` cho disassembly, không nhất thiết khôi phục thành mã nguồn Python. Khi đọc, tập trung vào hằng số, hàm AES và vòng kiểm tra từng ký tự.

### Bước 4: Hiểu các dữ liệu mã hóa

Đây là các hằng số đã xác định từ bytecode:

```text
mask = 0x36

KEY_DATA = (5,87,3,79,113,67,5,69,3,7,88,81,93,5,79,23)
IV_DATA  = (69,67,70,83,68,69,83,85,68,83,66,95,64,8,12,5)
```

Mỗi phần tử được XOR với `0x36` để tạo key và IV thật.

Ví dụ phần tử đầu của key là 5:

```text
5 XOR 54 = 51
51 là mã ASCII của '3'
```

Kết quả đầy đủ:

```text
AES key = 3a5yGu3s51ngk3y!
IV      = supersecretiv>:3
```

**AES** là thuật toán mã hóa. **Key** là khóa. **CBC** là chế độ xử lý các khối dữ liệu. **IV** là khối khởi đầu dùng trong chế độ đó; nó không phải password.

Ở bài này key và IV đều dài 16 byte. Dữ liệu AES sau khi bỏ lớp XOR che hằng số là:

```text
b4ed512ca51986be2a7f9b31ac775bb6f6149b5a919668388f6d516b1f37faec
```

**Ciphertext** là dữ liệu đã mã hóa. **Plaintext** là dữ liệu sau giải mã.

AES xử lý theo khối 16 byte. Khi dữ liệu chưa vừa khối, chương trình thêm **padding**, tức các byte đệm ở cuối. Script dùng `unpad` để bỏ đúng phần đệm sau giải mã.

### Bước 5: Giải AES rồi đảo bước kiểm tra

Kết quả AES sau bỏ padding **chưa phải flag cuối cùng**. Chương trình so sánh nó với từng ký tự input sau công thức:

```text
expected[i] = ((ord(flag[i]) XOR 0x36) + 3*i) & 0xff
```

`ord` lấy mã số của ký tự. Với ký tự ASCII, mã đó cũng là byte tương ứng.

Muốn lấy flag từ `expected`:

1. Trừ `3*i`.
2. Giữ kết quả trong một byte.
3. XOR với `0x36`.

Phải đảo theo thứ tự ngược. Trong công thức gốc, XOR trước rồi cộng; khi giải, trừ trước rồi XOR.

Lưu thành `solve_revpy.py`:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

mask = 0x36
key_data = (5,87,3,79,113,67,5,69,3,7,88,81,93,5,79,23)
iv_data = (69,67,70,83,68,69,83,85,68,83,66,95,64,8,12,5)

key = bytes(value ^ mask for value in key_data)
iv = bytes(value ^ mask for value in iv_data)

# Ciphertext sau khi bỏ lớp XOR che dữ liệu.
ciphertext = bytes.fromhex(
    "b4ed512ca51986be2a7f9b31ac775bb6"
    "f6149b5a919668388f6d516b1f37faec"
)

aes = AES.new(key, AES.MODE_CBC, iv)
with_padding = aes.decrypt(ciphertext)
expected = unpad(with_padding, 16)

flag = bytearray()
for i in range(len(expected)):
    value = (expected[i] - 3 * i) & 0xff
    value = value ^ mask
    flag.append(value)

print("Key:", key.decode("ascii"))
print("IV:", iv.decode("ascii"))
print("Dữ liệu sau AES:", expected.hex())
print("Flag:", flag.decode("ascii"))
```

Chạy trong môi trường đã cài PyCryptodome:

```bash
source .venv/bin/activate
python solve_revpy.py
```

Kết quả:

```text
Key: 3a5yGu3s51ngk3y!
IV: supersecretiv>:3
Dữ liệu sau AES: 75657656527e13731e738726262a799694387684
Flag: CTF{pY7h0n_345y_R3v}
```

`expected.hex()` cho thấy byte trung gian. Nó giúp kiểm tra bước AES riêng, trước khi kiểm tra bước đảo công thức.

## 12. apk/basicapk.apk: key và IV nằm trong mã Android

**Mục tiêu:** đọc ciphertext, key, IV rồi giải AES.

### Bước 1: Mở APK bằng JADX

APK là một gói chứa ứng dụng Android. Các file `classes.dex`, `classes2.dex`, `classes3.dex` chứa bytecode. Logic bài này nằm trong `classes3.dex`.

[JADX](https://github.com/skylot/jadx) có giao diện đồ họa và hỗ trợ mở APK trực tiếp.

Nếu máy đã cài `jadx-gui`, chạy từ thư mục `chall`:

```bash
jadx-gui apk/basicapk.apk
```

Hoặc mở JADX GUI rồi chọn **File → Open** và chọn APK. Nếu chưa có công cụ, lấy bản phát hành theo hướng dẫn trong repository trên.

Trong danh sách lớp ở bên trái:

1. Tìm `MainActivity` bằng chức năng tìm kiếm.
2. Mở lớp đó.
3. Tìm phần gắn xử lý cho nút bấm, thường có `setOnClickListener`.
4. Theo hàm được gọi khi nhấn nút.
5. Tìm hàm `decrypt` và những đối số gửi vào nó.

**Activity** là thành phần điều khiển một màn hình Android. **Listener** là đoạn xử lý chạy khi có sự kiện, như người dùng nhấn nút.

Mở toàn bộ APK thường tiện hơn chỉ mở một DEX vì bạn có thể tìm trong tất cả các lớp.

### Bước 2: Chép ba dữ liệu cần thiết

Phần giải mã dùng:

```text
AES/CBC/PKCS5Padding
```

Dữ liệu đã xác định:

```text
Ciphertext Base64: E1QN7PnxJsb6s21SpV1e95tL9E8STO9WOF7M7DXWEA4=
Key:               s3cr3tk3y!!!!!!!
IV:                s3cretIv!!!!!!!!
```

Giữ chính xác số dấu `!`. Key và IV ở đây đều dài 16 byte.

**Base64** là cách biểu diễn byte bằng chữ để tiện lưu và truyền. Nó không phải thuật toán mã hóa; bước `b64decode` chỉ chuyển biểu diễn đó về các byte AES ciphertext.

Tên `PKCS5Padding` là tên padding được dùng trong API Java của bài. Với AES khối 16 byte này, script Python bỏ padding bằng `unpad(..., 16)`.

### Bước 3: Giải bằng Python

Lưu thành `solve_basicapk.py`:

```python
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

encoded_ciphertext = (
    "E1QN7PnxJsb6s21SpV1e95tL9E8STO9WOF7M7DXWEA4="
)

key = b"s3cr3tk3y!!!!!!!"
iv = b"s3cretIv!!!!!!!!"

ciphertext = b64decode(encoded_ciphertext)

aes = AES.new(key, AES.MODE_CBC, iv)
with_padding = aes.decrypt(ciphertext)
plaintext = unpad(with_padding, 16)

print(plaintext.decode("utf-8"))
```

Chạy:

```bash
source .venv/bin/activate
python solve_basicapk.py
```

Kết quả:

```text
CTF{SUp3r_Bas1c_R3v3rs3_Apk!!!}
```

Ta không cần chạy APK trên điện thoại để giải, vì dữ liệu và cách giải mã đều có sẵn trong mã.

Nếu dùng IDA để mở DEX thì cần phiên bản/cấu hình hỗ trợ. Với người mới, JADX làm phần Java dễ theo hơn; những lệnh GDB cho ELF ở mục 4 không áp dụng trực tiếp cho bytecode APK.

## 13. apk/PinChecker.apk: thử các PIN 6 chữ số

**Mục tiêu:** tìm PIN tạo được key AES đúng, rồi lấy flag.

Bài này không chứa trực tiếp key AES. Key được tạo từ PIN, nên ta cần thử các PIN có thể có.

### Bước 1: Theo đúng nút kiểm tra trong JADX

Mở:

```bash
jadx-gui apk/PinChecker.apk
```

1. Tìm `MainActivity`.
2. Tìm listener của nút kiểm tra PIN.
3. Theo chỗ lấy nội dung ô nhập.
4. Xem phép kiểm tra độ dài: 6 ký tự.
5. Theo lời gọi sang `CryptoHelper`.
6. Ghi lại cách tạo key, IV và ciphertext.

Logic cần tái tạo:

```text
key = 16 byte đầu của SHA256(pin + "CTF_SALT_2026")
IV = "1234567890123456"
ciphertext = Base64 decode dữ liệu nhúng
plaintext = AES-CBC decrypt(ciphertext, key, IV)
```

Các dữ liệu:

```text
Salt:              CTF_SALT_2026
IV:                1234567890123456
Ciphertext Base64: h86dPZchLKJiVIIGLJhAIoGNN9VAkVGj/pxtUZk4n3s=
```

**Salt** là chuỗi được thêm khi tạo key. Nó không phải PIN và không cần đoán, vì nằm trong mã. Dấu `+` ở đây nghĩa là nối các byte của PIN với các byte của salt, không phải cộng số.

Ví dụ PIN `000123` tạo dữ liệu băm:

```text
000123CTF_SALT_2026
```

### Bước 2: Hiểu tại sao có thể thử toàn bộ

Với PIN gồm 6 chữ số, có 1.000.000 trường hợp:

```text
000000
000001
000002
...
999999
```

**Brute force** nghĩa là lần lượt thử các trường hợp đó. Ở đây có thể thử ngay trong Python trên ciphertext đã lấy ra, không cần nhập từng PIN vào ứng dụng.

Chú ý: `000123` khác `123` vì số 0 ở đầu là một phần của chuỗi tạo key. Trong script, `f"{number:06d}"` đảm bảo luôn có đúng 6 chữ số.

UI kiểm tra độ dài 6; vòng thử dưới đây chọn tập PIN 6 chữ số và tìm được đáp án trong tập đó.

### Bước 3: Chọn tiêu chí nhận biết PIN đúng

Giải AES bằng key sai vẫn cho ra byte, nhưng thường là dữ liệu vô nghĩa.

Trong script, ta tìm kết quả đồng thời thỏa:

1. Bắt đầu bằng `CTF{`.
2. Có padding hợp lệ ở cuối.

Padding hợp lệ với khối 16 byte có dạng: nếu byte cuối là `p`, thì `p` phải từ 1 đến 16 và `p` byte cuối đều bằng `p`.

Ví dụ:

```text
... 03 03 03          -> 3 byte đệm, hợp lệ
... 04 04 04 04       -> 4 byte đệm, hợp lệ
... 01 02 03          -> byte cuối báo 3, nhưng 3 byte không giống nhau
```

Không chỉ kiểm tra một byte cuối rồi chấp nhận ngay.

### Bước 4: Viết vòng thử PIN

Lưu thành `solve_pinchecker.py`:

```python
from base64 import b64decode
from hashlib import sha256
from Crypto.Cipher import AES

ciphertext = b64decode(
    "h86dPZchLKJiVIIGLJhAIoGNN9VAkVGj/pxtUZk4n3s="
)
iv = b"1234567890123456"
salt = b"CTF_SALT_2026"

found = False

for number in range(1_000_000):
    # Giữ đúng 6 chữ số, bao gồm số 0 ở đầu.
    pin_text = f"{number:06d}"
    pin_bytes = pin_text.encode("ascii")

    # digest() cho 32 byte hash thật; lấy 16 byte đầu làm key.
    key = sha256(pin_bytes + salt).digest()[:16]

    aes = AES.new(key, AES.MODE_CBC, iv)
    plaintext = aes.decrypt(ciphertext)

    if not plaintext.startswith(b"CTF{"):
        continue

    pad_length = plaintext[-1]

    if not 1 <= pad_length <= 16:
        continue

    expected_padding = bytes([pad_length]) * pad_length
    if not plaintext.endswith(expected_padding):
        continue

    flag = plaintext[:-pad_length].decode("utf-8")

    print("PIN:", pin_text)
    print("Flag:", flag)

    found = True
    break

if not found:
    print("Chưa tìm được PIN; kiểm tra lại salt, IV và ciphertext.")
```

`continue` bỏ trường hợp hiện tại để thử số tiếp theo. `break` dừng vòng lặp khi tìm thấy kết quả. `[:16]` lấy 16 byte đầu; `[:-pad_length]` bỏ phần đệm ở cuối.

Phân biệt hai hàm hash:

- `digest()` trả byte thật, dùng để làm key trong bài này.
- `hexdigest()` trả chuỗi chữ hex, dùng khi in flag của `Guessing.exe`.

Nếu thay `digest()` bằng `hexdigest()` ở đây, key sẽ sai.

Chạy:

```bash
source .venv/bin/activate
python solve_pinchecker.py
```

Kết quả:

```text
PIN: 641888
Flag: CTF{fr1da_h00k_otp_e4sy!}
```

### Bước 5: Vì sao không dùng PinGenerator?

DEX còn có hàm `PinGenerator.generateCurrentPin`. Seed được phân tích trong hàm đó là `super_secret_seed_phrase`; logic đã đọc cho ra PIN `048553`.

Tuy nhiên, luồng nút kiểm tra trong `MainActivity` không gọi hàm này. PIN đó không mở được ciphertext của bài.

Đây là dữ liệu đánh lạc hướng. Cách tránh nhầm là bắt đầu từ **nút mà người dùng thực sự bấm**, rồi theo những hàm được gọi từ nút ấy. Tên hàm nghe có vẻ phù hợp chưa đủ để kết luận nó quyết định đáp án.

Tên flag nhắc đến Frida, nhưng dữ liệu nhúng cũng cho phép giải bằng vòng thử PIN trên. Lời giải này lấy flag bằng cách tái tạo thuật toán.


## 14. Khi làm theo nhưng kết quả khác: kiểm tra ở đâu?

### 14.1. IDA không có hàm main

Có hai khả năng thường gặp:

- File stripped nên tên hàm đã bị xóa.
- IDA chưa nhận diện được hàm chính.

Bắt đầu bằng Strings, tìm lời nhắc hoặc thông báo đúng/sai. Dùng `X` để đi đến code sử dụng chuỗi đó. Hàm chứa prompt và phép kiểm tra input thường là nơi cần đọc.

Trong file stripped, tên `sub_3858` chỉ là tên tự đặt theo địa chỉ, không phải một thuật toán đặc biệt.

### 14.2. F5 không ra mã giống C

Có thể phiên bản IDA không có decompiler phù hợp. Bạn vẫn có thể:

1. Tìm Strings.
2. Mở xref.
3. Xem assembly.
4. Tìm lời gọi `strcmp`, `strlen`, hàm AES hoặc các vòng XOR.

Tài liệu dùng những đoạn viết lại logic bằng lời để giải thích. Đó không phải cam kết rằng cửa sổ F5 trên mọi máy sẽ hiện đúng từng dòng như ví dụ.

### 14.3. GDB báo chương trình không chạy được

Nếu báo thiếu loader hoặc không thực thi được file x86-64 trên ARM64, đọc lại mục 3.5. Kiến trúc và thư viện chạy phải phù hợp.

Nếu trên Linux x86-64 báo không tìm được `__isoc23_scanf` hoặc phiên bản GLIBC yêu cầu, thư viện trên máy chưa tương thích với binary. Các file này có lời gọi scanf của bộ libc tương ứng. Dùng môi trường Linux x86-64 có libc phù hợp.

Trong lúc chưa có môi trường chạy, vẫn có thể dùng `disassemble` để đọc file và các script giải tĩnh để tái tạo dữ liệu.

### 14.4. Địa chỉ trong IDA khác địa chỉ trong GDB

Một số ELF trong bộ này là **PIE**. Chương trình có thể được nạp vào địa chỉ khác nhau giữa các lần chạy. **ASLR** là cơ chế làm thay đổi vị trí nạp đó.

Với file có symbol, ưu tiên:

```text
(gdb) break main
(gdb) break *(main+72)
```

GDB tính vị trí từ tên hàm. Bạn tránh phải chép một địa chỉ tuyệt đối của lần chạy trước.

Với ELF stripped có image base tĩnh bằng 0, có thể làm trên Linux x86-64:

```text
(gdb) starti
(gdb) info proc mappings
```

`starti` dừng ở lệnh đầu tiên của tiến trình; lệnh đó có thể thuộc loader, chưa phải main. `info proc mappings` liệt kê các vùng bộ nhớ được ánh xạ.

Tìm dòng:

1. Có đường dẫn của **chính file challenge**, không phải libc hay loader.
2. Có file offset bằng 0.

Địa chỉ đầu dòng đó là base, ký hiệu `B`. Với các ELF PIE được phân tích ở base 0 trong bộ này:

```text
địa chỉ lúc chạy = B + địa chỉ tĩnh trong IDA
```

Ví dụ minh họa, nếu mapping cho `B = 0x555555554000`, muốn dừng ở offset `0x3858`:

```text
(gdb) set $base = 0x555555554000
(gdb) break *($base + 0x3858)
(gdb) continue
```

**Thay giá trị base bằng số thật trên máy bạn.** Số `0x555555554000` chỉ minh họa phép tính. Với `trytodebugme`, chạy tiếp dưới debugger còn có thể gặp các kiểm tra anti-debug đã giải thích ở mục 8.

Không áp dụng máy móc phép cộng này cho mọi loại binary. Với PE được IDA hiển thị tại base `0x140000000`, cần tính phần chênh so với base của PE trước khi quy đổi sang địa chỉ lúc chạy.

### 14.5. x/s không hiện hết dữ liệu

`x/s` đọc như chuỗi C và dừng khi gặp byte `00`. Ciphertext có thể chứa `00` ngay giữa mảng.

Dùng:

```text
(gdb) x/21bx ADDRESS
```

Thay `ADDRESS` bằng địa chỉ hoặc biểu thức thật. Ví dụ `x/21bx $rax` nếu RAX đang trỏ tới vùng muốn đọc. Với dữ liệu nhị phân, biết độ dài rồi xem byte là cách chính xác hơn xem chuỗi.

### 14.6. Script báo FileNotFoundError

Script `solve_iforget_secret.py` đọc `IForgetMyPassAgain` bằng đường dẫn tương đối. Bạn cần chạy trong thư mục chứa file:

```bash
cd /home/kali/Desktop/hacker_lord/chall
python3 solve_iforget_secret.py
```

Nếu script nằm ở nơi khác, chuyển file script về thư mục `chall` hoặc sửa đường dẫn trong script thành đường dẫn đầy đủ.

### 14.7. AES báo key không đúng độ dài hoặc padding sai

Nếu key không đúng độ dài:

- Kiểm tra số dấu `!`.
- Kiểm tra khoảng trắng bị dán thêm.
- Kiểm tra đang dùng byte thật hay chuỗi chữ hex.

Nếu padding sai:

- Kiểm tra ciphertext, key và IV.
- Kiểm tra đã Base64 decode trước khi giải AES chưa.
- Kiểm tra chế độ là CBC.
- Với PinChecker, padding sai ở đa số PIN là bình thường; đó là các key thử chưa đúng.

Không xóa thủ công vài byte ở cuối chỉ để kết quả in được. Phải bỏ padding theo quy tắc.

### 14.8. Giải ra chữ lạ

Thử kiểm tra theo thứ tự:

1. Đã lấy đủ byte và đúng thứ tự chưa?
2. Hằng số nhiều byte đã đọc little-endian chưa?
3. Có lần ghi chồng làm đổi mảng ban đầu không?
4. Khóa có đúng độ dài và ký tự không?
5. Đã đảo các phép biến đổi theo thứ tự ngược chưa?
6. Dữ liệu trung gian có phải plaintext cuối cùng không?

Ví dụ `RevPY` sau AES vẫn cần đảo công thức từng ký tự. `bypassantidebug.exe` thì thực sự chứa byte tạo ra chuỗi khác mẫu, như đã phân biệt ở mục 9.

## 15. Bảng đáp án và mức độ xác nhận

Bảng này dùng để đối chiếu sau khi làm bài. Các mục đã giải có dữ liệu và script tương ứng ở phía trên.

| File | Password/PIN nếu có | Flag hoặc trạng thái |
|---|---|---|
| `WhatIsMyPassword` | `P4sSw0rD` | `Flag{The_password_is_P4sSw0rD}` |
| `IForgetMyPassAgain` | `T4t_c4_cH1_la_C0n9_cU` | Flag dài nguyên văn ở mục 5 |
| `win/giothieuanti.exe` | `T4t_c4_cH1_la_C0n9_cU` | Cùng flag dài ở mục 5 |
| `InfiniteXOR` | Khóa XOR: `D0m41n` | Đã biết thuật toán; thiếu ciphertext đích để tìm flag |
| `trytodebugme` | Khóa XOR: `0xf9` | `CTF{Byp455_4nt1_D3bUg}` |
| `win/bypassantidebug.exe` | Khóa nhánh sạch: `0xf9` | Chuỗi tính theo PE: `CRF{Byp44_4.472r74Dg}` |
| `win/Guessing.exe` | Dãy số từ state ban đầu 1 | `CTF{90e8f2c958a19840510acff379cf19c553c49420c137c2ffab936b2702b68e2b}` |
| `RevPY` | Key/IV tại mục 11 | `CTF{pY7h0n_345y_R3v}` |
| `apk/basicapk.apk` | Key/IV tại mục 12 | `CTF{SUp3r_Bas1c_R3v3rs3_Apk!!!}` |
| `apk/PinChecker.apk` | `641888` | `CTF{fr1da_h00k_otp_e4sy!}` |

Flag `CTF{Byp455_4nt1_D3bUg}` được giải trực tiếp từ Linux `trytodebugme`. Nếu dùng nó như flag dự kiến của `win/bypassantidebug.exe`, cần ghi rằng đó là suy luận từ bài Linux liên quan, chưa được xác nhận bởi dữ liệu PE hiện tại.

Với `InfiniteXOR`, cần đề gốc bổ sung ciphertext/output cần giải hoặc file phụ. Đã xác định được khóa không đồng nghĩa đã có đủ dữ liệu để tạo một flag.

## 16. Nếu đây là lần đầu học reverse, đọc theo thứ tự nào?

Bạn có thể chia thành các buổi ngắn:

1. **Mục 1–4:** học cách mở file, tìm Strings/xref và xem hai chuỗi trước `strcmp`. Tự thử một password sai rồi password đúng.
2. **Mục 5:** học cách đọc giá trị hàm trả về bằng `finish` và `x/s $rax`. Sau đó đọc script để hiểu giải password và flag.
3. **Mục 7–8:** học little-endian, XOR lặp và lấy mảng byte từ code.
4. **Mục 10:** học tái tạo thuật toán và giữ đúng định dạng dữ liệu băm.
5. **Mục 12–13:** học đọc luồng nút bấm trong JADX, giải AES và thử PIN.
6. **Mục 11:** học bài Python có nhiều lớp biến đổi.
7. **Mục 6 và 9:** đọc thêm phiên bản Windows, sự khác nhau về đối số hàm và cách báo kết quả khi dữ liệu có dấu hiệu lỗi.

Sau mỗi bài, thử tự trả lời bốn câu:

- Input được đọc ở đâu?
- Chương trình kiểm tra điều kiện nào?
- Dữ liệu nào nằm sẵn trong file?
- Script của mình đang tái tạo bước nào trong chương trình?

Khi giải thích được bốn điểm đó, bạn đã hiểu lời giải của bài thay vì chỉ sao chép đáp án.

