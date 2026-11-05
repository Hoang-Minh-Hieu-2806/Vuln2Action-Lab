# Giải thích bài báo Vuln2Action cho người không biết cybersecurity

Tài liệu này giải thích bài báo gốc:

> S. Kumari và G. Yadav, **“Vuln2Action: An LLM-based framework for generating
> vulnerability reproduction steps and mapping exploits”**, *Journal of
> Information Security and Applications* 99 (2026) 104420.

Mục tiêu là để người chưa biết gì về an ninh mạng vẫn hiểu:

- bài báo giải quyết vấn đề gì;
- các khái niệm CVE, CWE, CAPEC, NVD, ExploitDB là gì;
- pipeline của bài báo chạy như thế nào;
- họ dùng model gì, train ra sao;
- họ đánh giá kết quả bằng cách nào;
- kết quả và hạn chế của bài báo;
- vì sao project reproduction của mình không thể “copy y nguyên” kết quả.

---

## 1. Bài báo giải quyết vấn đề gì?

Hãy tưởng tượng bạn là một chuyên gia bảo mật. Mỗi ngày có rất nhiều lỗ hổng mới
được công bố. Mỗi lỗ hổng chỉ có một đoạn mô tả bằng tiếng Anh, ví dụ:

> “Một phần mềm X xử lý dữ liệu đầu vào sai, cho phép kẻ tấn công gửi dữ liệu
> đặc biệt để chạy lệnh từ xa.”

Từ đoạn mô tả đó, chuyên gia phải tự trả lời:

1. Lỗ hổng này thuộc loại gì?
2. Kẻ tấn công thường khai thác nó theo các bước nào?
3. Có exploit (mã khai thác) công khai nào không?
4. Nếu muốn kiểm chứng trong phòng lab thì làm thế nào?

Làm thủ công việc này rất tốn thời gian. Bài báo muốn tự động hóa một phần quy
trình đó bằng AI.

Cụ thể, bài báo xây dựng **Vuln2Action**, một framework nhận vào **mô tả CVE**
và sinh ra:

- **CAPEC** phù hợp nhất — tức là “kiểu tấn công” gần nhất;
- **execution flow** — các bước tấn công theo 3 pha Explore → Experiment →
  Exploit;
- **exploit mapping** — liên kết các bước đó với exploit thật trong ExploitDB;
- **exploit code** — lấy code tương ứng từ ExploitDB GitLab.

Nói ngắn gọn:

> Đưa vào một lỗ hổng đã được mô tả, hệ thống sinh ra một “kịch bản tấn công”
> và chỉ ra exploit thật tương ứng.

Đây là bài toán **Cyber Threat Intelligence (CTI)** — biến dữ liệu lỗ hổng
thành hiểu biết có thể hành động.

---

## 2. Các khái niệm cần biết trước

### 2.1. CVE là gì?

**CVE** = *Common Vulnerabilities and Exposures*.

Mỗi lỗ hổng được cấp một mã duy nhất, ví dụ:

- `CVE-2021-44228` — Log4Shell;
- `CVE-2020-1472` — ZeroLogon;
- `CVE-2022-22965` — Spring4Shell.

Bạn có thể hiểu CVE giống như **số hồ sơ của một vụ án cụ thể**. Mỗi CVE mô tả
một lỗ hổng cụ thể trong một sản phẩm cụ thể.

### 2.2. CWE là gì?

**CWE** = *Common Weakness Enumeration*.

CWE mô tả **loại điểm yếu**, không phải một vụ cụ thể. Ví dụ:

- `CWE-79`: Cross-site Scripting (XSS);
- `CWE-89`: SQL Injection;
- `CWE-78`: OS Command Injection;
- `CWE-22`: Path Traversal.

Nếu CVE là “vụ án cụ thể”, CWE là “loại tội phạm”.

Ví dụ:

- CVE-2021-44228 là một vụ cụ thể;
- nó thuộc nhóm CWE-20 hoặc CWE-502 tùy cách NVD gán.

### 2.3. CAPEC là gì?

**CAPEC** = *Common Attack Pattern Enumeration and Classification*.

CAPEC mô tả **kiểu tấn công** — cách kẻ tấn công thường làm để khai thác một
loại điểm yếu. Ví dụ:

- CAPEC-66: SQL Injection;
- CAPEC-100: Overflow Buffers;
- CAPEC-126: Path Traversal.

Nếu CWE là “loại điểm yếu”, CAPEC là **“playbook” / “modus operandi”** của kẻ
tấn công.

Ví dụ dễ hiểu:

- CWE = “cửa sổ bị khóa sơ sài”;
- CAPEC = “cách kẻ trộm thường cạy cửa sổ loại đó”.

### 2.4. NVD là gì?

**NVD** = *National Vulnerability Database* — cơ sở dữ liệu của NIST (Mỹ).

NVD lấy thông tin CVE và làm giàu thêm:

- mô tả;
- điểm nguy hiểm CVSS;
- CWE;
- CPE (sản phẩm bị ảnh hưởng);
- tài liệu tham khảo.

Trong bài báo, NVD là nguồn chính để lấy CVE và CWE.

### 2.5. ExploitDB là gì?

**ExploitDB** là một kho exploit công khai. Mỗi exploit thường có:

- mô tả;
- đường dẫn tới file code (Python, PHP, C, text…);
- CVE liên quan (nếu có).

Bài báo dùng ExploitDB để:

1. lấy mô tả exploit;
2. map mỗi bước tấn công với exploit gần nhất;
3. lấy code exploit từ GitLab.

### 2.6. Quan hệ CVE → CWE → CAPEC

Đây là xương sống của bài báo.

```text
CVE (vụ cụ thể)
  ↓ NVD gán
CWE (loại điểm yếu)
  ↓ CAPEC liệt kê các CWE liên quan
CAPEC (kiểu tấn công)
```

Ví dụ:

```text
CVE-2021-44228
  ↓
CWE-20 / CWE-502
  ↓
CAPEC-233 (Exploitation of Log4j)
```

Một CVE có thể ứng với nhiều CWE, và một CWE có thể ứng với nhiều CAPEC. Vì
vậy bài báo phải **chọn CAPEC phù hợp nhất**.

### 2.7. CVSS là gì?

**CVSS** là thang điểm 0–10 đo mức độ nguy hiểm của lỗ hổng.

- 0.0: không nguy hiểm;
- 9.0–10.0: critical.

Bài báo không dùng CVSS làm input chính, nhưng dùng để chọn mẫu đa dạng khi
đánh giá.

### 2.8. Exploit là gì?

**Exploit** là mã hoặc kỹ thuật cụ thể để khai thác lỗ hổng.

- “PoC” = proof of concept — mã chứng minh lỗ hổng tồn tại;
- “weaponized exploit” = exploit hoàn chỉnh, có thể tấn công thật.

Bài báo map tới exploit code công khai. Đây là phần nhạy cảm về an toàn thông
tin, nên project của mình sẽ giới hạn code trong lab isolated.

---

## 3. Pipeline của bài báo

Bài báo có 5 phần lớn:

```text
1. Xây dataset
   CVE + CWE + CAPEC + ExploitDB
        ↓
2. Chọn CAPEC phù hợp nhất
   TF-IDF / Word2Vec + cosine similarity
        ↓
3. Train T5 giai đoạn 1
   CVE description → execution flow
        ↓
4. Map technique → ExploitDB description
   rồi train T5 giai đoạn 2
        ↓
5. Map step → exploit code bằng SBERT
   và hiển thị qua GUI Flask
```

### 3.1. Bước 1 — Xây dataset

Paper lấy:

- CVE có index năm 2023;
- exploit từ 1999 đến 2023;
- CWE và CAPEC từ MITRE.

Kết quả:

| Thành phần | Số lượng |
|---|---:|
| CVE | 114.560 |
| cặp CVE–CWE | 28.831 |
| cặp CWE–CAPEC | 46.575 |
| CWE | 915 |
| CAPEC | 1.024 |

Họ không có một dataset có sẵn mapping CVE → CAPEC. Vì vậy họ tự xây:

1. CVE → CWE lấy từ NVD;
2. CWE → CAPEC lấy từ CAPEC;
3. ghép lại thành CVE → CWE → nhiều CAPEC ứng viên;
4. chọn CAPEC tốt nhất bằng similarity.

### 3.2. Bước 2 — Chọn CAPEC tốt nhất

Vấn đề: một CVE có thể ra nhiều CAPEC. Cần chọn một CAPEC “đúng nhất”.

Paper thử 2 cách:

#### Cách 1: TF-IDF

TF-IDF là phương pháp so khớp **từ**. Nó đếm từ nào xuất hiện nhiều và quan
trọng.

Ví dụ:

- CVE nói: “remote code execution”;
- CAPEC nói: “execute arbitrary code”.

TF-IDF có thể không nhận ra hai câu này giống nhau vì dùng từ khác nhau.

#### Cách 2: Word2Vec

Word2Vec biến mỗi từ thành một vector số, sao cho các từ gần nghĩa nằm gần nhau.

Ví dụ:

- “code injection” gần với “remote code execution”;
- “overflow” gần với “buffer overflow”.

Nhờ vậy Word2Vec hiểu nghĩa tốt hơn TF-IDF.

#### Cosine similarity

Sau khi có vector, họ tính **cosine similarity** — đo góc giữa hai vector.

- Giống nhau → cosine gần 1;
- Khác nhau → cosine gần 0;
- Ngược nhau → cosine gần -1.

Paper chọn CAPEC có cosine cao nhất.

Kết quả paper báo cáo:

- TF-IDF similarity tối đa: **52.9%**;
- Word2Vec similarity tối đa: **91.2%**;
- Vì vậy họ chọn **Word2Vec**.

Họ cũng kiểm tra thủ công 100 CVE–CAPEC. Hai nhà nghiên cứu chấm độc lập, sau
đó thống nhất. Kết quả: **89/100 đúng**.

Một quan sát quan trọng: các CAPEC **con** (child-level) thường cụ thể và khớp
hơn CAPEC cha (parent-level).

### 3.3. Bước 3 — Train T5 giai đoạn 1

**T5** là một mô hình ngôn ngữ dạng *text-to-text*: đưa vào text, sinh ra text.

Paper dùng T5 để:

```text
Input:  mô tả CVE
Output: execution flow gồm 3 pha
```

Execution flow có 3 bước lớn:

1. **Explore** — thu thập thông tin về mục tiêu;
2. **Experiment** — thử các kỹ thuật để tìm lỗ hổng;
3. **Exploit** — khai thác thành công.

Mỗi bước có thể chứa nhiều technique, ví dụ:

- SQL Injection;
- Buffer Overflow;
- Privilege Escalation.

Paper fine-tune T5 trên dataset CVE → flow. Cấu hình:

- learning rate `5e-5`;
- optimizer AdamW;
- loss cross-entropy;
- 50 epochs;
- split 80% train / 20% validation;
- GPU NVIDIA A100 32GB.

### 3.4. Bước 4 — Map technique sang ExploitDB

Sau khi có flow, mỗi technique còn khá trừu tượng. Paper muốn gắn nó với exploit
thật.

Cách làm:

1. Lấy từng technique trong flow;
2. So với mô tả exploit trong ExploitDB;
3. Dùng Word2Vec + cosine để tìm exploit gần nhất;
4. Thay technique bằng mô tả exploit đó.

Sau đó họ **train lại T5 lần 2** trên các flow đã được làm giàu bằng exploit
description.

Đây là lý do paper gọi là **two-stage training**:

```text
Stage 1: CVE → flow cơ bản
Stage 2: CVE → flow có exploit thật
```

### 3.5. Bước 5 — Map step sang exploit code bằng SBERT

Sau khi có flow chi tiết, paper muốn lấy **code exploit** thật.

Họ dùng:

- **ExploitDB CSV** để lấy mô tả và đường dẫn file code;
- **Sentence-BERT (SBERT)** để so sánh cả câu, không chỉ từng từ;
- cosine similarity;
- một threshold (ngưỡng) để chỉ lấy khi đủ giống.

Nếu similarity vượt ngưỡng:

1. lấy đường dẫn file từ CSV;
2. tải code từ ExploitDB GitLab;
3. gắn code vào step.

SBERT mạnh hơn TF-IDF/Word2Vec ở chỗ nó hiểu **cả câu**, không chỉ từng từ.

### 3.6. GUI Flask

Paper làm một web app bằng **Flask**:

- nhập CVE ID;
- xem CAPEC được chọn;
- xem execution flow;
- xem exploit code;
- xem điểm similarity.

Frontend dùng HTML + Bootstrap + JavaScript.

---

## 4. Cách bài báo đánh giá

Paper đánh giá ở 4 góc:

1. mapping CVE → CAPEC có đúng không;
2. execution flow sinh ra có giống ground truth không;
3. so sánh T5 với FLAN-T5;
4. con người đọc và chấm output.

### 4.1. CAPEC accuracy

Họ chọn 100 CVE, so CAPEC dự đoán với ground truth từ repo **CVE2CAPEC**.

Kết quả: **89/100 đúng**.

Lưu ý: đây là top-1 accuracy — chỉ cần CAPEC đứng đầu đúng.

### 4.2. BLEU

**BLEU** đo mức độ trùng khớp n-gram giữa output của model và reference.

- BLEU cao → output dùng nhiều từ/cụm từ giống reference;
- BLEU thấp → output khác reference.

Paper báo cáo:

- TF-IDF + T5: **BLEU 0.75**;
- Word2Vec + T5: **BLEU 0.72**.

Điều thú vị: Word2Vec giúp chọn CAPEC tốt hơn, nhưng BLEU lại thấp hơn một
chút, vì BLEU nhạy với việc dùng từ giống hệt.

### 4.3. ROUGE

**ROUGE** đo mức độ bao phủ nội dung reference.

- ROUGE-1: trùng từng từ;
- ROUGE-2: trùng từng cặp từ;
- ROUGE-L: trùng chuỗi con dài nhất.

Paper báo cáo T5 đạt:

| Metric | Giá trị |
|---|---:|
| BLEU | 0.7589 |
| ROUGE-1 F1 | 0.8126 |
| ROUGE-2 F1 | 0.7762 |
| ROUGE-L F1 | 0.7950 |

FLAN-T5-base thấp hơn:

| Model | BLEU |
|---|---:|
| T5 | 0.7589 |
| FLAN-T5 | 0.6813 |

### 4.4. Human evaluation

Paper chọn 20 CVE nổi tiếng, nhờ **3 chuyên gia** chấm:

- **Correctness**: các bước có đúng không (%);
- **Completeness**: có thiếu bước quan trọng không (1–5);
- **Clarity**: có dễ hiểu, làm theo được không (1–5).

Kết quả trung bình:

- correctness **86.9%**;
- completeness **4.3/5**;
- clarity **4.4/5**;
- precision **0.87**, recall **0.82**, F1 **0.83**.

### 4.5. Resource usage

Trên A100:

- inference trung bình **2.67 giây/CVE**;
- CPU RAM khoảng **1609 MB**;
- GPU peak khoảng **1773 MB**.

---

## 5. Kết quả chính của bài báo

Tóm tắt:

1. Xây được dataset lớn: 114.560 CVE, 915 CWE, 1.024 CAPEC.
2. Word2Vec + cosine chọn CAPEC tốt hơn TF-IDF.
3. T5 sinh execution flow có BLEU ~0.75.
4. T5 tốt hơn FLAN-T5-base trong task này.
5. Human eval đạt correctness ~86.9%.
6. GUI Flask giúp demo end-to-end.

---

## 6. Hạn chế của bài báo

Paper tự thừa nhận:

1. **Phụ thuộc ExploitDB**: nếu lỗ hổng không có exploit công khai thì không mô
   hình đầy đủ được.
2. **Chỉ là text, chưa chạy thật**: execution flow là mô tả, không phải exploit
   đã được kiểm chứng trong sandbox.
3. **BLEU/ROUGE không đo được tính đúng thực tế**: output có thể giống chữ nhưng
   không chạy được.
4. **CVE description có thể mơ hồ**: mô tả ngắn, thiếu ngữ cảnh → model bỏ qua
   bước.
5. **Mapping CVE→CWE→CAPEC có thể sai**: NVD gán CWE không phải lúc nào cũng
   hoàn hảo.
6. **Không tổng quát hóa tốt** cho kiểu tấn công mới ngoài training data.
7. **Cần human validation** cho case quan trọng.

Điểm quan trọng: paper **không làm sandbox validation**. Họ để phần này cho
future work.

---

## 7. Vì sao project reproduction của mình không thể giống 100%?

Có 4 lý do lớn:

### 7.1. Dataset gốc không public

Paper ghi dataset “available on request”. Mình không có đúng file họ dùng.

Mình phải dựng lại từ:

- NVD;
- CWE;
- CAPEC;
- ExploitDB;
- CVE2CAPEC.

Vì vậy số lượng CVE, cách split, cách gán nhãn có thể lệch.

### 7.2. Hardware khác

Paper dùng **A100 32GB**. Mình dùng **Kaggle T4 x2**.

T4 chậm hơn, nên:

- có thể phải giảm epochs;
- hoặc dùng `t5-small`;
- hoặc giảm dataset.

Mọi thay đổi phải ghi rõ trong báo cáo.

### 7.3. Human evaluation khác

Paper có **3 chuyên gia**. Mình có **1 thầy hướng dẫn**.

Vì vậy kết quả human eval của mình là **single-expert advisor review**, không
phải “3-expert study”. Không được so trực tiếp với 86.9% của paper.

### 7.4. Exploit code là phần nhạy cảm

Paper tải exploit code công khai và hiển thị trên GUI. Project của mình giữ scope
defensive:

- code chỉ nằm trong lab isolated;
- không tự động chạy;
- không dùng target thật;
- không upload code lên Kaggle.

---

## 8. Project của mình sẽ làm gì?

Mục tiêu là **method-faithful reproduction**:

```text
NVD/CWE/CAPEC/ExploitDB
        ↓
CVE → CWE → CAPEC (TF-IDF + Word2Vec)
        ↓
T5 stage 1: CVE → execution flow
        ↓
Map technique → ExploitDB description
        ↓
T5 stage 2: CVE → flow có exploit
        ↓
SBERT: step → exploit code (isolated lab)
        ↓
Flask GUI + evaluation
```

Các phần sẽ làm:

1. Data ingestion và build dataset.
2. CAPEC mapping + evaluate 100 CVE.
3. Train T5 2 giai đoạn trên Kaggle T4 x2.
4. BLEU/ROUGE + so sánh FLAN-T5.
5. SBERT exploit mapping.
6. Flask GUI.
7. Human eval với thầy.
8. Docker lab isolated để kiểm chứng an toàn.

---

## 9. Cách đọc kết quả reproduction cho đúng

Khi báo cáo, luôn tách 2 cột:

| Paper | Reproduction |
|---|---|
| 114.560 CVE | dataset tự dựng |
| A100 32GB | T4 x2 |
| 50 epochs | số epoch thực tế |
| 3 chuyên gia | 1 thầy hướng dẫn |
| BLEU 0.7589 | BLEU đo được |
| exploit code công khai | code trong lab isolated |

Không được viết:

> “Bọn em reproduce được đúng kết quả paper.”

Nên viết:

> “Bọn em tái tạo pipeline và phương pháp; kết quả đo được là X, khác paper vì
> dataset/hardware/reviewer khác.”

Đó là cách báo cáo trung thực và đúng khoa học.

---

## 10. Tóm tắt một câu

> Bài báo biến mô tả lỗ hổng CVE thành một kịch bản tấn công có các bước, chọn
> CAPEC phù hợp bằng Word2Vec, sinh flow bằng T5, gắn với exploit thật trong
> ExploitDB, rồi hiển thị qua GUI; project của mình tái tạo pipeline đó nhưng
> dùng dữ liệu/hardware/reviewer khác và thêm lab isolated để kiểm chứng an
> toàn.
