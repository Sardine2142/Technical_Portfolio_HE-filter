# DEPLOY_DAY.md — Oracle VPS 배포 당일 순서서 (위에서 아래로)

전제: Oracle 계정 생성 완료, A1.Flex 인스턴스(Ubuntu 24.04 aarch64) 확보,
공인 IP 발급, SSH 키 등록 완료. 이하 `<IP>` 는 공인 IP.

---

## 0. 접속 확인 (WSL 에서)

```bash
ssh ubuntu@<IP>
```

키를 기본 경로가 아닌 곳에 만들었다면 `ssh -i ~/.ssh/키파일 ubuntu@<IP>`.

## 1. 파일 업로드 (WSL ~/lookup 에서)

```bash
# 원격에 작업 디렉터리를 만든다
ssh ubuntu@<IP> "mkdir -p ~/lookup"

# 필요한 파일 일체를 올린다
scp lookup_common.h lookup_server.cpp \
    fetch_feed_v4.py tranco_top10k.json \
    vps_setup.sh lookup.service \
    measure_client.cpp run_measure.sh \
    ubuntu@<IP>:~/lookup/
```

feed_hv.csv 는 올리지 않는다 — VPS 에서 v4 로 새로 수집하는 게 더 신선하다.

## 2. 초기 구축 (VPS 에서, 시간이 가장 오래 걸리는 단계)

```bash
cd ~/lookup
chmod +x vps_setup.sh
./vps_setup.sh
```

OpenFHE 컴파일이 수십 분 걸릴 수 있다 (4 OCPU 기준 ~20-30분 예상).
끝나면 서버 빌드까지 자동으로 된다.

## 3. 목록 수집 (VPS 에서)

```bash
cd ~/lookup
python3 fetch_feed_v4.py --out feed_hv.csv
```

54만대 최종 목록과 필터 제외 건수가 로컬 실행과 비슷한 규모로 나오는지 확인.

## 4. 방화벽 — Oracle 은 두 겹이다 (가장 자주 막히는 지점)

### 4a. OCI 콘솔 쪽 (Security List)
콘솔 -> Networking -> VCN -> 해당 서브넷의 Security List -> Ingress Rules 에 추가:
- Source CIDR: 0.0.0.0/0  (임시. 원하면 내 집 공인 IP/32 로 좁혀도 됨)
- Protocol: TCP, Destination Port: 8080

### 4b. OS 쪽 (Oracle 이미지는 iptables REJECT 가 기본 내장)

```bash
# REJECT 규칙보다 앞 순번에 8080 허용을 끼워 넣는다
sudo iptables -I INPUT 5 -p tcp --dport 8080 -j ACCEPT
# 재부팅 후에도 유지되도록 저장한다
sudo netfilter-persistent save
```

## 5. 서비스 기동 (VPS 에서)

```bash
sudo cp ~/lookup/lookup.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lookup
# 상태 확인 (active (running) 이어야 함)
systemctl status lookup --no-pager
```

## 6. 외부 도달 확인 (WSL 에서)

```bash
curl -s http://<IP>:8080/health && echo
```

JSON 이 나오면 두 겹 방화벽 통과. 안 나오면 4a/4b 를 다시 점검
(VPS 자체에서 curl 127.0.0.1:8080/health 가 되는데 밖에서 안 되면 방화벽 확정).

## 7. 원격 측정 (WSL ~/lookup 에서 — 문서의 원격 칸을 채우는 실행)

```bash
OMP_NUM_THREADS=1 ./measure_client <IP>:8080 30 --listed $(head -1 feed_hv.csv | cut -d, -f1)
```

주의: --listed 는 로컬 feed_hv.csv 의 첫 항목인데, VPS 목록과 수집 시점이
다르면 없을 수 있다. 양성 실패가 나오면 VPS 쪽 첫 항목으로 교체:
`ssh ubuntu@<IP> "head -1 ~/lookup/feed_hv.csv | cut -d, -f1"`

기대: http 단계만 로컬 수 ms -> (KR-JP 왕복 ~30ms + 650KB 전송) 수준으로 늘고
나머지 단계는 로컬과 동일. measure_log.csv 에 원격 줄이 추가된다.

## 8. 실사용 전환 (Windows 쪽 한 줄)

run_daemon.sh (wsl 래퍼가 부르는 스크립트) 에서:

```bash
export LOOKUP_SERVER=<IP>:8080
export OMP_NUM_THREADS=1        # 측정으로 확정된 처방 — 같이 넣는다
```

Edge 재시작 후 아무 사이트나 방문 -> 원격 서버로 질의가 나가는지
`journalctl -u lookup -f` (VPS) 로 확인.

## 9. 목록 자동 갱신 (VPS 에서, 선택이지만 권장)

```bash
# 6시간마다 재수집 (서버는 60초 내 자동 반영)
crontab -e
# 아래 한 줄 추가:
# 0 */6 * * * cd /home/ubuntu/lookup && python3 fetch_feed_v4.py --out feed_hv.csv >> fetch.log 2>&1
```

---

## 이후 과제 (당일 범위 아님)
- TLS: 실사용자가 생기는 시점에 필수 -> caddy 리버스 프록시 + 클라이언트 libcurl 전환
- C-TAS: 공유정책 재배포 조항 확인 전까지 VPS 에 투입 금지 (공개 피드 4개만)
