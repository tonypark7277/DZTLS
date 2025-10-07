#!/usr/bin/env bash
set -euo pipefail

# 사용법:
#   ./run_experiments.sh <횟수> [라벨]
# 예:
#   ./run_experiments.sh 10 sav_on
#   ./run_experiments.sh 10 sav_off
#
# 횟수를 생략하면 대화형으로 물어봅니다.
# 라벨을 생략하면 기본값 sav_run 이 사용됩니다.

# ===== 설정 =====
CLIENT_SCRIPT="client.py"       # 클라이언트 스크립트 경로
OUT_DIR="results"                # 결과 저장 폴더
SLEEP_BETWEEN_RUNS="${SLEEP_BETWEEN_RUNS:-1}"   # 각 실행 사이 대기(초). 환경변수로 조절 가능.

# 가상환경 python 우선 사용
if [[ -x ".venv/bin/python" ]]; then
  PYTHON=".venv/bin/python"
else
  PYTHON="python"
fi

# ===== 인자 파싱 =====
RUNS="${1:-}"
LABEL="${2:-sav_run}"

if [[ -z "${RUNS}" ]]; then
  read -rp "몇 번 반복할까요? (정수): " RUNS
fi

# 숫자 검증
if ! [[ "${RUNS}" =~ ^[0-9]+$ ]] || [[ "${RUNS}" -eq 0 ]]; then
  echo "에러: 횟수는 1 이상의 정수여야 합니다." >&2
  exit 1
fi

# ===== 준비 =====
mkdir -p "${OUT_DIR}"

echo "실험 시작: 총 ${RUNS}회, 라벨='${LABEL}', 결과폴더='${OUT_DIR}'"
echo "Python: ${PYTHON}"
echo "Client: ${CLIENT_SCRIPT}"
echo "Run 간 대기: ${SLEEP_BETWEEN_RUNS}s"
echo "----------------------------------------"

# ===== 반복 실행 =====
for ((i=1; i<=RUNS; i++)); do
  # 파일명: run_<label>_<seq>_<timestamp>.txt (밀리초 포함)
  TS="$(date +'%Y%m%d_%H%M%S_%3N')"
  OUTFILE="${OUT_DIR}/run_${LABEL}_${i}_${TS}.txt"

  echo "[$(date +'%F %T')] (${i}/${RUNS}) 실행 시작 → ${OUTFILE}"
  # 표준출력을 화면에도 보여주고 파일에도 저장(tee)
  # 표준에러까지 저장하고 싶으면 2>&1 추가
  "${PYTHON}" "${CLIENT_SCRIPT}" 2>&1 | tee "${OUTFILE}"

  # 다음 반복 전 대기
  if [[ "${i}" -lt "${RUNS}" ]]; then
    sleep "${SLEEP_BETWEEN_RUNS}"
  fi
done

echo "----------------------------------------"
echo "완료! 결과 파일은 '${OUT_DIR}/' 아래에 저장되었습니다."

