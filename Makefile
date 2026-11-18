# Linux-parity mirror of lab.py. On Windows, call `python lab.py <verb>` directly.
PY ?= python

.PHONY: doctor selftest up attack snapshot reset collect down test lint

doctor:    ; $(PY) lab.py doctor
selftest:  ; $(PY) lab.py selftest
up:        ; $(PY) lab.py up
attack:    ; $(PY) lab.py attack
snapshot:  ; $(PY) lab.py snapshot
reset:     ; $(PY) lab.py reset
collect:   ; $(PY) lab.py collect
down:      ; $(PY) lab.py down

test:      ; $(PY) -m pytest -q
lint:      ; $(PY) -m ruff check . && $(PY) -m ruff format --check .
