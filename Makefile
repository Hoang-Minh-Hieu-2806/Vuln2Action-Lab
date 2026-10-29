.PHONY: install test pipeline eval eval-capec capec-benchmark retrieval-context lint clean docker-up docker-down

install:
	pip install -r requirements.txt

test:
	pytest -v

pipeline:
	python scripts/run_pipeline.py --sample CVE-2024-0001 --provider rule_based

eval:
	python scripts/run_evaluation.py --stage retrieval

eval-capec:
	python scripts/run_evaluation.py --stage capec --save results/evaluation

capec-benchmark:
	python scripts/build_capec_benchmark.py --download --year 2021 --size 120

retrieval-context:
	python scripts/build_retrieval_context.py

lint:
	python -m compileall -q src api scripts tests evaluation

clean:
	rm -rf __pycache__ src/__pycache__ .pytest_cache results/*

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down
