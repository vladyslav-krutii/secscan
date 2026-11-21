.PHONY: help install test lint run up down logs load k8s-render k8s-pin k8s-policy k8s-deploy k8s-verify k8s-delete

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Install dev dependencies
	pip install -r requirements-dev.txt

test: ## Run unit tests
	pytest -q

lint: ## Lint with ruff
	ruff check .

run: ## Run the API locally with autoreload
	uvicorn app.main:app --reload

up: ## Start full stack (API + Prometheus + Grafana)
	docker compose up --build -d

down: ## Stop the stack
	docker compose down

logs: ## Tail stack logs
	docker compose logs -f

load: ## Fire a few scans to populate metrics
	@for u in https://github.com https://example.com https://cloudflare.com; do \
		curl -s "http://localhost:8000/scan?url=$$u" >/dev/null && echo "scanned $$u"; \
	done

K8S_IMAGE := ghcr.io/vladyslav-krutii/secscan
K8S_OVERLAY := k8s/overlays/kind

k8s-render: ## Render all Kustomize manifests (no cluster needed)
	kubectl kustomize k8s/policy >/dev/null
	kubectl kustomize $(K8S_OVERLAY)

k8s-pin: ## Pin the overlay to the digest :latest points to (signed by CI)
	@d=$$(docker buildx imagetools inspect $(K8S_IMAGE):latest --format '{{json .Manifest.Digest}}' | tr -d '"'); \
	sed -i "s/digest: sha256:.*/digest: $$d/" $(K8S_OVERLAY)/kustomization.yaml; \
	echo "pinned $(K8S_IMAGE)@$$d"

k8s-policy: ## Apply the namespace and the Kyverno signature policy
	kubectl apply -k k8s/policy
	kubectl -n secscan wait nivpol/verify-secscan-signature --for=jsonpath='{.status.conditionStatus.ready}'=true --timeout=60s

k8s-deploy: k8s-policy ## Policy first, then the app (by digest)
	kubectl apply -k $(K8S_OVERLAY)
	kubectl -n secscan rollout status deploy/secscan --timeout=180s

k8s-verify: ## Prove the hardening on the cluster (app, network, admission)
	bash scripts/k8s-verify.sh

k8s-delete: ## Remove the secscan namespace and everything in it
	kubectl delete namespace secscan
