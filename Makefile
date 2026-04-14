PYTHON ?= python3
PYTEST ?= $(PYTHON) -m pytest
PLATFORM_API_BASE_URL ?= http://127.0.0.1:8000
DEMO_WATCHGUARD_PAYLOAD ?= examples/watchguard/minimal_payload.json
DEMO_PHISHING_EMAIL_PAYLOAD ?= examples/phishing/minimal_payload.json
WATCHGUARD_S3_BUCKET ?= egslatam-cai-dev
WATCHGUARD_S3_REGION ?= us-east-2

.DEFAULT_GOAL := help

TF_DIR ?= infrastructure/terraform
TF_ENV ?= prod

.PHONY: help install-dev build up down test test-apps api-dev health demo-watchguard demo-phishing-email upload-workspace install-ui install-ui-cai ui tf-bootstrap tf-init tf-plan tf-apply tf-import ecs-stop ecs-start

help:
	@printf "Available targets:\n"
	@printf "  help              Show this help output.\n"
	@printf "  install-dev       Install the full contributor/dev Python surface for this repo.\n"
	@printf "  build             Build the compose-managed platform-api and platform-ui images.\n"
	@printf "  up                Start platform-api and platform-ui via Docker Compose.\n"
	@printf "  down              Stop all Docker Compose services.\n"
	@printf "  test              Run the current repository test suite.\n"
	@printf "  test-apps         Run only the app-layer test suite.\n"
	@printf "  api-dev           Run platform-api locally without Docker for contributor/dev use.\n"
	@printf "  health            Check the platform-api health endpoint.\n"
	@printf "  demo-watchguard   Run the baseline WatchGuard demo.\n"
	@printf "  demo-phishing-email  Run the phishing email demo.\n"
	@printf "  upload-workspace ZIP=<path> WORKSPACE=<id>  Upload a WatchGuard workspace ZIP to S3.\n"
	@printf "  install-ui        Install the Streamlit platform-ui app (without CAI).\n"
	@printf "  install-ui-cai    Install the Streamlit platform-ui app with CAI agent support.\n"
	@printf "  ui                Launch the Streamlit platform-ui at http://localhost:8501.\n"
	@printf "  tf-bootstrap      Create S3 state bucket + DynamoDB lock table (run once per new account).\n"
	@printf "  tf-init           Initialize Terraform (run after bootstrap).\n"
	@printf "  tf-plan           Preview infrastructure changes.\n"
	@printf "  tf-apply          Apply infrastructure changes.\n"
	@printf "  tf-import         Import existing AWS resources into Terraform state (run once).\n"
	@printf "  ecs-stop          Scale all ECS services to 0 (cost saving when not in use).\n"
	@printf "  ecs-start         Scale ECS services back to 1.\n"

install-dev:
	$(PYTHON) -m pip install -e packages/platform-contracts
	$(PYTHON) -m pip install -e packages/platform-core
	$(PYTHON) -m pip install -e packages/platform-adapters
	$(PYTHON) -m pip install -e packages/platform-backends
	$(PYTHON) -m pip install -e 'apps/platform-api[test]'
	$(PYTHON) -m pip install -e 'apps/cai-orchestrator[test]'

build:
	docker compose build platform-api platform-ui

up:
	docker compose up -d platform-api platform-ui

down:
	docker compose down

test:
	$(PYTEST) tests

test-apps:
	$(PYTEST) tests/apps

api-dev:
	$(PYTHON) -m platform_api

health:
	$(PYTHON) -c "import json, urllib.request; print(json.dumps(json.loads(urllib.request.urlopen('$(PLATFORM_API_BASE_URL)/health').read().decode()), indent=2, sort_keys=True))"

demo-watchguard:
	PLATFORM_API_BASE_URL='$(PLATFORM_API_BASE_URL)' $(PYTHON) -m cai_orchestrator run-watchguard --client-id "demo-client" --title "WatchGuard demo case" --summary "Run the minimal WatchGuard demo slice." --payload-file '$(DEMO_WATCHGUARD_PAYLOAD)'

demo-phishing-email:
	PLATFORM_API_BASE_URL='$(PLATFORM_API_BASE_URL)' $(PYTHON) -m cai_orchestrator run-phishing-email-basic-assessment --client-id "demo-client" --title "Phishing email demo case" --summary "Run the phishing email basic assessment slice." --payload-file '$(DEMO_PHISHING_EMAIL_PAYLOAD)'

install-ui:
	$(PYTHON) -m pip install -e apps/platform-ui

install-ui-cai:
	$(PYTHON) -m pip install -e 'apps/platform-ui[cai]'

ui:
	$(PYTHON) -m streamlit run apps/platform-ui/src/platform_ui/app.py

tf-bootstrap:
	@echo "==> Creating S3 bucket for Terraform state: $(WATCHGUARD_S3_BUCKET)"
	aws s3api create-bucket \
		--bucket $(WATCHGUARD_S3_BUCKET) \
		--region $(WATCHGUARD_S3_REGION) \
		--create-bucket-configuration LocationConstraint=$(WATCHGUARD_S3_REGION) || true
	aws s3api put-bucket-versioning \
		--bucket $(WATCHGUARD_S3_BUCKET) \
		--versioning-configuration Status=Enabled \
		--region $(WATCHGUARD_S3_REGION)
	aws s3api put-bucket-encryption \
		--bucket $(WATCHGUARD_S3_BUCKET) \
		--server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' \
		--region $(WATCHGUARD_S3_REGION)
	@echo "==> Creating DynamoDB table for Terraform locks"
	aws dynamodb create-table \
		--table-name cai-platform-tf-locks \
		--attribute-definitions AttributeName=LockID,AttributeType=S \
		--key-schema AttributeName=LockID,KeyType=HASH \
		--billing-mode PAY_PER_REQUEST \
		--region $(WATCHGUARD_S3_REGION) || true
	@echo ""
	@echo "Bootstrap complete. Next steps:"
	@echo "  1. Edit infrastructure/terraform/versions.tf — update bucket name if different"
	@echo "  2. Edit infrastructure/terraform/terraform.tfvars — set your values"
	@echo "  3. make tf-init"
	@echo "  4. make tf-apply"

tf-init:
	cd $(TF_DIR) && terraform init

tf-plan:
	cd $(TF_DIR) && terraform plan

tf-apply:
	cd $(TF_DIR) && terraform apply

tf-import:
	cd $(TF_DIR) && bash import.sh

ecs-stop:
	aws ecs update-service --cluster cai-platform --service platform-api --desired-count 0 --region us-east-2
	aws ecs update-service --cluster cai-platform --service platform-ui  --desired-count 0 --region us-east-2
	@echo "ECS services scaled to 0."

ecs-start:
	aws ecs update-service --cluster cai-platform --service platform-api --desired-count 1 --region us-east-2
	aws ecs update-service --cluster cai-platform --service platform-ui  --desired-count 1 --region us-east-2
	@echo "ECS services scaled to 1."

upload-workspace:
	@if [ -z "$(ZIP)" ] || [ -z "$(WORKSPACE)" ]; then \
		echo "Usage: make upload-workspace ZIP=<path/to/file.zip> WORKSPACE=<workspace_id>"; \
		exit 1; \
	fi
	@UPLOAD_ID=$$(date +%Y%m%d_%H%M%S) && \
	S3_KEY="workspaces/$(WORKSPACE)/input/uploads/$${UPLOAD_ID}/raw.zip" && \
	echo "Uploading $(ZIP) to s3://$(WATCHGUARD_S3_BUCKET)/$${S3_KEY} ..." && \
	aws s3 cp "$(ZIP)" "s3://$(WATCHGUARD_S3_BUCKET)/$${S3_KEY}" --region "$(WATCHGUARD_S3_REGION)" && \
	echo "Done. workspace_id=$(WORKSPACE) upload_id=$${UPLOAD_ID}" && \
	echo "S3 URI: s3://$(WATCHGUARD_S3_BUCKET)/$${S3_KEY}"
