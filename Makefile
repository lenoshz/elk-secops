# =============================================================================
# ELK Stack SecOps — Makefile
# =============================================================================
# Convenience targets for managing the Docker Compose stack.
#
# Usage:
#   make up       — Start all services in detached mode
#   make secops   — Configure SIEM rules + ML anomaly detection
#   make down     — Stop all services and remove volumes
#   make logs     — Tail logs from all containers
#   make test     — Run full health checks (ES, Kibana, indices, SIEM, ML)
# =============================================================================

.PHONY: up down logs test clean status siem ml secops

# ---------------------------------------------------------------------------
# Start the full ELK stack in detached mode
# ---------------------------------------------------------------------------
up:
	@echo "🚀 Starting ELK stack..."
	docker-compose up -d
	@echo "✅ Stack is starting. Use 'make logs' to follow output."
	@echo "   Kibana: http://localhost:5601  (elastic / changeme)"
	@echo "   Elasticsearch: http://localhost:9200"
	@echo ""
	@echo "   After stack is healthy, run 'make secops' to configure SIEM + ML."

# ---------------------------------------------------------------------------
# Stop all services and remove named volumes
# ---------------------------------------------------------------------------
down:
	@echo "🛑 Stopping ELK stack and removing volumes..."
	docker-compose down -v
	@echo "✅ Stack stopped."

# ---------------------------------------------------------------------------
# Tail logs from all containers (follow mode)
# ---------------------------------------------------------------------------
logs:
	docker-compose logs -f

# ---------------------------------------------------------------------------
# Configure SIEM detection rules via Kibana Detection Engine API
# ---------------------------------------------------------------------------
siem:
	@echo "🛡️  Setting up SIEM detection rules..."
	docker-compose run --rm setup bash -c "pip install --quiet requests && python scripts/setup_siem.py"
	@echo "✅ SIEM rules configured."

# ---------------------------------------------------------------------------
# Configure ML anomaly detection job and datafeed
# ---------------------------------------------------------------------------
ml:
	@echo "🤖 Setting up ML anomaly detection..."
	docker-compose run --rm setup bash -c "pip install --quiet requests && python scripts/setup_ml.py"
	@echo "✅ ML anomaly detection configured."

# ---------------------------------------------------------------------------
# Full SecOps setup: SIEM rules + ML in sequence
# ---------------------------------------------------------------------------
secops: siem ml
	@echo ""
	@echo "🔐 SecOps stack fully configured!"
	@echo "   → Import dashboard: Kibana > Stack Management > Saved Objects > Import"
	@echo "     File: kibana/dashboards/secops_dashboard.ndjson"
	@echo "   → Attack simulations run every 5 minutes automatically."

# ---------------------------------------------------------------------------
# Run full health checks against the running stack
# ---------------------------------------------------------------------------
test:
	@echo "🔍 Running health checks..."
	@echo ""
	@echo "--- Elasticsearch ---"
	@curl -sf -u elastic:changeme http://localhost:9200/_cluster/health?pretty || (echo "❌ Elasticsearch is not reachable" && exit 1)
	@echo ""
	@echo "--- License ---"
	@curl -sf -u elastic:changeme http://localhost:9200/_license?pretty | head -10 || echo "❌ Could not check license"
	@echo ""
	@echo "--- Kibana ---"
	@curl -sf -u elastic:changeme http://localhost:5601/api/status | python -m json.tool --no-ensure-ascii 2>/dev/null | head -5 || echo "❌ Kibana is not reachable (may still be starting)"
	@echo ""
	@echo "--- App Logs Indices ---"
	@curl -sf -u elastic:changeme http://localhost:9200/_cat/indices/app-logs-*?v || echo "⚠️  No app-logs-* indices yet"
	@echo ""
	@echo "--- Security Logs Indices ---"
	@curl -sf -u elastic:changeme http://localhost:9200/_cat/indices/security-logs-*?v || echo "⚠️  No security-logs-* indices yet"
	@echo ""
	@echo "--- ILM Policy ---"
	@curl -sf -u elastic:changeme http://localhost:9200/_ilm/policy/app-logs-policy?pretty || echo "❌ ILM policy not found"
	@echo ""
	@echo "--- Index Templates ---"
	@curl -sf -u elastic:changeme http://localhost:9200/_index_template/app-logs-template?pretty | head -10 || echo "❌ app-logs template not found"
	@curl -sf -u elastic:changeme http://localhost:9200/_index_template/security-logs-template?pretty | head -10 || echo "❌ security-logs template not found"
	@echo ""
	@echo "--- SIEM Detection Rules ---"
	@curl -sf -u elastic:changeme -H 'kbn-xsrf: true' http://localhost:5601/api/detection_engine/rules/_find?per_page=10 | python -m json.tool --no-ensure-ascii 2>/dev/null | head -15 || echo "⚠️  SIEM rules not configured yet (run 'make secops')"
	@echo ""
	@echo "--- ML Anomaly Detection Job ---"
	@curl -sf -u elastic:changeme http://localhost:9200/_ml/anomaly_detectors/security-anomaly-detector/_stats?pretty | head -20 || echo "⚠️  ML job not configured yet (run 'make secops')"
	@echo ""
	@echo "✅ Health checks complete."

# ---------------------------------------------------------------------------
# Show container status
# ---------------------------------------------------------------------------
status:
	docker-compose ps

# ---------------------------------------------------------------------------
# Full cleanup: stop stack, remove volumes, and delete generated files
# ---------------------------------------------------------------------------
clean: down
	@echo "🧹 Removing generated files..."
	@rm -rf logs/
	@rm -f elastalert/alerts.log
	@echo "✅ Clean complete."
