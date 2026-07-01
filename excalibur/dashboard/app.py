from pathlib import Path
import os
import csv
import io
import json
import logging
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from excalibur.env import load_environment

load_environment()

from flask import (
    Flask,
    abort,
    current_app,
    g,
    render_template,
    request,
    redirect,
    Response,
    jsonify,
    send_file,
    send_from_directory,
    url_for,
)

from excalibur.config import Config
from excalibur.database import Database
from excalibur.detection.rules_config import RulesConfig
from excalibur.detection.signature_engine import SignatureEngine, SignatureValidationError
from excalibur.notifications import NotificationManager
from excalibur.paths import (
    config_path as platform_config_path,
    database_path as platform_database_path,
    plugins_dir as platform_plugins_dir,
    rules_config_path as platform_rules_config_path,
    rules_dir as platform_rules_dir,
    runtime_path,
)
from excalibur.services.service_controller import (
    ServiceControllerError,
    create_service_controller,
)

logger = logging.getLogger(__name__)


def create_app(
    db_path=None,
    config_path=None,
    rules_path=None,
    rule_packs_path=None,
    service_controller=None,
):
    config_path = runtime_path(
        "EXCALIBUR_CONFIG_PATH", config_path or "config.yaml", platform_config_path()
    )
    rules_path = runtime_path(
        "EXCALIBUR_RULES_CONFIG_PATH",
        rules_path or "rules.yaml",
        platform_rules_config_path(),
    )
    rule_packs_path = runtime_path(
        "EXCALIBUR_RULES_DIR", rule_packs_path or "rules", platform_rules_dir()
    )
    config = Config.load(config_path)
    app = Flask(__name__)
    configured_database_path = Config.get_database_path(config)
    if db_path is not None:
        database_path = db_path
    elif "EXCALIBUR_DATA_DIR" in os.environ or "EXCALIBUR_DATABASE_PATH" in os.environ:
        database_path = platform_database_path(configured_database_path)
    else:
        database_path = configured_database_path
    app.config["DATABASE_PATH"] = database_path
    app.config["ASSETS_PATH"] = Path.cwd() / "assets"
    app.config["CONFIG_PATH"] = config_path
    app.config["RULES_PATH"] = rules_path
    app.config["RULE_PACKS_PATH"] = _resolve_rule_packs_path(rule_packs_path, config_path)
    app.config["SERVICE_CONTROLLER"] = service_controller or create_service_controller()

    @app.template_filter("local_time")
    def local_time(value):
        return format_local_time(value)

    @app.route("/assets/<path:filename>")
    def assets(filename):
        return send_from_directory(current_app.config["ASSETS_PATH"], filename)

    @app.teardown_appcontext
    def close_database(exception=None):
        database = g.pop("database", None)
        if database is not None:
            database.close()

    @app.route("/")
    def index():
        database = get_database()
        system_health = database.get_system_health()
        dashboard_metrics = _dashboard_metrics(database, system_health=system_health)
        alert_trend = _dashboard_alert_trend(database)
        top_rules = _dashboard_top_rules(database)
        top_sources = _dashboard_top_sources(database)
        recent_alerts = database.get_recent_alerts(limit=5)
        return render_template(
            "index.html",
            dashboard_metrics=dashboard_metrics,
            alert_trend=alert_trend,
            top_rules=top_rules,
            top_sources=top_sources,
            recent_alerts=recent_alerts,
            system_health=system_health,
        )

    @app.route("/api/dashboard/metrics")
    def dashboard_metrics():
        database = get_database()
        return jsonify(_dashboard_metrics(database, system_health=database.get_system_health()))

    @app.route("/api/dashboard/alert-trend")
    def dashboard_alert_trend():
        return jsonify({"days": _dashboard_alert_trend(get_database())})

    @app.route("/api/dashboard/top-rules")
    def dashboard_top_rules():
        return jsonify({"rules": _dashboard_top_rules(get_database())})

    @app.route("/api/dashboard/top-sources")
    def dashboard_top_sources():
        return jsonify({"sources": _dashboard_top_sources(get_database())})

    @app.route("/traffic")
    def traffic():
        database = get_database()
        page = _positive_int(request.args.get("page"), default=1)
        per_page = 100
        sort_by = request.args.get("sort_by", "timestamp")
        sort_order = request.args.get("sort_order", "DESC").upper()
        search = request.args.get("search", "").strip()
        filters = {
            "src_ip": request.args.get("src_ip", "").strip(),
            "dst_ip": request.args.get("dst_ip", "").strip(),
            "protocol": request.args.get("protocol", "").strip(),
            "src_port": request.args.get("src_port", "").strip(),
            "dst_port": request.args.get("dst_port", "").strip(),
        }
        traffic_entries, total_records = database.get_traffic(
            search=search,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
            page=page,
            per_page=per_page,
        )
        total_pages = max((total_records + per_page - 1) // per_page, 1)
        if page > total_pages:
            page = total_pages
            traffic_entries, total_records = database.get_traffic(
                search=search,
                filters=filters,
                sort_by=sort_by,
                sort_order=sort_order,
                page=page,
                per_page=per_page,
            )
        query_params = _active_query_params(
            search=search,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        return render_template(
            "traffic.html",
            traffic_entries=traffic_entries,
            filters=filters,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
            sort_urls=_traffic_sort_urls(sort_by, sort_order, query_params, page),
            total_records=total_records,
            page=page,
            total_pages=total_pages,
            has_previous=page > 1,
            has_next=page < total_pages,
            previous_url=url_for("traffic", **query_params, page=page - 1),
            next_url=url_for("traffic", **query_params, page=page + 1),
        )

    @app.route("/hosts")
    def hosts():
        database = get_database()
        return render_template("hosts.html", hosts=database.get_hosts())

    @app.route("/alerts")
    def alerts():
        database = get_database()
        return render_template("alerts.html", alerts=database.get_alerts())

    @app.route("/alerts/<int:alert_id>")
    def alert_detail(alert_id):
        database = get_database()
        alert = database.get_alert(alert_id)
        if alert is None:
            abort(404)
        details = _alert_details_payload(database, alert)
        return render_template(
            "alert_detail.html",
            alert=alert,
            details=details,
        )

    @app.route("/api/alerts/<int:alert_id>/details")
    def alert_details_api(alert_id):
        database = get_database()
        alert = database.get_alert(alert_id)
        if alert is None:
            abort(404)
        return jsonify(_alert_details_payload(database, alert))

    @app.route("/alerts/delete/<int:alert_id>", methods=["POST"])
    def delete_alert(alert_id):
        database = get_database()
        database.delete_alert(alert_id)
        return redirect(url_for("alerts"))

    @app.route("/alerts/delete-all", methods=["POST"])
    def delete_all_alerts():
        database = get_database()
        database.delete_all_alerts()
        return redirect(url_for("alerts"))

    @app.route("/alerts/export.csv")
    def export_alerts_csv():
        database = get_database()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "timestamp",
                "severity",
                "title",
                "description",
                "source_ip",
                "destination_ip",
                "context_json",
            ]
        )
        for alert in database.get_alerts():
            writer.writerow(
                [
                    alert["timestamp"],
                    alert["severity"],
                    alert["title"],
                    alert["description"] or "",
                    alert["source_ip"] or "",
                    alert["destination_ip"] or "",
                    alert["context_json"] or "",
                ]
            )
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=alerts.csv"},
        )

    @app.route("/alerts/export.json")
    def export_alerts_json():
        database = get_database()
        alerts = [
            {
                "timestamp": alert["timestamp"],
                "severity": alert["severity"],
                "title": alert["title"],
                "description": alert["description"] or "",
                "source_ip": alert["source_ip"],
                "destination_ip": alert["destination_ip"],
                "context": _parse_alert_context(alert["context_json"]),
            }
            for alert in database.get_alerts()
        ]
        return jsonify(alerts)

    @app.route("/dns")
    def dns_queries():
        database = get_database()
        page = _positive_int(request.args.get("page"), default=1)
        per_page = 100
        sort_by = request.args.get("sort_by", "timestamp")
        sort_order = request.args.get("sort_order", "DESC").upper()
        search = request.args.get("search", "").strip()
        rows, total_records = database.get_dns_queries(
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
            page=page,
            per_page=per_page,
        )
        total_pages = max((total_records + per_page - 1) // per_page, 1)
        if page > total_pages:
            page = total_pages
            rows, total_records = database.get_dns_queries(
                search=search,
                sort_by=sort_by,
                sort_order=sort_order,
                page=page,
                per_page=per_page,
            )
        query_params = _active_query_params(
            search=search,
            filters={},
            sort_by=sort_by,
            sort_order=sort_order,
        )
        return render_template(
            "dns.html",
            dns_queries=rows,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
            sort_urls=_sort_urls(
                "dns_queries",
                [
                    "timestamp",
                    "client_ip",
                    "dns_server_ip",
                    "query_name",
                    "query_type",
                    "dns_rcode",
                ],
                sort_by,
                sort_order,
                query_params,
                page,
            ),
            total_records=total_records,
            page=page,
            total_pages=total_pages,
            has_previous=page > 1,
            has_next=page < total_pages,
            previous_url=url_for("dns_queries", **query_params, page=page - 1),
            next_url=url_for("dns_queries", **query_params, page=page + 1),
        )

    @app.route("/domains")
    def domains():
        database = get_database()
        page = _positive_int(request.args.get("page"), default=1)
        per_page = 100
        sort_by = request.args.get("sort_by", "last_seen")
        sort_order = request.args.get("sort_order", "DESC").upper()
        search = request.args.get("search", "").strip()
        rows, total_records = database.get_domains(
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
            page=page,
            per_page=per_page,
        )
        total_pages = max((total_records + per_page - 1) // per_page, 1)
        if page > total_pages:
            page = total_pages
            rows, total_records = database.get_domains(
                search=search,
                sort_by=sort_by,
                sort_order=sort_order,
                page=page,
                per_page=per_page,
            )
        query_params = _active_query_params(
            search=search,
            filters={},
            sort_by=sort_by,
            sort_order=sort_order,
        )
        return render_template(
            "domains.html",
            domains=rows,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
            sort_urls=_sort_urls(
                "domains",
                ["domain", "first_seen", "last_seen", "query_count"],
                sort_by,
                sort_order,
                query_params,
                page,
            ),
            total_records=total_records,
            page=page,
            total_pages=total_pages,
            has_previous=page > 1,
            has_next=page < total_pages,
            previous_url=url_for("domains", **query_params, page=page - 1),
            next_url=url_for("domains", **query_params, page=page + 1),
        )

    @app.route("/domains/log")
    def download_domains_log():
        runtime_data_dir = Path(os.environ.get("EXCALIBUR_DATA_DIR", Path.cwd() / "data"))
        log_path = (runtime_data_dir / "domains.log").resolve()
        if not log_path.exists():
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text("", encoding="utf-8")
        return send_file(log_path, as_attachment=True, download_name="domains.log")

    @app.route("/browser")
    @app.route("/domain-risk")
    def domain_risk():
        database = get_database()
        page = _positive_int(request.args.get("page"), default=1)
        per_page = 100
        sort_by = request.args.get("sort_by", "risk_score")
        sort_order = request.args.get("sort_order", "DESC").upper()
        search = request.args.get("search", "").strip()
        risk_level = request.args.get("risk_level", "").strip()
        rows, total_records = database.get_domain_risk(
            search=search,
            risk_level=risk_level,
            sort_by=sort_by,
            sort_order=sort_order,
            page=page,
            per_page=per_page,
        )
        total_pages = max((total_records + per_page - 1) // per_page, 1)
        if page > total_pages:
            page = total_pages
            rows, total_records = database.get_domain_risk(
                search=search,
                risk_level=risk_level,
                sort_by=sort_by,
                sort_order=sort_order,
                page=page,
                per_page=per_page,
            )
        filters = {"risk_level": risk_level}
        query_params = _active_query_params(
            search=search,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        return render_template(
            "browser.html",
            domains=rows,
            search=search,
            risk_level=risk_level,
            sort_by=sort_by,
            sort_order=sort_order,
            sort_urls=_sort_urls(
                "domain_risk",
                ["domain", "risk_score", "risk_level", "first_seen", "last_seen", "query_count"],
                sort_by,
                sort_order,
                query_params,
                page,
            ),
            total_records=total_records,
            page=page,
            total_pages=total_pages,
            has_previous=page > 1,
            has_next=page < total_pages,
            previous_url=url_for("domain_risk", **query_params, page=page - 1),
            next_url=url_for("domain_risk", **query_params, page=page + 1),
        )

    @app.route("/system")
    def system_health():
        database = get_database()
        system = database.get_system_health()
        if request.args.get("format") == "json":
            return jsonify(system)
        return render_template("system.html", system=system)

    @app.route("/settings", methods=["GET", "POST"])
    def settings():
        config = get_config()
        saved = False
        rules_saved = False
        error = None
        rules_error = None
        rules_text = _read_rules_text()
        if request.method == "POST":
            action = request.form.get("action", "save_settings")
            if action == "save_rules":
                submitted_rules = request.form.get("rules_yaml", "")
                try:
                    RulesConfig.validate(submitted_rules)
                except ValueError as exc:
                    rules_error = str(exc)
                    rules_text = submitted_rules
                else:
                    Path(current_app.config["RULES_PATH"]).write_text(
                        submitted_rules,
                        encoding="utf-8",
                    )
                    rules_text = submitted_rules
                    rules_saved = True
            else:
                timezone_name = request.form.get("timezone", "").strip()
                excluded_sources = _parse_multiline_values(
                    request.form.get("excluded_sources", "")
                )
                if timezone_name not in Config.SUPPORTED_TIMEZONES:
                    error = "Unsupported timezone."
                else:
                    config["general"]["timezone"] = timezone_name
                    config["portscan"]["excluded_sources"] = excluded_sources
                    config["notifications"] = {
                        "enabled": request.form.get("notifications_enabled") == "on",
                        "desktop": {
                            "enabled": request.form.get("desktop_enabled") == "on",
                        },
                        "ntfy": {
                            "enabled": request.form.get("ntfy_enabled") == "on",
                            "url": request.form.get("ntfy_url", "").strip(),
                            "timeout_seconds": _positive_int(
                                request.form.get("ntfy_timeout_seconds"),
                                default=5,
                            ),
                        },
                    }
                    Config.save(config, current_app.config["CONFIG_PATH"])
                    g.app_config = config
                    return redirect(url_for("settings", saved="1"))

        saved = request.args.get("saved") == "1"
        notifications = Config._merge_notifications(config.get("notifications", {}))
        return render_template(
            "settings.html",
            current_timezone=config["general"]["timezone"],
            excluded_sources="\n".join(config["portscan"].get("excluded_sources", [])),
            notifications=notifications,
            supported_timezones=Config.SUPPORTED_TIMEZONES,
            saved=saved,
            rules_saved=rules_saved,
            error=error,
            rules_error=rules_error,
            rules_text=rules_text,
        )

    @app.route("/api/notifications/test", methods=["POST"])
    def test_notification():
        success, error_message = get_notification_manager().send_test_notification()
        if success:
            return jsonify({"success": True})
        return jsonify({"success": False, "error": error_message or "Test notification failed."}), 500

    @app.route("/rules")
    def rules():
        database = get_database()
        saved = request.args.get("saved") == "1"
        updated = request.args.get("updated") == "1"
        imported = request.args.get("imported") == "1"
        selected_pack = _normalize_pack_name(
            request.args.get("pack") or request.args.get("category")
        )
        severity_filter = request.args.get("severity", "").strip()
        state_filter = request.args.get("state", "").strip()
        search = request.args.get("search", "").strip()
        pack_overview = _rule_pack_overview()
        try:
            pack_data = _load_rule_pack(selected_pack)
            validation_error = _validate_rule_pack_text(pack_data["text"], selected_pack)
        except SignatureValidationError as exc:
            pack_path = _rule_pack_path(selected_pack)
            pack_data = {
                "pack": selected_pack,
                "path": pack_path,
                "text": pack_path.read_text(encoding="utf-8"),
                "signatures": [],
            }
            validation_error = str(exc)
        stats = _rule_stats_map(database)
        rules = _rules_for_display(pack_data["signatures"], selected_pack, stats)
        filtered_rules = _filter_rules(
            rules,
            search=search,
            severity=severity_filter,
            state=state_filter,
        )
        summary = _rule_summary_from_packs(pack_overview)

        return render_template(
            "rules.html",
            packs=pack_overview,
            selected_pack=selected_pack,
            selected_pack_label=_pack_label(selected_pack),
            rules=filtered_rules,
            pack_text=pack_data["text"],
            summary=summary,
            search=search,
            severity_filter=severity_filter,
            state_filter=state_filter,
            validation_valid=validation_error is None,
            saved=saved,
            updated=updated,
            imported=imported,
            error=validation_error,
        )

    @app.route("/plugins")
    def plugins():
        return render_template(
            "plugins.html",
            plugins=_plugin_overview(),
            updated=request.args.get("updated") == "1",
        )

    @app.route("/sensor/status")
    def sensor_status():
        try:
            status = get_service_controller().status()
        except ServiceControllerError:
            status = "unknown"
        return jsonify({"status": status})

    @app.route("/sensor/restart", methods=["POST"])
    def sensor_restart():
        try:
            get_service_controller().restart()
        except ServiceControllerError as exc:
            return jsonify({"success": False, "error": str(exc)}), 500
        return jsonify({"success": True})

    @app.route("/plugins/toggle/<plugin_id>", methods=["POST"])
    def toggle_plugin(plugin_id):
        plugin = _plugin_by_id(plugin_id)
        if plugin is None:
            abort(404)
        _write_plugin_enabled(plugin["path"], not plugin["enabled"])
        return redirect(url_for("plugins", updated="1"))

    @app.route("/rules/save", methods=["POST"])
    def save_rules_pack():
        selected_pack = _normalize_pack_name(request.form.get("pack"))
        pack_text = request.form.get("pack_yaml", "")
        try:
            parsed = SignatureEngine.parse(
                pack_text,
                source_name=_pack_file_name(selected_pack),
                allow_empty=True,
            )
        except SignatureValidationError as exc:
            database = get_database()
            pack_overview = _rule_pack_overview()
            stats = _rule_stats_map(database)
            rules = _rules_for_display(
                _best_effort_rule_pack_parse(pack_text),
                selected_pack,
                stats,
            )
            return render_template(
                "rules.html",
                packs=pack_overview,
                selected_pack=selected_pack,
                selected_pack_label=_pack_label(selected_pack),
                rules=rules,
                pack_text=pack_text,
                summary=_rule_summary_from_packs(pack_overview),
                search="",
                severity_filter="",
                state_filter="",
                validation_valid=False,
                saved=False,
                updated=False,
                imported=False,
                error=str(exc),
            )

        _rule_pack_path(selected_pack).write_text(
            SignatureEngine.to_yaml(parsed, allow_empty=True),
            encoding="utf-8",
        )
        return redirect(url_for("rules", pack=selected_pack, saved="1"))

    @app.route("/rules/export/<pack>")
    def export_rules_pack(pack):
        selected_pack = _normalize_pack_name(pack)
        pack_path = _rule_pack_path(selected_pack)
        return send_file(
            pack_path,
            as_attachment=True,
            download_name=pack_path.name,
            mimetype="application/x-yaml",
        )

    @app.route("/rules/import", methods=["POST"])
    def import_rules_pack():
        selected_pack = _normalize_pack_name(request.form.get("pack"))
        upload = request.files.get("pack_file")
        if upload is None or not upload.filename:
            return _render_rules_import_error(
                selected_pack,
                "Select a YAML rule pack file to import.",
            )
        try:
            pack_text = upload.read().decode("utf-8")
        except UnicodeDecodeError:
            return _render_rules_import_error(
                selected_pack,
                "Imported rule pack must be UTF-8 text.",
            )
        try:
            parsed = SignatureEngine.parse(
                pack_text,
                source_name=_pack_file_name(selected_pack),
                allow_empty=True,
            )
        except SignatureValidationError as exc:
            return _render_rules_import_error(selected_pack, str(exc), pack_text=pack_text)

        _rule_pack_path(selected_pack).write_text(
            SignatureEngine.to_yaml(parsed, allow_empty=True),
            encoding="utf-8",
        )
        return redirect(url_for("rules", pack=selected_pack, imported="1"))

    @app.route("/rules/format", methods=["POST"])
    def format_rules_pack():
        selected_pack = _normalize_pack_name(request.form.get("pack"))
        pack_text = request.form.get("pack_yaml", "")
        try:
            parsed = SignatureEngine.parse(
                pack_text,
                source_name=_pack_file_name(selected_pack),
                allow_empty=True,
            )
        except SignatureValidationError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify(
            {
                "ok": True,
                "formatted": SignatureEngine.to_yaml(parsed, allow_empty=True),
            }
        )

    @app.route("/rules/toggle/<pack>/<int:rule_index>", methods=["POST"])
    def toggle_rule(pack, rule_index):
        selected_pack = _normalize_pack_name(pack)
        pack_data = _load_rule_pack(selected_pack)
        signatures = pack_data["signatures"]
        if 0 <= rule_index < len(signatures):
            signatures[rule_index]["enabled"] = not signatures[rule_index].get("enabled", True)
            _rule_pack_path(selected_pack).write_text(
                SignatureEngine.to_yaml({"signatures": signatures}, allow_empty=True),
                encoding="utf-8",
            )
            return redirect(url_for("rules", pack=selected_pack, updated="1"))
        return redirect(url_for("rules", pack=selected_pack))

    @app.route("/rules/<pack>/<int:rule_index>")
    def rule_detail(pack, rule_index):
        selected_pack = _normalize_pack_name(pack)
        pack_data = _load_rule_pack(selected_pack)
        signatures = pack_data["signatures"]
        if rule_index < 0 or rule_index >= len(signatures):
            return redirect(url_for("rules", pack=selected_pack))
        stats = _rule_stats_map(get_database())
        rule = _rules_for_display(signatures, selected_pack, stats)[rule_index]
        rule_yaml = SignatureEngine.to_yaml(
            {"signatures": [signatures[rule_index]]},
            allow_empty=True,
        )
        return render_template(
            "rule_detail.html",
            rule=rule,
            selected_pack=selected_pack,
            selected_pack_label=_pack_label(selected_pack),
            rule_yaml=rule_yaml,
        )

    @app.route("/signatures")
    def signatures():
        return redirect(url_for("rules"))

    @app.route("/signatures/save", methods=["POST"])
    def save_signatures():
        return redirect(url_for("rules"))

    @app.route("/settings/signatures")
    def legacy_signature_settings():
        return redirect(url_for("rules"))

    @app.route("/debug/portscan")
    def debug_portscan():
        database = get_database()
        return render_template(
            "debug_portscan.html",
            sources=database.get_portscan_debug_state(),
        )

    return app


def get_database():
    if "database" not in g:
        g.database = Database(current_app.config["DATABASE_PATH"])
    return g.database


def get_config():
    if "app_config" not in g:
        g.app_config = Config.load(current_app.config["CONFIG_PATH"])
    return g.app_config


def get_notification_manager():
    configured_manager = current_app.config.get("NOTIFICATION_MANAGER")
    if configured_manager is not None:
        return configured_manager
    return NotificationManager(get_config())


def get_service_controller():
    return current_app.config["SERVICE_CONTROLLER"]


def _read_rules_text():
    rules_path = Path(current_app.config["RULES_PATH"])
    if not rules_path.exists():
        RulesConfig.create_default(rules_path)
    return rules_path.read_text(encoding="utf-8")


RULE_PACK_LABELS = {
    "recon": "Recon",
    "dns": "DNS",
    "ad": "AD",
    "databases": "Databases",
    "web": "Web",
    "browser": "Browser",
}


def _rules_dir():
    rules_dir = Path(current_app.config["RULE_PACKS_PATH"])
    SignatureEngine.create_default_rule_packs(rules_dir)
    return rules_dir


def _plugins_dir():
    if "EXCALIBUR_PLUGINS_DIR" in os.environ:
        return platform_plugins_dir().resolve()
    return (Path(current_app.config["CONFIG_PATH"]).resolve().parent / "plugins").resolve()


def _resolve_rule_packs_path(rule_packs_path, config_path):
    rules_dir = Path(rule_packs_path)
    if rules_dir.is_absolute():
        return str(rules_dir)
    return str((Path(config_path).resolve().parent / rules_dir).resolve())


def _normalize_pack_name(pack):
    pack = str(pack or "recon").replace(".yaml", "").strip().lower()
    if pack not in RULE_PACK_LABELS:
        return "recon"
    return pack


def _pack_file_name(pack):
    return f"{_normalize_pack_name(pack)}.yaml"


def _pack_label(pack):
    return RULE_PACK_LABELS[_normalize_pack_name(pack)]


def _rule_pack_path(pack):
    return _rules_dir() / _pack_file_name(pack)


def _load_rule_pack(pack):
    pack = _normalize_pack_name(pack)
    path = _rule_pack_path(pack)
    text = path.read_text(encoding="utf-8")
    parsed = SignatureEngine.parse(
        text,
        source_name=path.name,
        allow_empty=True,
    )
    return {
        "pack": pack,
        "path": path,
        "text": text,
        "signatures": parsed.get("signatures", []),
    }


def _rule_pack_overview():
    packs = []
    for pack in RULE_PACK_LABELS:
        try:
            pack_data = _load_rule_pack(pack)
            count = len(pack_data["signatures"])
            error = None
        except SignatureValidationError as exc:
            count = 0
            error = str(exc)
        packs.append(
            {
                "name": pack,
                "label": _pack_label(pack),
                "file_name": _pack_file_name(pack),
                "count": count,
                "error": error,
            }
        )
    return packs


def _plugin_overview():
    plugins = []
    plugins_dir = _plugins_dir()
    if not plugins_dir.exists():
        return plugins

    for plugin_dir in sorted(path for path in plugins_dir.iterdir() if path.is_dir()):
        metadata_path = plugin_dir / "plugin.yaml"
        metadata = _load_plugin_metadata(metadata_path)
        if metadata is None:
            continue
        plugins.append(
            {
                "name": str(metadata.get("name") or plugin_dir.name),
                "id": str(metadata.get("id") or plugin_dir.name),
                "version": str(metadata.get("version") or ""),
                "author": str(metadata.get("author") or ""),
                "description": str(metadata.get("description") or ""),
                "enabled": bool(metadata.get("enabled", True)),
                "path": metadata_path,
            }
        )
    return plugins


def _plugin_by_id(plugin_id):
    normalized_id = _normalize_plugin_id(plugin_id)
    if normalized_id is None:
        return None
    for plugin in _plugin_overview():
        if plugin["id"] == normalized_id:
            return plugin
    return None


def _normalize_plugin_id(plugin_id):
    plugin_id = str(plugin_id or "").strip()
    if not plugin_id:
        return None
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
    if any(character not in allowed for character in plugin_id):
        return None
    return plugin_id


def _load_plugin_metadata(metadata_path):
    if not metadata_path.exists() or not metadata_path.is_file():
        return None
    data = {}
    for raw_line in metadata_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = _parse_plugin_metadata_scalar(value.strip())
    return data


def _write_plugin_enabled(metadata_path, enabled):
    replacement = f"enabled: {'true' if enabled else 'false'}"
    lines = metadata_path.read_text(encoding="utf-8").splitlines()
    updated_lines = []
    replaced = False
    for line in lines:
        if line.strip().startswith("enabled:"):
            updated_lines.append(replacement)
            replaced = True
        else:
            updated_lines.append(line)
    if not replaced:
        updated_lines.append(replacement)
    metadata_path.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")


def _parse_plugin_metadata_scalar(value):
    if value == "":
        return ""
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _rules_for_display(signatures, pack, stats):
    rules = []
    for index, signature in enumerate(signatures):
        alert = signature.get("alert", {})
        rule_stats = stats.get(signature.get("name", ""), {})
        rules.append(
            {
                "index": index,
                "pack": pack,
                "pack_label": _pack_label(pack),
                "enabled": signature.get("enabled", True),
                "name": signature.get("name", f"Rule {index + 1}"),
                "severity": alert.get("severity", ""),
                "description": alert.get("description", ""),
                "tags": signature.get("tags", []),
                "cooldown_seconds": signature.get("cooldown_seconds", 0),
                "group_by": signature.get("group_by", ""),
                "hits": int(rule_stats.get("hits", 0)),
                "alerts": int(rule_stats.get("alerts_generated", 0)),
                "last_triggered": rule_stats.get("last_triggered"),
                "raw": signature,
            }
        )
    return rules


def _filter_rules(rules, search, severity, state):
    filtered = rules
    if search:
        lowered = search.lower()
        filtered = [rule for rule in filtered if lowered in rule["name"].lower()]
    if severity:
        filtered = [rule for rule in filtered if rule["severity"] == severity]
    if state == "enabled":
        filtered = [rule for rule in filtered if rule["enabled"]]
    elif state == "disabled":
        filtered = [rule for rule in filtered if not rule["enabled"]]
    return filtered


def _rule_stats_map(database):
    return {
        row["rule_name"]: {
            "hits": row["hits"],
            "alerts_generated": row["alerts_generated"],
            "last_triggered": row["last_triggered"],
        }
        for row in database.get_rule_stats()
    }


def _rule_summary_from_packs(packs):
    total = sum(pack["count"] for pack in packs)
    enabled = 0
    for pack in packs:
        if pack["error"]:
            continue
        try:
            enabled += sum(
                1
                for signature in _load_rule_pack(pack["name"])["signatures"]
                if signature.get("enabled", True)
            )
        except SignatureValidationError:
            continue
    return {
        "total": total,
        "enabled": enabled,
        "disabled": total - enabled,
    }


def _rules_summary(database):
    packs = _rule_pack_overview()
    summary = _rule_summary_from_packs(packs)
    top_triggered = sorted(
        [
            {
                "name": row["rule_name"],
                "hits": int(row["hits"]),
                "alerts": int(row["alerts_generated"]),
            }
            for row in database.get_rule_stats()
        ],
        key=lambda row: row["hits"],
        reverse=True,
    )[:3]
    summary["top_triggered"] = top_triggered
    return summary


def _dashboard_metrics(database, system_health=None):
    system_health = system_health or database.get_system_health()
    timezone_name = get_config()["general"]["timezone"]
    start_utc, end_utc = _local_day_utc_window(timezone_name)
    return {
        "sensor_status": _sensor_status_value(),
        "alerts_today": database.count_alerts_between(start_utc, end_utc),
        "total_alerts": database.count_alerts(),
        "rule_hits": database.get_total_rule_hits(),
        "hosts_seen": database.count_hosts(),
        "dns_queries_today": database.count_dns_queries_between(start_utc, end_utc),
        "packets_processed": system_health["writes"]["traffic_records_written"],
        "dns_queries": system_health["database"]["dns_queries"],
        "traffic_records": system_health["database"]["traffic_records"],
        "alerts_generated": system_health["writes"]["alerts_written"],
    }


def _dashboard_alert_trend(database, days=7):
    timezone_name = get_config()["general"]["timezone"]
    timeline_anchor = _latest_alert_local(database, timezone_name)
    if timeline_anchor is None:
        timeline_anchor = datetime.now(_resolve_timezone(timezone_name))
    today_start_local = timeline_anchor.replace(hour=0, minute=0, second=0, microsecond=0)
    trend = []
    for offset in range(days - 1, -1, -1):
        day_start_local = today_start_local - timedelta(days=offset)
        day_end_local = day_start_local + timedelta(days=1)
        start_utc = day_start_local.astimezone(timezone.utc).isoformat()
        end_utc = day_end_local.astimezone(timezone.utc).isoformat()
        trend.append(
            {
                "label": day_start_local.strftime("%a"),
                "date": day_start_local.strftime("%Y-%m-%d"),
                "count": database.count_alerts_between(start_utc, end_utc),
            }
        )
    return trend


def _latest_alert_local(database, timezone_name):
    row = database.connection.execute("SELECT MAX(timestamp) FROM alerts").fetchone()
    timestamp = row[0] if row else None
    if not timestamp:
        return None
    parsed = datetime.fromisoformat(str(timestamp))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(_resolve_timezone(timezone_name))


def _dashboard_top_rules(database, limit=10):
    return [
        {
            "rule_name": row["rule_name"],
            "hits": int(row["hits"]),
            "alerts": int(row["alerts_generated"]),
            "last_triggered": row["last_triggered"],
        }
        for row in database.get_top_rule_stats(limit=limit)
    ]


def _dashboard_top_sources(database, limit=10):
    return [
        {
            "source_ip": row["source_ip"],
            "alert_count": int(row["alert_count"]),
        }
        for row in database.get_top_alert_sources(limit=limit)
    ]


def _local_day_utc_window(timezone_name):
    now_local = datetime.now(_resolve_timezone(timezone_name))
    day_start_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    day_end_local = day_start_local + timedelta(days=1)
    return (
        day_start_local.astimezone(timezone.utc).isoformat(),
        day_end_local.astimezone(timezone.utc).isoformat(),
    )


def _sensor_status_value():
    try:
        return get_service_controller().status()
    except ServiceControllerError:
        return "unknown"


def _validate_rule_pack_text(text, pack):
    try:
        SignatureEngine.parse(
            text,
            source_name=_pack_file_name(pack),
            allow_empty=True,
        )
    except SignatureValidationError as exc:
        return str(exc)
    return None


def _best_effort_rule_pack_parse(text):
    try:
        return SignatureEngine.parse(text, allow_empty=True).get("signatures", [])
    except SignatureValidationError:
        return []


def _render_rules_import_error(selected_pack, error_message, pack_text=None):
    database = get_database()
    pack_overview = _rule_pack_overview()
    stats = _rule_stats_map(database)
    effective_text = (
        pack_text
        if pack_text is not None
        else _rule_pack_path(selected_pack).read_text(encoding="utf-8")
    )
    return render_template(
        "rules.html",
        packs=pack_overview,
        selected_pack=selected_pack,
        selected_pack_label=_pack_label(selected_pack),
        rules=_rules_for_display(
            _best_effort_rule_pack_parse(effective_text),
            selected_pack,
            stats,
        ),
        pack_text=effective_text,
        summary=_rule_summary_from_packs(pack_overview),
        search="",
        severity_filter="",
        state_filter="",
        validation_valid=False,
        saved=False,
        updated=False,
        imported=False,
        error=error_message,
    )


def _parse_alert_context(context_json):
    if not context_json:
        return {}
    try:
        parsed = json.loads(context_json)
    except (TypeError, ValueError):
        return {"raw": context_json}
    if isinstance(parsed, dict):
        return parsed
    return {"value": parsed}


EVIDENCE_LABELS = {
    "unique_dst_ports": "Observed Unique Ports",
    "unique_dst_ips": "Observed Unique Hosts",
    "unique_domains": "Observed Unique Domains",
    "dns_queries": "Observed DNS Queries",
    "dst_port": "Destination Port",
    "group_by": "Group By",
    "domain": "Observed Domain",
    "risk_score": "Observed Risk Score",
    "risk_level": "Observed Risk Level",
    "reasons": "Risk Reasons",
}


def _alert_details_payload(database, alert):
    context = _parse_alert_context(alert["context_json"])
    rule_context = context.get("rule", {})
    evidence_context = context.get("evidence", {})
    observed = evidence_context.get("observed")
    thresholds = evidence_context.get("thresholds")
    if observed is None and thresholds is None:
        observed, thresholds, window_seconds = _legacy_evidence_snapshot(context)
    else:
        window_seconds = evidence_context.get("window_seconds")
    source_ip = alert["source_ip"]
    return {
        "alert": {
            "id": alert["id"],
            "timestamp": alert["timestamp"],
            "severity": alert["severity"],
            "title": alert["title"],
            "description": alert["description"],
            "source_ip": source_ip,
            "destination_ip": alert["destination_ip"],
        },
        "rule": {
            "name": rule_context.get("name") or alert["title"],
            "pack": rule_context.get("pack") or "unknown",
            "tags": rule_context.get("tags", []),
            "event_type": rule_context.get("event_type") or "unknown",
        },
        "evidence": _build_evidence_rows(observed, thresholds, window_seconds),
        "related_activity": {
            "alerts": [
                {
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "severity": row["severity"],
                    "title": row["title"],
                    "source_ip": row["source_ip"],
                    "destination_ip": row["destination_ip"],
                }
                for row in database.get_recent_alerts_for_source(
                    source_ip,
                    exclude_alert_id=alert["id"],
                    limit=20,
                )
            ],
            "dns_queries": [
                {
                    "timestamp": row["timestamp"],
                    "client_ip": row["client_ip"],
                    "dns_server_ip": row["dns_server_ip"],
                    "query_name": row["query_name"],
                    "query_type": row["query_type"],
                    "dns_rcode": row["dns_rcode"],
                }
                for row in database.get_recent_dns_queries_for_source(source_ip, limit=20)
            ],
            "traffic": [
                {
                    "timestamp": row["timestamp"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dst_ip"],
                    "protocol": row["protocol"],
                    "src_port": row["src_port"],
                    "dst_port": row["dst_port"],
                    "packet_size": row["packet_size"],
                    "packet_count": row["packet_count"],
                    "byte_count": row["byte_count"],
                }
                for row in database.get_recent_traffic_for_source(source_ip, limit=20)
            ],
        },
    }


def _legacy_evidence_snapshot(context):
    observed = {}
    thresholds = {}
    window_seconds = context.get("window_seconds")
    legacy_threshold_map = {
        "unique_dst_ports": "unique_dst_ports",
        "unique_dst_ips": "unique_dst_ips",
        "unique_domains": "unique_domains",
        "dns_queries": "dns_queries",
        "dst_port": "dst_port",
    }
    for key, label_key in legacy_threshold_map.items():
        if key in context:
            observed[label_key] = context[key]
    return observed, thresholds, window_seconds


def _build_evidence_rows(observed, thresholds, window_seconds):
    rows = []
    observed = observed or {}
    thresholds = thresholds or {}
    for key, value in observed.items():
        rows.append({"label": EVIDENCE_LABELS.get(key, key.replace("_", " ").title()), "value": value})
        if key in thresholds:
            rows.append({"label": "Threshold", "value": thresholds[key]})
    if window_seconds is not None:
        rows.append({"label": "Window", "value": f"{window_seconds} seconds"})
    return rows


def _signature_summary(signatures_text):
    try:
        parsed = SignatureEngine.parse(signatures_text)
    except SignatureValidationError as exc:
        return {"total": 0, "enabled": 0, "disabled": 0}, str(exc)

    signatures = parsed.get("signatures", [])
    enabled_count = sum(1 for signature in signatures if signature.get("enabled", True))
    total_count = len(signatures)
    return (
        {
            "total": total_count,
            "enabled": enabled_count,
            "disabled": total_count - enabled_count,
        },
        None,
    )


def format_local_time(value):
    if value in (None, ""):
        return ""
    timezone_name = get_config()["general"].get("timezone", "Asia/Amman")
    target_timezone = _resolve_timezone(timezone_name)

    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return value

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(target_timezone).strftime("%Y-%m-%d %H:%M:%S %Z")


def _resolve_timezone(timezone_name):
    try:
        return ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        logger.warning(
            "Time zone %r is unavailable; falling back to UTC. "
            "Install the tzdata package when system time zone data is unavailable.",
            timezone_name,
        )
        return timezone.utc


def _positive_int(value, default):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _parse_multiline_values(value):
    return [line.strip() for line in value.splitlines() if line.strip()]


def _active_query_params(search, filters, sort_by, sort_order):
    params = {}
    if search:
        params["search"] = search
    for key, value in filters.items():
        if value:
            params[key] = value
    if sort_by:
        params["sort_by"] = sort_by
    if sort_order:
        params["sort_order"] = sort_order
    return params


def _traffic_sort_urls(current_sort_by, current_sort_order, query_params, page):
    columns = [
        "timestamp",
        "first_seen",
        "last_seen",
        "src_ip",
        "dst_ip",
        "protocol",
        "src_port",
        "dst_port",
        "service",
        "packet_size",
        "packet_count",
        "byte_count",
    ]
    return _sort_urls("traffic", columns, current_sort_by, current_sort_order, query_params, page)


def _sort_urls(endpoint, columns, current_sort_by, current_sort_order, query_params, page):
    urls = {}
    for column in columns:
        next_order = "ASC"
        if current_sort_by == column and current_sort_order == "ASC":
            next_order = "DESC"

        params = {
            **query_params,
            "sort_by": column,
            "sort_order": next_order,
            "page": page,
        }
        urls[column] = url_for(endpoint, **params)
    return urls


app = create_app()
