import threading
import queue
import logging
import datetime
import os

from modules import dns_recon, network_scan, web_recon, data_extract
from utils import report_gen, visual
from config import OUTPUT_DIR


class ReconOrchestrator:
    def __init__(self, ui_queue: queue.Queue):
        self.ui_queue = ui_queue
        self.results = {}
        self.scan_thread = None
        self.is_running = False
        self.logger = logging.getLogger("auto_recon.orchestrator")

    def _log(self, message: str, level: str = "info"):
        level_name = str(level).lower()
        prefix_map = {
            "info": "[+]",
            "success": "[+]",
            "error": "[-]",
            "status": "[*]",
            "done": "[*]",
            "warning": "[~]",
        }
        log_map = {
            "info": logging.INFO,
            "success": logging.INFO,
            "error": logging.ERROR,
            "status": logging.INFO,
            "done": logging.INFO,
            "warning": logging.WARNING,
        }

        prefix = prefix_map.get(level_name, "[+]")

        if self.ui_queue is not None:
            try:
                self.ui_queue.put(f"{prefix} {message}")
            except Exception:
                pass

        self.logger.log(log_map.get(level_name, logging.INFO), "%s %s", prefix, message)

    def start_scan(self, domain: str, ip: str, profile: str = "Quick") -> bool:
        if self.is_running:
            if self.ui_queue is not None:
                try:
                    self.ui_queue.put("[-] Scan already in progress")
                except Exception:
                    pass
            self.logger.error("Scan already in progress")
            return False

        self.is_running = True
        self.results = {}
        self.scan_thread = threading.Thread(
            target=self._run_modules,
            args=(domain, ip, profile),
            daemon=True,
        )
        self.scan_thread.start()
        self._log(f"Scan started for {domain} using profile '{profile}'", "status")
        return True

    def _run_modules(self, domain: str, ip: str, profile: str):
        start_time = datetime.datetime.now()
        self.results["metadata"] = {
            "domain": domain,
            "ip": ip,
            "profile": profile,
            "started_at": start_time.isoformat(),
        }

        self._log(f"Starting recon workflow for {domain}", "status")

        try:
            dns_result = self._safe_run_module("DNS Recon", lambda: dns_recon.run(domain))
            self.results["dns"] = dns_result

            if not dns_result.get("success", False):
                self._log("DNS recon did not complete successfully; continuing with remaining checks.", "warning")

            network_result = self._safe_run_module(
                "Network Scan",
                lambda: network_scan.run(ip, profile=profile),
            )
            self.results["network"] = network_result

            web_result = self._safe_run_module(
                "Web Recon",
                lambda: web_recon.run(domain, profile=profile),
            )
            self.results["web"] = web_result

            data_result = self._safe_run_module(
                "Data Extract",
                lambda: data_extract.run(domain, ip, profile=profile),
            )
            self.results["data"] = data_result

            os.makedirs(OUTPUT_DIR, exist_ok=True)
            report_path = os.path.join(
                OUTPUT_DIR,
                f"report_{domain}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            )
            report_result = self._safe_run_module(
                "Report Generation",
                lambda: report_gen.generate_report(self.results, domain, report_path),
            )
            self.results["report"] = report_result

            visualization_result = self._safe_run_module(
                "Visualization",
                lambda: visual.generate_dashboard(self.results, OUTPUT_DIR),
            )
            self.results["visual"] = visualization_result

            finish_time = datetime.datetime.now()
            self.results["metadata"]["finished_at"] = finish_time.isoformat()
            self.results["metadata"]["duration_seconds"] = round(
                (finish_time - start_time).total_seconds(),
                2,
            )

            self._log(f"Recon completed successfully for {domain}", "done")

        except Exception as exc:
            self._log(f"Unhandled orchestration failure: {exc}", "error")
            self.results["error"] = {
                "message": str(exc),
                "timestamp": datetime.datetime.now().isoformat(),
            }

        finally:
            self.is_running = False
            self._log(f"Recon workflow finished for {domain}", "status")

    def _safe_run_module(self, module_name: str, action):
        try:
            result = action()
            if result is None:
                result = {"success": True, "message": f"{module_name} completed without explicit output."}
            if isinstance(result, dict) and "success" not in result:
                result["success"] = True
            self._log(f"{module_name} completed successfully.", "info")
            return result
        except Exception as exc:
            self._log(f"{module_name} failed: {exc}", "error")
            return {"success": False, "error": str(exc), "module": module_name}
