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
        self._stop_event = threading.Event()
        self.logger = logging.getLogger("ReconOrchestrator")

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
        queue_message = f"{prefix} {message}"

        if self.ui_queue is not None:
            try:
                self.ui_queue.put(queue_message)
            except Exception:
                pass

        self.logger.log(log_map.get(level_name, logging.INFO), queue_message)

    def start_scan(self, domain: str, ip: str, profile: str = "Quick") -> bool:
        if self.is_running:
            self._log("Scan already in progress", "error")
            return False

        self.is_running = True
        self._stop_event.clear()
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
        try:
            self._log(f"[*] Starting DNS recon for {domain}", "status")
            dns_result = dns_recon.run(domain)
            self.results["dns_recon"] = dns_result
            self._log("[+] DNS recon complete", "info")

            if self._stop_event.is_set():
                self._log("[~] Scan stop requested — finishing current module", "warning")
                return

            self._log(f"[+] Web recon complete — tech stack and WHOIS retrieved", "info")
            web_result = web_recon.get_web_summary(f"https://{domain}", domain)
            self.results["web_recon"] = web_result

            if self._stop_event.is_set():
                self._log("[~] Scan stop requested — finishing current module", "warning")
                return

            emails = []
            js_files = []
            js_findings = []

            sensitive_data = data_extract.extract_sensitive_data(f"https://{domain}")
            http_headers_result = data_extract.get_http_headers(f"https://{domain}")
            security_headers = data_extract.check_security_headers(http_headers_result)

            if isinstance(sensitive_data, dict):
                emails = sensitive_data.get("emails", [])
                js_files = sensitive_data.get("js_files", [])

            if isinstance(http_headers_result, dict):
                if "http_headers" in http_headers_result:
                    http_headers_result = http_headers_result["http_headers"]

            for js_url in js_files:
                try:
                    findings = data_extract.analyze_js_file(js_url)
                    if findings:
                        js_findings.extend(findings)
                except Exception as exc:
                    self._log(f"[-] JS file analysis failed for {js_url}: {exc}", "error")

            self.results["data_extract"] = {
                "emails": emails,
                "js_files": js_files,
                "http_headers": http_headers_result,
                "security_headers": security_headers,
                "js_findings": js_findings,
            }
            self._log(f"[+] Data extraction complete — {len(emails)} emails, {len(js_findings)} JS findings", "info")

            if profile == "Full":
                if ip is not None:
                    network_result = network_scan.get_network_summary(ip)
                    self.results["network_scan"] = network_result
                    open_ports = network_result.get("open_ports", []) if isinstance(network_result, dict) else []
                    self._log(f"[+] Network scan complete — {len(open_ports)} open ports found", "info")
                else:
                    self._log("[~] Skipping network scan — no IP resolved", "warning")

                try:
                    screenshot_path = visual.take_screenshot(f"https://{domain}")
                    self.results["screenshot"] = screenshot_path
                    self._log("[+] Screenshot captured", "info")
                except Exception as exc:
                    self.results["screenshot"] = None
                    self._log(f"[-] Screenshot failed: {exc}", "error")

            self.results.update(
                {
                    "domain": domain,
                    "ip": ip,
                    "profile": profile,
                    "scan_time": datetime.datetime.now().isoformat(),
                    "status": "complete",
                }
            )

            try:
                report_gen.generate_pdf(self.results, domain)
                self._log("[+] PDF report generated successfully", "success")
            except Exception as exc:
                self._log(f"[-] PDF generation failed: {exc}", "error")

            try:
                report_gen.generate_csv(self.results, domain)
                self._log("[+] CSV report generated successfully", "success")
            except Exception as exc:
                self._log(f"[-] CSV generation failed: {exc}", "error")

        except Exception as exc:
            self.results["status"] = "failed"
            self.results["error"] = str(exc)
            self._log(f"[-] Orchestration failure: {exc}", "error")
        finally:
            self.is_running = False
            if self.ui_queue is not None:
                try:
                    self.ui_queue.put("[*] DONE")
                except Exception:
                    pass

    def stop_scan(self):
        self._stop_event.set()
        self._log("[~] Scan stop requested — finishing current module", "warning")

    def get_results(self) -> dict:
        return dict(self.results)


if __name__ == "__main__":
    ui_queue = queue.Queue()
    orchestrator = ReconOrchestrator(ui_queue)

    started = orchestrator.start_scan("google.com", "142.250.190.14", "Quick")
    print(f"Start result: {started}")

    while orchestrator.is_running or not ui_queue.empty():
        try:
            print(ui_queue.get(timeout=0.5))
        except queue.Empty:
            continue

    print("Final results:")
    print(orchestrator.get_results())
