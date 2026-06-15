# Weblink-analysis-
        </aside>
      </div>
      <p class="notice">This scanner is a first-pass triage tool. For high confidence, compare results with established services and avoid entering passwords or downloading files from unknown sites.</p>
    </section>
  </main>
  <script>
    const form = document.querySelector("#scan-form");
    const button = document.querySelector("#scan-button");
    const errorBox = document.querySelector("#error");
    const result = document.querySelector("#result");
    const levelColors = { high: "#b42318", medium: "#a15b00", low: "#176b42", good: "#176b42" };

    function text(value) {
      return value === null || value === undefined || value === "" ? "Unknown" : String(value);
    }

    function addFact(label, value) {
      const row = document.createElement("div");
      row.className = "fact";
      row.innerHTML = `<span></span><strong></strong>`;
      row.querySelector("span").textContent = label;
      row.querySelector("strong").textContent = text(value);
      document.querySelector("#facts").appendChild(row);
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      errorBox.style.display = "none";
      result.style.display = "none";
      button.disabled = true;
      button.textContent = "Scanning...";
      try {
        const url = document.querySelector("#url").value;
        const response = await fetch(`/scan?url=${encodeURIComponent(url)}`);
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Scan failed");

        const meter = document.querySelector("#meter");
        meter.style.setProperty("--score", data.score);
        meter.style.setProperty("--meter", levelColors[data.level]);
        document.querySelector("#score").textContent = data.score;
        document.querySelector("#verdict").textContent = data.verdict;
        document.querySelector("#verdict").style.color = levelColors[data.level];
        document.querySelector("#checked-url").textContent = data.normalized_url;
        document.querySelector("#checked-at").textContent = `Checked ${data.checked_at}`;

        const signals = document.querySelector("#signals");
        signals.replaceChildren();
        data.signals.forEach((signal) => {
          const item = document.createElement("div");
          item.className = "signal";
          item.style.setProperty("--signal", levelColors[signal.severity] || "#5b6762");
          item.innerHTML = `<strong></strong><p></p>`;
          item.querySelector("strong").textContent = signal.title;
          item.querySelector("p").textContent = signal.detail;
          signals.appendChild(item);
        });

        document.querySelector("#facts").replaceChildren();
        addFact("Host", data.host);
        addFact("HTTP status", data.fetch.status);
        addFact("Final URL", data.fetch.final_url);
        addFact("Content type", data.fetch.content_type);
        addFact("Server", data.fetch.server);
        addFact("Fetch time", `${data.fetch.elapsed_ms} ms`);
        if (data.tls) {
          addFact("TLS valid", data.tls.valid ? "Yes" : "No");
          addFact("TLS issuer", data.tls.issuer);
          addFact("TLS expires", data.tls.expires);
        }

        const links = document.querySelector("#links");
        links.replaceChildren();
        Object.entries(data.external_lookup_links).forEach(([name, href]) => {
          const link = document.createElement("a");
          link.href = href;
          link.target = "_blank";
          link.rel = "noreferrer";
          link.textContent = name;
          links.appendChild(link);
        });

        result.style.display = "block";
      } catch (error) {
        errorBox.textContent = error.message;
        errorBox.style.display = "block";
      } finally {
        button.disabled = false;
        button.textContent = "Scan URL";
      }
    });
  </script>
</body>
</html>"""


class ScannerHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        print("%s - %s" % (self.address_string(), format % args))

    def send_text(self, status: int, body: str, content_type: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_text(200, page_template(), "text/html; charset=utf-8")
            return
        if parsed.path == "/scan":
            params = parse_qs(parsed.query)
            raw_url = params.get("url", [""])[0]
            try:
                result = analyze_url(raw_url)
                self.send_text(200, json.dumps(result), "application/json; charset=utf-8")
            except ValueError as exc:
                self.send_text(400, json.dumps({"error": html.escape(str(exc))}), "application/json; charset=utf-8")
            except Exception as exc:
                self.send_text(500, json.dumps({"error": f"Unexpected scanner error: {exc}"}), "application/json; charset=utf-8")
            return
        self.send_text(404, "Not found", "text/plain; charset=utf-8")


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), ScannerHandler)
    print(f"Malware Safety Website Scanner running at http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping scanner.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
