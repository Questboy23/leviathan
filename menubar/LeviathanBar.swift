import AppKit
import Foundation
import UserNotifications
import UniformTypeIdentifiers

// Leviathan Bar - Menu bar app for Leviathan security tool
// Build: swiftc -O -framework AppKit LeviathanBar.swift -o build/Leviathan\ Bar.app/Contents/MacOS/Leviathan\ Bar

final class LeviathanBar {
    static let shared = LeviathanBar()

    let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    let menu = NSMenu()
    var levelItems: [Int: NSMenuItem] = [:]
    var modeItems: [String: NSMenuItem] = [:]
    var pasteboardChangeCount: Int = NSPasteboard.general.changeCount
    var clipboardTimer: Timer?
    var passwordBoxTimer: Timer?
    var level: Int = 2
    var modes: [String: Bool] = ["crypto": false, "apps": false, "tor": false, "agents": false]
    let leviathanBin: String
    let pythonBin = "/usr/bin/python3"

    private init() {
        if let envBin = ProcessInfo.processInfo.environment["LEVIATHAN_BIN"], !envBin.isEmpty {
            leviathanBin = envBin
        } else {
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            leviathanBin = "\(home)/.leviathan/bin/leviathan.py"
        }
        setupUI()
        requestNotificationAuth()
        checkNotificationAuth()
        startClipboardMonitor()
        startPasswordBoxMonitor()
        refreshStatus()
    }

    func setupUI() {
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Leviathan")
            button.target = self
            button.action = #selector(statusItemClicked)
        }
        statusItem.menu = menu
    }

    func requestNotificationAuth() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    func startClipboardMonitor() {
        clipboardTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.checkClipboard()
        }
        RunLoop.main.add(clipboardTimer!, forMode: .common)
    }

    func startPasswordBoxMonitor() {
        passwordBoxTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in
            self?.checkPasswordBoxes()
        }
        RunLoop.main.add(passwordBoxTimer!, forMode: .common)
    }

    @objc func statusItemClicked() {
        refreshStatus()
    }

    func refreshStatus() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            self?.fetchLevelAndModes()
        }
    }

    func fetchLevelAndModes() {
        var newLevel = 2
        var newModes = ["crypto": false, "apps": false, "tor": false, "agents": false]
        var installed = true

        let levelResult = runCLI(["level", "--json"], timeout: 10)
        if let data = levelResult.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let lvl = json["level"] as? Int {
            newLevel = lvl
        } else {
            installed = false
        }

        let modeResult = runCLI(["mode", "--json"], timeout: 10)
        if let data = modeResult.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            for (key, value) in json {
                if let boolVal = value as? Bool {
                    newModes[key] = boolVal
                }
            }
        } else {
            installed = false
        }

        DispatchQueue.main.async { [weak self] in
            self?.level = newLevel
            self?.modes = newModes
            self?.updateMenu(installed: installed)
        }
    }

    func updateMenu(installed: Bool) {
        menu.removeAllItems()

        if !installed {
            let item = NSMenuItem(title: "Leviathan not installed", action: nil, keyEquivalent: "")
            item.isEnabled = false
            menu.addItem(item)
            menu.addItem(NSMenuItem.separator())
            addQuitItem()
            return
        }

        let statusItem = NSMenuItem(title: "Level \(level) • \(modeSummary())", action: nil, keyEquivalent: "")
        statusItem.isEnabled = false
        menu.addItem(statusItem)
        menu.addItem(NSMenuItem.separator())

        addLevelMenu()
        menu.addItem(NSMenuItem.separator())
        addModeMenu()
        menu.addItem(NSMenuItem.separator())
        addActionMenu()
        menu.addItem(NSMenuItem.separator())
        addQuitItem()
    }

    func modeSummary() -> String {
        let active = modes.filter { $0.value }.keys.joined(separator: ", ")
        return active.isEmpty ? "no modes" : active
    }

    func addLevelMenu() {
        let submenu = NSMenu()
        for lvl in 1...5 {
            let item = NSMenuItem(title: "Level \(lvl): \(levelName(lvl))", action: #selector(setLevel(_:)), keyEquivalent: "")
            item.target = self
            item.tag = lvl
            item.state = lvl == level ? .on : .off
            submenu.addItem(item)
            levelItems[lvl] = item
        }
        let parent = NSMenuItem(title: "Level", action: nil, keyEquivalent: "")
        menu.setSubmenu(submenu, for: parent)
        menu.addItem(parent)
    }

    func levelName(_ lvl: Int) -> String {
        switch lvl {
        case 1: return "Basic"
        case 2: return "Standard"
        case 3: return "Careful"
        case 4: return "Strict"
        case 5: return "Lockdown"
        default: return ""
        }
    }

    @objc func setLevel(_ sender: NSMenuItem) {
        runCLIAsync(["level", "\(sender.tag)"]) { [weak self] output in
            if output.contains("error") || output.contains("Error") {
                self?.showAlert("Failed to set level", output)
            } else {
                self?.refreshStatus()
            }
        }
    }

    func addModeMenu() {
        let modeOrder = [("crypto", "Crypto"), ("apps", "Untrusted apps"), ("tor", "Tor"), ("agents", "AI agents")]
        let submenu = NSMenu()
        for (key, label) in modeOrder {
            let item = NSMenuItem(title: label, action: #selector(toggleMode(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = key
            item.state = modes[key] == true ? .on : .off
            submenu.addItem(item)
            modeItems[key] = item
        }
        let parent = NSMenuItem(title: "Modes", action: nil, keyEquivalent: "")
        menu.setSubmenu(submenu, for: parent)
        menu.addItem(parent)
    }

    @objc func toggleMode(_ sender: NSMenuItem) {
        guard let key = sender.representedObject as? String else { return }
        let newState = modes[key] != true
        runCLIAsync(["mode", key, newState ? "on" : "off"]) { [weak self] output in
            if output.contains("error") || output.contains("Error") {
                self?.showAlert("Failed to toggle mode", output)
            } else {
                self?.refreshStatus()
            }
        }
    }

    func addActionMenu() {
        let pauseItem = NSMenuItem(title: "Pause all AI agents", action: #selector(pauseAgents), keyEquivalent: "")
        pauseItem.target = self
        menu.addItem(pauseItem)

        let resumeItem = NSMenuItem(title: "Resume all AI agents", action: #selector(resumeAgents), keyEquivalent: "")
        resumeItem.target = self
        menu.addItem(resumeItem)

        let sandboxItem = NSMenuItem(title: "Open app in sandbox…", action: #selector(openInSandbox), keyEquivalent: "")
        sandboxItem.target = self
        menu.addItem(sandboxItem)

        let pkgItem = NSMenuItem(title: "Check installer…", action: #selector(checkInstaller), keyEquivalent: "")
        pkgItem.target = self
        menu.addItem(pkgItem)

        let activityItem = NSMenuItem(title: "Recent activity", action: #selector(showRecentActivity), keyEquivalent: "")
        activityItem.target = self
        menu.addItem(activityItem)

        let scanItem = NSMenuItem(title: "Run full scan", action: #selector(runFullScan), keyEquivalent: "")
        scanItem.target = self
        menu.addItem(scanItem)
    }

    @objc func pauseAgents() {
        runCLIAsync(["agents", "pause"]) { [weak self] output in
            self?.showResult("Pause agents", output)
        }
    }

    @objc func resumeAgents() {
        runCLIAsync(["agents", "resume"]) { [weak self] output in
            self?.showResult("Resume agents", output)
        }
    }

    @objc func openInSandbox() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowedContentTypes = [.application]
        panel.message = "Select an app to open in sandbox"
        if panel.runModal() == .OK, let url = panel.url {
            runCLIAsync(["sandbox", url.path]) { [weak self] output in
                self?.showResult("Open in sandbox", output)
            }
        }
    }

    @objc func checkInstaller() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowedContentTypes = [UTType(filenameExtension: "pkg")!]
        panel.message = "Select a .pkg installer to check"
        if panel.runModal() == .OK, let url = panel.url {
            runCLIAsync(["pkg", url.path]) { [weak self] output in
                self?.showResult("Check installer", output)
            }
        }
    }

    @objc func showRecentActivity() {
        let result = runCLI(["status"], timeout: 10)
        showAlert("Recent Activity (last 30 entries)", result)
    }

    @objc func runFullScan() {
        runCLIAsync(["scan"]) { [weak self] output in
            self?.showResult("Full scan", output)
        }
    }

    func addQuitItem() {
        let quitItem = NSMenuItem(title: "Quit Leviathan Bar", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(quitItem)
    }

    func checkClipboard() {
        let currentCount = NSPasteboard.general.changeCount
        if currentCount != pasteboardChangeCount {
            pasteboardChangeCount = currentCount
            if let string = NSPasteboard.general.string(forType: .string), !string.isEmpty {
                let limited = String(string.prefix(10240))
                runCLIAsync(["clip"], stdin: limited) { [weak self] output in
                    if !output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        self?.showWarning("Clipboard guard", output)
                    }
                }
            }
        }
    }

    func checkPasswordBoxes() {
        guard level >= 2 else { return }
        let result = runCLI(["ps", "-axo", "pid=,ppid=,command="], timeout: 5)
        let lines = result.split(separator: "\n")
        for line in lines {
            let parts = line.split(separator: " ", maxSplits: 2)
            if parts.count < 3 { continue }
            let pid = String(parts[0])
            let ppid = String(parts[1])
            let cmd = String(parts[2])
            if cmd.contains("osascript") && cmd.localizedCaseInsensitiveContains("hidden answer") {
                if !isParentTerminal(ppid: ppid) {
                    _ = runCLI(["kill", "-9", pid], timeout: 2)
                    _ = runCLI(["note-event", "password-box", pid], timeout: 2)
                    showWarning("Fake password box blocked", "Terminated osascript PID \(pid)")
                }
            }
        }
    }

    func isParentTerminal(ppid: String) -> Bool {
        let result = runCLI(["ps", "-p", ppid, "-o", "comm="], timeout: 2)
        let comm = result.trimmingCharacters(in: .whitespacesAndNewlines)
        return comm == "Terminal" || comm == "iTerm2" || comm == "iTerm"
    }

    var notificationAuthorized = false

    func checkNotificationAuth() {
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            DispatchQueue.main.async {
                self.notificationAuthorized = settings.authorizationStatus == .authorized
            }
        }
    }

    func showWarning(_ title: String, _ message: String) {
        if notificationAuthorized {
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = String(message.prefix(200))
            content.sound = .default
            let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
            UNUserNotificationCenter.current().add(request, withCompletionHandler: nil)
        } else {
            showAlert(title, message)
        }
    }

    func showAlert(_ title: String, _ message: String) {
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = title
            alert.informativeText = String(message.prefix(500))
            alert.alertStyle = .informational
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }
    }

    func showResult(_ title: String, _ output: String) {
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return }
        showAlert(title, trimmed)
    }

    func runCLI(_ args: [String], timeout: TimeInterval = 10, stdin: String? = nil) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: pythonBin)
        process.arguments = [leviathanBin] + args
        process.standardOutput = Pipe()
        process.standardError = Pipe()

        if stdin != nil {
            let inputPipe = Pipe()
            process.standardInput = inputPipe
        }

        do {
            try process.run()
            if stdin != nil {
                if let inputPipe = process.standardInput as? Pipe {
                    let data = stdin!.data(using: .utf8) ?? Data()
                    try inputPipe.fileHandleForWriting.write(contentsOf: data)
                    try inputPipe.fileHandleForWriting.close()
                }
            }
            process.waitUntilExit()
            let outputData = (process.standardOutput as? Pipe)?.fileHandleForReading.readDataToEndOfFile() ?? Data()
            let errorData = (process.standardError as? Pipe)?.fileHandleForReading.readDataToEndOfFile() ?? Data()
            let output = String(data: outputData, encoding: .utf8) ?? ""
            let error = String(data: errorData, encoding: .utf8) ?? ""
            return output + (error.isEmpty ? "" : "\n" + error)
        } catch {
            return "Error: \(error.localizedDescription)"
        }
    }

    func runCLIAsync(_ args: [String], stdin: String? = nil, completion: @escaping (String) -> Void) {
        DispatchQueue.global(qos: .utility).async {
            let result = self.runCLI(args, timeout: 10, stdin: stdin)
            DispatchQueue.main.async {
                completion(result)
            }
        }
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
_ = LeviathanBar.shared
app.run()