import AppKit
import Foundation
import UserNotifications
import UniformTypeIdentifiers

// Leviathan Bar - Menu bar app for Leviathan security tool
// Build: swiftc -O -framework AppKit LeviathanBar.swift -o build/Leviathan\ Bar.app/Contents/MacOS/Leviathan\ Bar

final class LeviathanBar: NSObject, NSMenuDelegate {
    static let shared = LeviathanBar()

    let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    let menu = NSMenu()
    var levelItems: [Int: NSMenuItem] = [:]
    var modeItems: [String: NSMenuItem] = [:]
    var agentLevelItems: [Int: NSMenuItem] = [:]
    var pasteboardChangeCount: Int = NSPasteboard.general.changeCount
    var clipboardTimer: Timer?
    var passwordBoxTimer: Timer?
    var vpnTimer: Timer?
    var alertTimer: Timer?
    var level: Int = 2
    var modes: [String: Bool] = ["crypto": false, "apps": false, "tor": false, "agents": false]
    var agentLevel: Int = 1
    var vpnStatus: String = ""
    var vpnClientFound: Bool = false
    var hasUnreadAlert: Bool = false
    let leviathanBin: String
    let pythonBin = "/usr/bin/python3"

    private override init() {
        if let envBin = ProcessInfo.processInfo.environment["LEVIATHAN_BIN"], !envBin.isEmpty {
            leviathanBin = envBin
        } else {
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            leviathanBin = "\(home)/.leviathan/bin/leviathan.py"
        }
        super.init()
        setupUI()
        requestNotificationAuth()
        checkNotificationAuth()
        startClipboardMonitor()
        startPasswordBoxMonitor()
        startVPNMonitor()
        refreshStatus()
    }

    func setupUI() {
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Leviathan")
            button.target = self
            button.action = #selector(statusItemClicked)
        }
        statusItem.menu = menu
        menu.delegate = self  // the button action never fires once a menu is attached; opening the menu clears the alert
    }

    func menuWillOpen(_ menu: NSMenu) {
        if menu === self.menu { statusItemClicked() }
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

    var passwordBoxSource: DispatchSourceTimer?
    func startPasswordBoxMonitor() {
        // Runs on its own queue: an alert or open menu on the main thread can never pause this guard.
        let t = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        t.schedule(deadline: .now() + 3, repeating: 3.0)
        t.setEventHandler { [weak self] in self?.checkPasswordBoxes() }
        t.resume()
        passwordBoxSource = t
    }

    func startVPNMonitor() {
        vpnTimer = Timer.scheduledTimer(withTimeInterval: 30.0, repeats: true) { [weak self] _ in
            self?.fetchVPNStatus()
        }
        RunLoop.main.add(vpnTimer!, forMode: .common)
    }

    @objc func statusItemClicked() {
        if hasUnreadAlert {
            hasUnreadAlert = false
            updateIconColor()
        }
        refreshStatus()
    }

    func refreshStatus() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            self?.fetchLevelAndModes()
            self?.fetchAgentLevel()
            self?.fetchVPNStatus()
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

    func fetchAgentLevel() {
        let result = runCLI(["agents", "level"], timeout: 10)
        if let line = result.split(separator: "\n").first,
           line.hasPrefix("Current agent level:") {
            let parts = line.split(separator: ":")
            if parts.count > 1, let lvl = Int(parts[1].trimmingCharacters(in: .whitespaces)) {
                DispatchQueue.main.async { [weak self] in
                    self?.agentLevel = lvl
                    self?.updateAgentLevelChecks()
                }
            }
        }
    }

    func fetchVPNStatus() {
        let result = runCLI(["vpn", "status"], timeout: 10)
        let status = result.trimmingCharacters(in: .whitespacesAndNewlines)
        var clientFound = false

        if status.hasPrefix("VPN:") || status.hasPrefix("Connected") || status.contains("on") {
            clientFound = true
        } else if status.contains("No supported VPN client found") {
            clientFound = false
        }

        DispatchQueue.main.async { [weak self] in
            self?.vpnStatus = status
            self?.vpnClientFound = clientFound
            self?.updateVPNMenu()
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

        // Shield status line
        let statusItem = NSMenuItem(title: "Leviathan • Level \(level) • \(modeSummary())", action: nil, keyEquivalent: "")
        statusItem.isEnabled = false
        menu.addItem(statusItem)
        menu.addItem(NSMenuItem.separator())

        // Level 1-5 with checkmarks
        addLevelMenu()
        menu.addItem(NSMenuItem.separator())

        // "I'm using:" with checkmarks
        addUsingMenu()
        menu.addItem(NSMenuItem.separator())

        // AI Safety card
        addAISafetyMenu()
        menu.addItem(NSMenuItem.separator())

        // AI Tune-up card
        addAITuneupMenu()
        menu.addItem(NSMenuItem.separator())

        // VPN
        addVPNMenu()
        menu.addItem(NSMenuItem.separator())

        // Actions
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

    func addUsingMenu() {
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
        let parent = NSMenuItem(title: "I'm using:", action: nil, keyEquivalent: "")
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

    func addAISafetyMenu() {
        let submenu = NSMenu()

        // Agent level submenu
        let levelSubmenu = NSMenu()
        for lvl in 1...3 {
            let item = NSMenuItem(title: "Level \(lvl): \(agentLevelName(lvl))", action: #selector(setAgentLevel(_:)), keyEquivalent: "")
            item.target = self
            item.tag = lvl
            item.state = lvl == agentLevel ? .on : .off
            levelSubmenu.addItem(item)
            agentLevelItems[lvl] = item
        }
        let levelParent = NSMenuItem(title: "Agent guard level", action: nil, keyEquivalent: "")
        submenu.setSubmenu(levelSubmenu, for: levelParent)
        submenu.addItem(levelParent)

        submenu.addItem(NSMenuItem.separator())

        let pauseItem = NSMenuItem(title: "Pause all AI agents", action: #selector(pauseAgents), keyEquivalent: "")
        pauseItem.target = self
        submenu.addItem(pauseItem)

        let resumeItem = NSMenuItem(title: "Resume all AI agents", action: #selector(resumeAgents), keyEquivalent: "")
        resumeItem.target = self
        submenu.addItem(resumeItem)

        let parent = NSMenuItem(title: "AI Safety", action: nil, keyEquivalent: "")
        menu.setSubmenu(submenu, for: parent)
        menu.addItem(parent)
    }

    func agentLevelName(_ lvl: Int) -> String {
        switch lvl {
        case 1: return "Watch"
        case 2: return "Guard"
        case 3: return "Lockdown"
        default: return ""
        }
    }

    func updateAgentLevelChecks() {
        for lvl in 1...3 {
            agentLevelItems[lvl]?.state = lvl == agentLevel ? .on : .off
        }
    }

    @objc func setAgentLevel(_ sender: NSMenuItem) {
        runCLIAsync(["agents", "level", "\(sender.tag)"]) { [weak self] output in
            if output.contains("error") || output.contains("Error") {
                self?.showAlert("Failed to set agent level", output)
            } else {
                self?.fetchAgentLevel()
            }
        }
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

    func addAITuneupMenu() {
        let submenu = NSMenu()

        let runItem = NSMenuItem(title: "Run check", action: #selector(runAITuneup), keyEquivalent: "")
        runItem.target = self
        submenu.addItem(runItem)

        let parent = NSMenuItem(title: "AI Tune-up", action: nil, keyEquivalent: "")
        menu.setSubmenu(submenu, for: parent)
        menu.addItem(parent)
    }

    @objc func runAITuneup() {
        runCLIAsync(["ai", "tuneup"], timeout: 120) { [weak self] output in
            self?.showResult("AI Tune-up", output)
        }
    }

    func addVPNMenu() {
        let submenu = NSMenu()

        if vpnClientFound {
            let statusItem = NSMenuItem(title: vpnStatus, action: nil, keyEquivalent: "")
            statusItem.isEnabled = false
            submenu.addItem(statusItem)
            submenu.addItem(NSMenuItem.separator())

            let onItem = NSMenuItem(title: "VPN on", action: #selector(vpnOn), keyEquivalent: "")
            onItem.target = self
            submenu.addItem(onItem)

            let offItem = NSMenuItem(title: "VPN off", action: #selector(vpnOff), keyEquivalent: "")
            offItem.target = self
            submenu.addItem(offItem)
        } else {
            let item = NSMenuItem(title: "Get free VPN (Cloudflare WARP)", action: #selector(openWARP), keyEquivalent: "")
            item.target = self
            submenu.addItem(item)
        }

        let parent = NSMenuItem(title: "VPN", action: nil, keyEquivalent: "")
        menu.setSubmenu(submenu, for: parent)
        menu.addItem(parent)
    }

    func updateVPNMenu() {
        // Find the VPN parent item and update its submenu
        for item in menu.items {
            if item.title == "VPN", let submenu = item.submenu {
                submenu.removeAllItems()
                if vpnClientFound {
                    let statusItem = NSMenuItem(title: vpnStatus, action: nil, keyEquivalent: "")
                    statusItem.isEnabled = false
                    submenu.addItem(statusItem)
                    submenu.addItem(NSMenuItem.separator())

                    let onItem = NSMenuItem(title: "VPN on", action: #selector(vpnOn), keyEquivalent: "")
                    onItem.target = self
                    submenu.addItem(onItem)

                    let offItem = NSMenuItem(title: "VPN off", action: #selector(vpnOff), keyEquivalent: "")
                    offItem.target = self
                    submenu.addItem(offItem)
                } else {
                    let item = NSMenuItem(title: "Get free VPN (Cloudflare WARP)", action: #selector(openWARP), keyEquivalent: "")
                    item.target = self
                    submenu.addItem(item)
                }
                break
            }
        }
    }

    @objc func vpnOn() {
        runCLIAsync(["vpn", "on"]) { [weak self] output in
            self?.showResult("VPN on", output)
            self?.fetchVPNStatus()
        }
    }

    @objc func vpnOff() {
        runCLIAsync(["vpn", "off"]) { [weak self] output in
            self?.showResult("VPN off", output)
            self?.fetchVPNStatus()
        }
    }

    @objc func openWARP() {
        if let url = URL(string: "https://one.one.one.one") {
            NSWorkspace.shared.open(url)
        }
    }

    func addActionMenu() {
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
            runCLIAsync(["pkg", url.path], timeout: 300) { [weak self] output in
                self?.showResult("Check installer", output)
            }
        }
    }

    @objc func showRecentActivity() {
        runCLIAsync(["status"]) { [weak self] result in
            let lines = result.split(separator: "\n").suffix(10).joined(separator: "\n")
            self?.showAlert("Recent Activity (last 10 entries)", lines)
        }
    }

    @objc func runFullScan() {
        runCLIAsync(["scan"], timeout: 300) { [weak self] output in
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
                        self?.hasUnreadAlert = true
                        self?.updateIconColor()
                        self?.showWarning("Clipboard guard", output)
                    }
                }
            }
        }
    }

    var cleanOsascript = Set<String>()  // already checked and harmless: skip re-reading its script every 3 s

    func checkPasswordBoxes() {
        guard level >= 2 else { return }
        let result = runCLI(["-axwwo", "pid=,ppid=,command="], timeout: 5, exe: "/bin/ps")  // ww: full command lines, or a long inline script is cut before the part that matters
        var procs: [String: (ppid: String, cmd: String)] = [:]
        for line in result.split(separator: "\n") {
            let parts = line.split(separator: " ", maxSplits: 2)
            if parts.count == 3 { procs[String(parts[0])] = (String(parts[1]), String(parts[2]).trimmingCharacters(in: .whitespaces)) }  // ps pads columns
        }
        var killed: [String] = []
        for (pid, pr) in procs {
            let prog = (String(pr.cmd.split(separator: " ").first ?? "") as NSString).lastPathComponent
            guard prog == "osascript", !cleanOsascript.contains(pid + pr.cmd) else { continue }
            guard asksHiddenAnswer(pr.cmd), !typedAtTerminalPrompt(pid, procs) else { cleanOsascript.insert(pid + pr.cmd); continue }
            if let p = Int32(pid) { kill(p, SIGKILL) }
            killed.append(pid)
        }
        if cleanOsascript.count > 5000 { cleanOsascript.removeAll() }
        for pid in killed {
            _ = runCLI(["note-event", "password-box", pid], timeout: 10)
            hasUnreadAlert = true
            updateIconColor()
            showWarning("Fake password box blocked", "Terminated osascript PID \(pid)")
        }
    }

    // True when the inline script, or a script file it runs, asks for a hidden answer (AppleScript or JavaScript).
    func asksHiddenAnswer(_ cmd: String) -> Bool {
        func hit(_ t: String) -> Bool { t.lowercased().components(separatedBy: .whitespacesAndNewlines).joined().contains("hiddenanswer") }
        if hit(cmd) { return true }
        // shortcut: splits on spaces, so a script path containing spaces is missed; scripts fed on stdin are never seen
        for arg in cmd.split(separator: " ").dropFirst() where arg.hasPrefix("/") || arg.hasSuffix(".scpt") || arg.hasSuffix(".applescript") || arg.hasSuffix(".js") {
            let path = String(arg)
            // regular files under 1 MB only: /dev/zero or a pipe would hang this guard
            guard let at = try? FileManager.default.attributesOfItem(atPath: path), at[.type] as? FileAttributeType == .typeRegular,
                  (at[.size] as? NSNumber)?.intValue ?? Int.max < 1_000_000,
                  let data = FileManager.default.contents(atPath: path) else { continue }
            if let text = String(data: data.prefix(65536), encoding: .utf8), hit(text) { return true }
            if path.hasSuffix(".scpt") && hit(runCLI([path], timeout: 5, exe: "/usr/bin/osadecompile")) { return true }
        }
        return false
    }

    // Real executable path from the kernel; argv[0] in ps output can be set to anything.
    func exePath(_ pid: String) -> String {
        guard let p = Int32(pid) else { return "" }
        var buf = [CChar](repeating: 0, count: 4096)
        return proc_pidpath(p, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : ""
    }

    // Exempt only an osascript typed straight at a Terminal or iTerm prompt: osascript, then a shell, then login or the
    // terminal itself. A script run by a pasted `curl | bash` has an extra shell in between, so it is still blocked.
    func typedAtTerminalPrompt(_ pid: String, _ procs: [String: (ppid: String, cmd: String)]) -> Bool {
        let terminals = ["/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                         "/Applications/iTerm.app/Contents/MacOS/iTerm2"]
        let shells = ["/bin/zsh", "/bin/bash", "/bin/sh", "/opt/homebrew/bin/fish", "/opt/homebrew/bin/bash"]
        guard let shell = procs[pid]?.ppid, shells.contains(exePath(shell)),
              let up = procs[shell]?.ppid else { return false }
        if terminals.contains(exePath(up)) { return true }
        guard exePath(up) == "/usr/bin/login", let term = procs[up]?.ppid else { return false }
        return terminals.contains(exePath(term))
    }

    var notificationAuthorized = false

    func checkNotificationAuth() {
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            DispatchQueue.main.async {
                self.notificationAuthorized = settings.authorizationStatus == .authorized
            }
        }
    }

    func updateIconColor() {
        DispatchQueue.main.async { [weak self] in
            guard let self = self, let button = self.statusItem.button else { return }
            if self.hasUnreadAlert {
                button.contentTintColor = .systemOrange
            } else {
                button.contentTintColor = nil
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
            DispatchQueue.main.async { self.showAlert(title, message) }  // never block the timer that called us
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

    /// Runs leviathan.py with args, or a system tool when exe is given. Output and errors share one pipe,
    /// read before waiting, so a large output cannot block; the timeout really stops a stuck command.
    func runCLI(_ args: [String], timeout: TimeInterval = 10, stdin: String? = nil, exe: String? = nil) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: exe ?? pythonBin)
        process.arguments = exe == nil ? [leviathanBin] + args : args
        let out = Pipe()
        process.standardOutput = out
        process.standardError = out
        let input = Pipe()
        if stdin != nil { process.standardInput = input }
        do {
            try process.run()
        } catch {
            return "Error: \(error.localizedDescription)"
        }
        let killer = DispatchWorkItem { if process.isRunning { process.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: killer)
        if let text = stdin {
            try? input.fileHandleForWriting.write(contentsOf: text.data(using: .utf8) ?? Data())
            try? input.fileHandleForWriting.close()
        }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        killer.cancel()
        return String(data: data, encoding: .utf8) ?? ""
    }

    func runCLIAsync(_ args: [String], timeout: TimeInterval = 10, stdin: String? = nil, completion: @escaping (String) -> Void) {
        DispatchQueue.global(qos: .utility).async {
            let result = self.runCLI(args, timeout: timeout, stdin: stdin)
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