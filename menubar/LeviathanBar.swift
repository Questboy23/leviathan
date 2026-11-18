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
    var passwordBoxTimer: Timer?
    var alertTimer: Timer?
    var level: Int = 2
    var modes: [String: Bool] = ["crypto": false, "apps": false, "tor": false, "agents": false]
    var agentLevel: Int = 2
    var hasUnreadAlert: Bool = false
    var activeTasks = 0          // menu actions still running (main thread only)
    var backgroundBusy = false   // a Leviathan scan or check started by its background jobs is running
    let leviathanBin: String
    let pythonBin = "/usr/bin/python3"
    let noNap = ProcessInfo.processInfo.beginActivity(options: [.userInitiatedAllowingIdleSystemSleep], reason: "menu bar guard")

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
        startPasswordBoxMonitor()
        refreshStatus()
    }

    func setupUI() {
        if let button = statusItem.button {
            let image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Leviathan")
            image?.isTemplate = true  // drawn white on a dark menu bar, like Apple's own icons
            button.image = image
            button.target = self
            button.action = #selector(statusItemClicked)
        }
        statusItem.menu = menu
        updateMenu(installed: FileManager.default.fileExists(atPath: leviathanBin))  // an empty menu never opens, so the first click did nothing
        menu.delegate = self  // the button action never fires once a menu is attached; opening the menu clears the alert
    }

    // Called just before the menu shows. Reading the settings file takes well under a millisecond,
    // so the menu opens at once with current checkmarks (no Python start on click).
    func menuNeedsUpdate(_ menu: NSMenu) {
        if menu === self.menu { statusItemClicked() }
    }

    func requestNotificationAuth() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
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

    @objc func statusItemClicked() {
        if hasUnreadAlert {
            hasUnreadAlert = false
            updateIconColor()
        }
        refreshStatus()
    }

    /// Reads ~/.leviathan/settings.json directly (the file `leviathan level` and `leviathan mode` write),
    /// then rebuilds the menu. Main thread only. Defaults match leviathan.py: level 2, agent level 2.
    func refreshStatus() {
        let installed = FileManager.default.fileExists(atPath: leviathanBin)
        let url = URL(fileURLWithPath: NSHomeDirectory() + "/.leviathan/settings.json")
        if let data = try? Data(contentsOf: url),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            level = json["level"] as? Int ?? 2
            agentLevel = json["agent_level"] as? Int ?? 2
            var newModes: [String: Bool] = ["crypto": false, "apps": false, "tor": false, "agents": false]
            for (k, v) in json["modes"] as? [String: Any] ?? [:] { if let b = v as? Bool { newModes[k] = b } }
            modes = newModes
        }
        updateMenu(installed: installed)
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
        // The website filter is the half that needs your password; say so when it is not installed.
        if !FileManager.default.fileExists(atPath: "/Library/LaunchDaemons/com.leviathan.dnscrypt.plist") {
            let f = NSMenuItem(title: "⚠︎ Website filter is off. Turn it on…", action: #selector(turnOnFilter), keyEquivalent: "")
            f.target = self
            menu.addItem(f)
        }
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
        level = sender.tag  // checkmark moves at once; the file is written by the CLI below
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
        modes[key] = newState
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
        agentLevel = sender.tag
        runCLIAsync(["agents", "level", "\(sender.tag)"]) { [weak self] output in
            if output.contains("error") || output.contains("Error") {
                self?.showAlert("Failed to set agent level", output)
            } else {
                self?.refreshStatus()
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

    // Opens the fix in Terminal, where macOS asks for the password. Nothing here sees the password.
    @objc func turnOnFilter() {
        let script = URL(fileURLWithPath: NSHomeDirectory() + "/.leviathan/bin/fix-filter.command")
        let terminal = URL(fileURLWithPath: "/System/Applications/Utilities/Terminal.app")
        NSWorkspace.shared.open([script], withApplicationAt: terminal, configuration: NSWorkspace.OpenConfiguration()) { [weak self] _, err in
            if let err = err { self?.showAlert("Could not open Terminal", "Run this in Terminal instead: bash ~/.leviathan/bin/fix-filter.command\n\n\(err.localizedDescription)") }
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

    var cleanOsascript = Set<String>()  // already checked and harmless: skip re-reading its script every 3 s

    // Background scans and checks that turn the shield green while they run.
    static let busyArgs = [" scan", " scan-all", " scan-apps", " scan-persist", " scan-downloads", " agents monitor", " sweep", " ai tuneup", " pkg ", " check "]

    func checkPasswordBoxes() {
        let result = runCLI(["-axwwo", "pid=,ppid=,command="], timeout: 5, exe: "/bin/ps")  // ww: full command lines, or a long inline script is cut before the part that matters
        var procs: [String: (ppid: String, cmd: String)] = [:]
        for line in result.split(separator: "\n") {
            let parts = line.split(separator: " ", maxSplits: 2)
            if parts.count == 3 { procs[String(parts[0])] = (String(parts[1]), String(parts[2]).trimmingCharacters(in: .whitespaces)) }  // ps pads columns
        }
        let busy = procs.values.contains { p in p.cmd.contains("leviathan.py") && LeviathanBar.busyArgs.contains { p.cmd.contains("leviathan.py" + $0) } }
        DispatchQueue.main.async { [weak self] in
            guard let self = self, self.backgroundBusy != busy else { return }
            self.backgroundBusy = busy
            self.updateIconColor()
        }
        guard level >= 2 else { return }
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
            // orange: an alert you have not seen; green: Leviathan is working; white (template) otherwise.
            // contentTintColor draws black in the macOS 26 menu bar, so the color goes into the image itself.
            let color: NSColor? = self.hasUnreadAlert ? .systemOrange : (self.activeTasks > 0 || self.backgroundBusy) ? .systemGreen : nil
            guard let base = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Leviathan") else { return }
            if let color = color, let tinted = base.withSymbolConfiguration(NSImage.SymbolConfiguration(paletteColors: [color])) {
                tinted.isTemplate = false
                button.image = tinted
            } else {
                base.isTemplate = true
                button.image = base
            }
            button.contentTintColor = nil
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
        process.qualityOfService = .userInitiated  // utility QoS + App Nap starved python for 10+ s, menu then said "not installed"
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
        let text = String(data: data, encoding: .utf8) ?? ""
        if text.isEmpty && exe == nil && process.terminationStatus != 0 { return "Leviathan command failed (exit \(process.terminationStatus))." }  // silent success stays silent
        return text
    }

    /// Runs a CLI command off the main thread. counts: the shield is green while it runs. Call from the main thread.
    func runCLIAsync(_ args: [String], timeout: TimeInterval = 30, stdin: String? = nil, counts: Bool = true, completion: @escaping (String) -> Void) {
        if counts { activeTasks += 1; updateIconColor() }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.runCLI(args, timeout: timeout, stdin: stdin)
            DispatchQueue.main.async {
                if counts { self.activeTasks -= 1; self.updateIconColor() }
                completion(result)
            }
        }
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
_ = LeviathanBar.shared
app.run()