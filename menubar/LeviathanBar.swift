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
    var filterOn: Bool? = nil     // nil until the first background check; nil also when offline
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
        startBusyMonitor()
        startFilterCheck()
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

    var busySource: DispatchSourceTimer?
    func startBusyMonitor() {
        // Every 15 s: turns the shield green while a scan runs.
        let t = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        t.schedule(deadline: .now() + 3, repeating: 15.0)
        t.setEventHandler { [weak self] in self?.checkBusy() }
        t.resume()
        busySource = t
    }

    @objc func statusItemClicked() {
        if hasUnreadAlert {
            hasUnreadAlert = false
            updateIconColor()
        }
        refreshStatus()
    }

    func refreshStatus() {
        updateMenu(installed: FileManager.default.fileExists(atPath: leviathanBin))
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
        let head = NSMenuItem(title: "Leviathan is on", action: nil, keyEquivalent: "")
        head.isEnabled = false
        menu.addItem(head)
        if filterOn == false {
            add("⚠︎ Turn on website filter…", #selector(turnOnFilter))
        }
        menu.addItem(NSMenuItem.separator())
        add("Check installer…", #selector(checkInstaller))
        add("Recent activity", #selector(showRecentActivity))
        add("Run full scan", #selector(runFullScan))
        menu.addItem(NSMenuItem.separator())
        addQuitItem()
    }

    @discardableResult func add(_ title: String, _ action: Selector) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
        item.target = self
        menu.addItem(item)
        return item
    }

    /// The filter is on when this Mac's DNS is Quad9: only Quad9 answers on.quad9.net with 216.21.3.77. Checked every 5 minutes off the main thread.
    func startFilterCheck() {
        let t = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        t.schedule(deadline: .now() + 2, repeating: 300.0)
        t.setEventHandler { [weak self] in
            guard let self = self else { return }
            let out = self.runCLI(["-q", "host", "-a", "name", "on.quad9.net"], timeout: 10, exe: "/usr/bin/dscacheutil")
            let on: Bool? = out.contains("216.21.3.77") ? true : (out.contains("ip_address") ? false : nil)
            DispatchQueue.main.async { self.filterOn = on }
        }
        t.resume()
        filterSource = t
    }
    var filterSource: DispatchSourceTimer?

    /// Opens the profile (macOS adds it to System Settings) and the pane where you click Install. Nothing here sees your password.
    @objc func turnOnFilter() {
        let profile = URL(fileURLWithPath: NSHomeDirectory() + "/.leviathan/bin/website-filter.mobileconfig")
        NSWorkspace.shared.open(profile)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            if let pane = URL(string: "x-apple.systempreferences:com.apple.Profiles-Settings.extension") { NSWorkspace.shared.open(pane) }
        }
        showAlert("Website filter", "System Settings is opening. Double-click \"Leviathan website filter\", click Install, and enter your Mac password. To remove it later, select it there and click the minus button.")
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

    // Background scans and checks that turn the shield green while they run.
    static let busyArgs = [" scan", " scan-all", " scan-apps", " scan-persist", " scan-downloads", " pkg ", " check "]

    func checkBusy() {
        let out = runCLI(["-axo", "command="], timeout: 5, exe: "/bin/ps")
        let busy = out.split(separator: "\n").contains { l in LeviathanBar.busyArgs.contains { l.contains("leviathan.py" + $0) } }
        DispatchQueue.main.async { [weak self] in
            guard let self = self, self.backgroundBusy != busy else { return }
            self.backgroundBusy = busy
            self.updateIconColor()
        }
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
            // no notification permission: stay silent, the orange shield and `leviathan log` carry the warning (never an OK window)
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