#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

namespace fs = std::filesystem;

// ANSI color codes
#define CYAN "\033[36m"
#define RESET "\033[0m"

// ======================
// Security Critical Section
// ======================

namespace Security {

class ScopedPrivilegeEscalation {
public:
    ScopedPrivilegeEscalation() {
        original_uid_ = geteuid();
        if (seteuid(0) == -1) {
            throw std::runtime_error("Failed to escalate privileges");
        }
    }

    ~ScopedPrivilegeEscalation() noexcept {
        if (seteuid(original_uid_) == -1) {
            std::cerr << "CRITICAL: Failed to drop privileges!" << std::endl;
            std::abort();
        }
    }

private:
    uid_t original_uid_;
};

bool VerifyPassword(const std::string& username, const std::string& password) {
    ScopedPrivilegeEscalation priv_guard;

    struct passwd* pw = getpwnam(username.c_str());
    if (!pw) return false;

    struct spwd* sp = getspnam(username.c_str());
    if (!sp) {
        // Fallback to regular password if shadow is unavailable
        sp = (struct spwd*)malloc(sizeof(struct spwd));
        sp->sp_namp = pw->pw_name;
        sp->sp_pwdp = pw->pw_passwd;
    }

    char* encrypted = crypt(password.c_str(), sp->sp_pwdp);
    if (!encrypted) return false;

    bool match = (strcmp(encrypted, sp->sp_pwdp) == 0);

    if (sp != nullptr && sp->sp_pwdp != pw->pw_passwd) {
        free(sp);
    }

    return match;
}

} // namespace Security

// ======================
// Desktop Session Management
// ======================

namespace Desktop {

struct Session {
    std::string name;
    std::string exec;
    std::string description;
    std::string desktop_file;
    bool is_wayland;
};

class SessionManager {
public:
    SessionManager() {
        LoadAvailableSessions();
    }

    const std::vector<Session>& GetSessions() const {
        return sessions_;
    }

    std::optional<Session> FindSession(const std::string& name) const {
        auto it = std::find_if(sessions_.begin(), sessions_.end(),
            [&name](const Session& s) { return s.name == name; });
        if (it != sessions_.end()) return *it;
        return std::nullopt;
    }

private:
    void LoadAvailableSessions() {
        const std::vector<std::pair<fs::path, bool>> search_paths = {
            {"/usr/share/wayland-sessions", true},
            {"/usr/share/xsessions", false},
            {"/usr/local/share/wayland-sessions", true},
            {"/usr/local/share/xsessions", false}
        };

        for (const auto& [dir, is_wayland] : search_paths) {
            if (!fs::exists(dir)) continue;

            for (const auto& entry : fs::directory_iterator(dir)) {
                if (entry.path().extension() != ".desktop") continue;

                try {
                    Session session = ParseDesktopFile(entry.path(), is_wayland);
                    if (!session.exec.empty()) {
                        sessions_.push_back(std::move(session));
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error parsing " << entry.path() << ": " << e.what() << std::endl;
                }
            }
        }

        // Sort sessions alphabetically
        std::sort(sessions_.begin(), sessions_.end(),
            [](const Session& a, const Session& b) {
                return a.name < b.name;
            });
    }

    Session ParseDesktopFile(const fs::path& path, bool is_wayland) {
        Session session;
        session.desktop_file = path;
        session.is_wayland = is_wayland;

        std::ifstream file(path);
        if (!file) throw std::runtime_error("Could not open file");

        std::string line;
        bool in_desktop_entry = false;

        while (std::getline(file, line)) {
            line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
            if (line.empty() || line[0] == '#') continue;

            if (line[0] == '[') {
                in_desktop_entry = (line == "[Desktop Entry]");
                continue;
            }

            if (!in_desktop_entry) continue;

            size_t sep = line.find('=');
            if (sep == std::string::npos) continue;

            std::string key = line.substr(0, sep);
            std::string value = line.substr(sep + 1);

            if (key == "Name") {
                session.name = value;
            } else if (key == "Exec") {
                session.exec = value;
            } else if (key == "Comment") {
                session.description = value;
            } else if (key == "Type" && value != "Application") {
                throw std::runtime_error("Not a session desktop file");
            }
        }

        // Clean up Exec command
        if (session.exec.find(" ") != std::string::npos) {
            session.exec = session.exec.substr(0, session.exec.find(" "));
        }

        return session;
    }

    std::vector<Session> sessions_;
};

} // namespace Desktop

// ======================
// User Management
// ======================

namespace User {

struct Info {
    std::string username;
    uid_t uid;
    gid_t gid;
    std::string home;
    std::string shell;
    std::string gecos;
};

class Manager {
public:
    Manager() {
        LoadUsers();
    }

    const std::vector<Info>& GetUsers() const {
        return users_;
    }

    std::optional<Info> FindUser(const std::string& username) const {
        auto it = std::find_if(users_.begin(), users_.end(),
            [&username](const Info& u) { return u.username == username; });
        if (it != users_.end()) return *it;
        return std::nullopt;
    }

private:
    void LoadUsers() {
        setpwent();
        struct passwd* pw;
        while ((pw = getpwent()) != nullptr) {
            // Skip system users (UID < 1000) and non-login shells
            if (pw->pw_uid >= 1000 && 
                std::strcmp(pw->pw_shell, "/usr/sbin/nologin") != 0 &&
                std::strcmp(pw->pw_shell, "/bin/false") != 0) {
                users_.push_back({
                    .username = pw->pw_name,
                    .uid = pw->pw_uid,
                    .gid = pw->pw_gid,
                    .home = pw->pw_dir,
                    .shell = pw->pw_shell,
                    .gecos = pw->pw_gecos
                });
            }
        }
        endpwent();

        // Sort users alphabetically
        std::sort(users_.begin(), users_.end(),
            [](const Info& a, const Info& b) {
                return a.username < b.username;
            });
    }

    std::vector<Info> users_;
};

} // namespace User

// ======================
// Terminal UI Components
// ======================

namespace UI {

class Terminal {
public:
    Terminal() {
        tcgetattr(STDIN_FILENO, &original_);
        struct termios raw = original_;
        raw.c_lflag &= ~(ECHO | ICANON);
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    }

    ~Terminal() {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_);
    }

    std::string ReadPassword(const std::string& prompt) {
        std::cout << prompt << ": ";
        std::cout.flush();

        std::string password;
        char ch;
        while (read(STDIN_FILENO, &ch, 1) == 1 && ch != '\n') {
            if (ch == 127 || ch == 8) { // Backspace
                if (!password.empty()) {
                    password.pop_back();
                    std::cout << "\b \b";
                }
            } else {
                password.push_back(ch);
                std::cout << '*';
            }
            std::cout.flush();
        }
        std::cout << std::endl;
        return password;
    }

    void Clear() {
        std::cout << "\033[2J\033[1;1H";
    }

    void SetTitle(const std::string& title) {
        std::cout << "\033]0;" << title << "\007";
    }

private:
    struct termios original_;
};

class Menu {
public:
    void AddOption(const std::string& text, std::function<void()> action) {
        options_.emplace_back(text, action);
    }

    void Display(const std::string& title) {
        Terminal term;
        while (true) {
            term.Clear();
            std::cout << "=== " CYAN "claude Login" RESET " ===\n\n";

            for (size_t i = 0; i < options_.size(); ++i) {
                std::cout << " " << i + 1 << ") " << options_[i].first << "\n";
            }
            std::cout << "\n 0) Back\n\n";

            int choice = GetNumericChoice(0, options_.size());
            if (choice == 0) break;
            options_[choice - 1].second();
        }
    }

    int GetNumericChoice(int min, int max) {
        int choice;
        while (true) {
            std::cout << "Select: ";
            std::cin >> choice;
            if (std::cin.fail()) {
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                continue;
            }
            if (choice >= min && choice <= max) break;
        }
        return choice;
    }

private:
    std::vector<std::pair<std::string, std::function<void()>>> options_;
};

} // namespace UI

// ======================
// Main Application
// ======================

class WaylandLoginManager {
public:
    WaylandLoginManager() : sessions_(), users_() {
        LoadConfiguration();
    }

    void Run() {
        UI::Terminal term;
        term.SetTitle("claude Login");

        if (config_.autologin) {
            TryAutoLogin();
            return;
        }

        LoginFlow();
    }

private:
    struct Config {
        bool autologin = false;
        std::string autologin_user;
        std::string autologin_session;
        std::string default_session = "sway";
    };

    void LoadConfiguration() {
        const char* autologin = std::getenv("WLM_AUTOLOGIN_USER");
        if (autologin && *autologin) {
            config_.autologin = true;
            config_.autologin_user = autologin;
            config_.autologin_session = std::getenv("WLM_AUTOLOGIN_SESSION");
            if (config_.autologin_session.empty()) {
                config_.autologin_session = config_.default_session;
            }
        }
    }

    void TryAutoLogin() {
        auto user = users_.FindUser(config_.autologin_user);
        if (!user) return;

        auto session = sessions_.FindSession(config_.autologin_session);
        if (!session) {
            session = sessions_.FindSession(config_.default_session);
        }

        if (session) {
            LaunchSession(*user, *session);
        }
    }

    void LoginFlow() {
        UI::Terminal term;
        term.Clear();

        // 1. Ask for username
        std::cout << CYAN "claude Login" RESET "\n\n";
        std::cout << "Username: ";
        std::string username;
        std::getline(std::cin, username);

        // 2. Verify user exists
        auto user = users_.FindUser(username);
        if (!user) {
            std::cout << "\nInvalid username\n";
            sleep(2);
            return;
        }

        // 3. Show session selection
        UI::Menu session_menu;
        for (const auto& session : sessions_.GetSessions()) {
            session_menu.AddOption(
                session.name + (session.is_wayland ? " (Wayland)" : " (X11)"),
                [this, user, session]() {
                    // 4. Ask for password after session selection
                    UI::Terminal term;
                    std::string password = term.ReadPassword("Password");

                    if (!Security::VerifyPassword(user->username, password)) {
                        std::cout << "\nAuthentication failed\n";
                        sleep(2);
                        return;
                    }

                    LaunchSession(*user, session);
                }
            );
        }

        session_menu.AddOption("Cancel", []() {});
        session_menu.Display("Select Desktop Session for " + username);
    }

    void LaunchSession(const User::Info& user, const Desktop::Session& session) {
        pid_t pid = fork();
        if (pid == 0) {
            // Child process
            SetupUserEnvironment(user);
            ExecuteSession(session);
            std::exit(0);
        } else if (pid > 0) {
            // Parent process
            int status;
            waitpid(pid, &status, 0);
        }
    }

    void SetupUserEnvironment(const User::Info& user) {
        setenv("HOME", user.home.c_str(), 1);
        setenv("USER", user.username.c_str(), 1);
        setenv("LOGNAME", user.username.c_str(), 1);
        setenv("SHELL", user.shell.c_str(), 1);
        setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1);

        std::string xdg_runtime_dir = "/run/user/" + std::to_string(user.uid);
        if (fs::exists(xdg_runtime_dir)) {
            setenv("XDG_RUNTIME_DIR", xdg_runtime_dir.c_str(), 1);
        }

        if (chdir(user.home.c_str()) != 0) {
            std::cerr << "Failed to change to home directory: " << strerror(errno) << std::endl;
        }

        if (setgid(user.gid) != 0 || setuid(user.uid) != 0) {
            std::cerr << "Failed to switch user: " << strerror(errno) << std::endl;
            std::exit(1);
        }
    }

    void ExecuteSession(const Desktop::Session& session) {
        if (session.is_wayland) {
            unsetenv("DISPLAY");
            setenv("XDG_SESSION_TYPE", "wayland", 1);
        } else {
            setenv("DISPLAY", ":0", 1);
            setenv("XDG_SESSION_TYPE", "x11", 1);
        }

        execlp(session.exec.c_str(), session.exec.c_str(), nullptr);
        std::cerr << "Failed to execute session: " << strerror(errno) << std::endl;
        std::exit(1);
    }

    Config config_;
    Desktop::SessionManager sessions_;
    User::Manager users_;
};

int main(int argc, char* argv[]) {
    try {
        WaylandLoginManager wlm;
        wlm.Run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}