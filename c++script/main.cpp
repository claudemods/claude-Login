
#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include <shadow.h>
#include <crypt.h>
#include <sys/types.h>
#include <pwd.h>
#include <wordexp.h>
#include <signal.h>
#include <sys/wait.h>

namespace fs = std::filesystem;

// Structure to hold desktop environment information
struct DesktopEnvironment {
    std::string name;
    std::string exec_command;
    std::string description;
};

// Available Wayland desktop environments
std::vector<DesktopEnvironment> get_available_desktops() {
    std::vector<DesktopEnvironment> desktops;
    
    // Check for common Wayland desktop environments
    if (fs::exists("/usr/bin/sway")) {
        desktops.push_back({"sway", "sway", "Sway - i3-compatible Wayland compositor"});
    }
    if (fs::exists("/usr/bin/wayfire")) {
        desktops.push_back({"wayfire", "wayfire", "Wayfire - 3D Wayland compositor"});
    }
    if (fs::exists("/usr/bin/hikari")) {
        desktops.push_back({"hikari", "hikari", "Hikari - stacking Wayland compositor"});
    }
    if (fs::exists("/usr/bin/qtile")) {
        desktops.push_back({"qtile", "qtile start", "Qtile - full-featured tiling window manager"});
    }
    if (fs::exists("/usr/bin/gnome-shell") && fs::exists("/usr/bin/gnome-session")) {
        desktops.push_back({"gnome", "gnome-session --session=gnome-wayland", "GNOME - Modern desktop environment"});
    }
    if (fs::exists("/usr/bin/startplasma-wayland")) {
        desktops.push_back({"kde", "startplasma-wayland", "KDE Plasma - Feature-rich desktop environment"});
    }
    
    return desktops;
}

// Display available desktop environments and let user choose
int select_desktop(const std::vector<DesktopEnvironment>& desktops) {
    std::cout << "\nAvailable Desktop Environments:\n";
    for (size_t i = 0; i < desktops.size(); ++i) {
        std::cout << i + 1 << ". " << desktops[i].name << " - " << desktops[i].description << "\n";
    }
    
    int choice = 0;
    while (choice < 1 || choice > desktops.size()) {
        std::cout << "\nSelect desktop (1-" << desktops.size() << "): ";
        std::cin >> choice;
        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            choice = 0;
        }
    }
    
    return choice - 1;
}

// Authenticate user
bool authenticate_user(const std::string& username, const std::string& password) {
    struct passwd *pw = getpwnam(username.c_str());
    if (!pw) {
        std::cerr << "User not found\n";
        return false;
    }
    
    struct spwd *sp = getspnam(username.c_str());
    if (!sp) {
        std::cerr << "Cannot access shadow database (run as root)\n";
        return false;
    }
    
    char *encrypted = crypt(password.c_str(), sp->sp_pwdp);
    if (!encrypted) {
        std::cerr << "Crypt error\n";
        return false;
    }
    
    return strcmp(encrypted, sp->sp_pwdp) == 0;
}

// Execute command with environment variables
void execute_command(const std::string& command, const std::string& username) {
    // Get user info
    struct passwd *pw = getpwnam(username.c_str());
    if (!pw) {
        std::cerr << "Failed to get user info\n";
        exit(EXIT_FAILURE);
    }
    
    // Fork and execute
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        // Set environment variables
        setenv("HOME", pw->pw_dir, 1);
        setenv("USER", pw->pw_name, 1);
        setenv("LOGNAME", pw->pw_name, 1);
        setenv("SHELL", pw->pw_shell, 1);
        setenv("XDG_RUNTIME_DIR", ("/run/user/" + std::to_string(pw->pw_uid)).c_str(), 1);
        setenv("WAYLAND_DISPLAY", "wayland-1", 1);
        
        // Switch to user
        if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
            std::cerr << "Failed to switch user\n";
            exit(EXIT_FAILURE);
        }
        
        // Change directory to user's home
        if (chdir(pw->pw_dir) != 0) {
            std::cerr << "Failed to change directory\n";
            exit(EXIT_FAILURE);
        }
        
        // Execute command
        wordexp_t p;
        if (wordexp(command.c_str(), &p, 0) != 0) {
            std::cerr << "Failed to parse command\n";
            exit(EXIT_FAILURE);
        }
        
        execvp(p.we_wordv[0], p.we_wordv);
        std::cerr << "Failed to execute command\n";
        exit(EXIT_FAILURE);
    } else if (pid < 0) {
        // Fork failed
        std::cerr << "Failed to fork\n";
        exit(EXIT_FAILURE);
    } else {
        // Parent process - wait for child to exit
        int status;
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status)) {
            std::cout << "Desktop environment exited with status: " << WEXITSTATUS(status) << "\n";
        } else if (WIFSIGNALED(status)) {
            std::cout << "Desktop environment killed by signal: " << WTERMSIG(status) << "\n";
        }
    }
}

int main() {
    // Check if running as root
    if (getuid() != 0) {
        std::cerr << "This program must be run as root\n";
        return EXIT_FAILURE;
    }
    
    // Get available desktop environments
    auto desktops = get_available_desktops();
    if (desktops.empty()) {
        std::cerr << "No Wayland desktop environments found\n";
        return EXIT_FAILURE;
    }
    
    // Main loop
    while (true) {
        std::cout << "\nWayland Login Manager\n";
        std::cout << "--------------------\n";
        
        // Get username
        std::string username;
        std::cout << "Username: ";
        std::cin >> username;
        
        // Get password (simple method - in production use termios to disable echo)
        std::string password;
        std::cout << "Password: ";
        std::cin >> password;
        
        // Authenticate
        if (!authenticate_user(username, password)) {
            std::cerr << "Authentication failed\n";
            continue;
        }
        
        // Select desktop
        int desktop_index = select_desktop(desktops);
        
        // Launch desktop
        std::cout << "Starting " << desktops[desktop_index].name << "...\n";
        execute_command(desktops[desktop_index].exec_command, username);
        
        // After desktop exits, ask if user wants to login again
        std::cout << "\nSession ended. Login again? (y/n): ";
        char choice;
        std::cin >> choice;
        if (choice != 'y' && choice != 'Y') {
            break;
        }
    }
    
    return EXIT_SUCCESS;
}
