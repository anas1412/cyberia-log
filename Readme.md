# 📊 Cyberia Log - A Modern Trading Journal

Cyberia Log is a sleek, modern, and self-hosted trading journal designed to help traders meticulously track, analyze, and improve their performance. Built with a lightweight and powerful tech stack, it provides a fast, responsive, and intuitive user experience without the need for heavy frameworks.

_(It is highly recommended to replace this placeholder with a high-quality screenshot or a GIF of your application in action!)_

## ✨ Features

Cyberia Log comes packed with features to cover every aspect of your trading journal needs.

### 🔐 Authentication & Security

- **Secure Login/Signup System:** Robust session management and password hashing.
- **CSRF Protection:** All form submissions are protected against Cross-Site Request Forgery attacks.
- **Admin & User Roles:** A built-in admin role for user management.

### 📈 Interactive Dashboard

- **At-a-Glance Statistics:** Key metrics like Current Capital, Total PnL ($), Profit (%), and Win Rate.
- **Interactive Equity Curve:** Visualize your account's growth over time.
- **Dynamic Chart Views:** Toggle the equity curve between absolute dollar amounts ($) and percentage (%) growth.
- **Trading Calendar:** A monthly calendar view showing your PnL for each trading day, with results displayed in $, %, or R-Multiple.

### 📓 Comprehensive Trade Management

- **Log Detailed Trades:** Record instrument, outcome, risk, PnL, direction, setup type, screenshot link, and personal notes.
- **Dynamic Trade History:** View all your trades in a clean, paginated table.
- **Advanced Filtering:** Instantly filter trades by date range, outcome (win/loss/BE), direction (long/short), and setup type.
- **Easy CRUD Operations:** Add, edit, and delete trades seamlessly with instant feedback.

### 🗂️ Multi-Account Support

- **Manage All Your Accounts:** Add and manage multiple trading accounts, including Personal, Prop-Firm Challenges, Verification, and Funded accounts.
- **Global Account Filter:** Filter the entire application's data (Dashboard, Trades) to a single account or view all accounts combined.
- **Account Details:** Store account number, password (with a show/hide toggle), platform, and prop firm info.

### ⚙️ User Settings & Customization

- **Personalization:** Change your public codename and update your password securely.
- **Display Preferences:** Customize how PnL is displayed throughout the application (absolute $, percentage of capital %, or R-Multiple).

### 👮 Admin Panel (For Admins Only)

- **Full User Management:** View a paginated list of all registered users.
- **Search & Filter:** Quickly find users by codename or email, and filter by role.
- **Role Management:** Promote users to Admin or demote them with a simple toggle.
- **Secure Deletion:** Delete users from the system (with built-in protection against self-deletion).

## 🚀 Tech Stack

This project leverages a modern, lightweight stack for a fast and responsive experience:

- **Backend:** **PHP 8+** (with the PDO SQLite extension)
- **Database:** **SQLite** (for a simple, file-based, zero-configuration database)
- **Frontend Framework:** **Alpine.js** (for reactive UI components and state management)
- **AJAX & Interactivity:** **HTMX** (for smooth, partial-page updates without writing complex JavaScript)
- **Styling:** **Tailwind CSS** (for a utility-first, modern design)
- **Charting:** **Chart.js** (for the beautiful and interactive equity curve)

## 🏁 Getting Started

Follow these instructions to get Cyberia Log up and running on your local machine or server.

### Prerequisites

- A web server (Apache, Nginx, etc.)
- PHP 7.4 or higher
- The `pdo_sqlite` PHP extension enabled

### Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/cyberia-log.git
    cd cyberia-log
    ```

2.  **Configure your web server:**

    - Point your web server's document root to the `cyberia-log` directory where `index.php` is located.

3.  **Set File Permissions:**

    - The web server needs permission to create and write to the SQLite database file. On Linux, you can grant permission to the directory:

    ```bash
    # Give the web server user (e.g., www-data for Apache/Nginx on Debian/Ubuntu) ownership
    sudo chown -R www-data:www-data .

    # Or, give write permissions to the directory
    sudo chmod -R 775 .
    ```

4.  **Launch the Application:**
    - Navigate to the URL of your project in a web browser (e.g., `http://localhost`).
    - The application will automatically create the `trader_journal.sqlite` database and the necessary tables on its first run.

## 📖 Usage

### Default Admin Account

An admin account is created by default to allow you to manage the application immediately.

- **Email:** `admin@mail.com`
- **Password:** `admin1412`

It is **strongly recommended** to log in and change the default admin password from the **Settings** page.

## 📜 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## 👤 Author

Created by **NAS**

- **GitHub:** [@anas1412](https://github.com/anas1412)
- **Twitter:** [@villainesthetic](https://twitter.com/villainesthetic)
