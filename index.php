<?php
// ========== CONFIGURATION & INITIALIZATION ==========
ini_set('display_errors', 1);
error_reporting(E_ALL);

define('DB_FILE', __DIR__ . '/trader_journal.sqlite');
define('PER_PAGE', 10); // Items per page for all tables

// ========== SECURE SESSION SETUP ==========
session_set_cookie_params(['lifetime' => 86400, 'path' => '/', 'domain' => '', 'secure' => isset($_SERVER['HTTPS']), 'httponly' => true, 'samesite' => 'Strict']);
session_start();

// ========== AUTH HELPERS ==========
function is_logged_in() { return isset($_SESSION['user_id']); }
function is_admin() { return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true; }

// ========== CSRF PROTECTION ==========
function generate_csrf_token() { if (empty($_SESSION['csrf_token'])) { $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); } return $_SESSION['csrf_token']; }
function validate_csrf_token() { if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) { http_response_code(403); exit('Invalid CSRF token.'); } }

// ========== DATABASE SETUP ==========
function getDB() { static $db = null; if ($db === null) { $db = new PDO('sqlite:' . DB_FILE); $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC); } return $db; }
function initDB() {
    $db = getDB();
    $db->beginTransaction();
    try {
        if (!$db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")->fetch()) {
            $db->exec("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, codename TEXT NOT NULL, is_admin BOOLEAN DEFAULT 0, pnl_display_unit TEXT DEFAULT 'amount', calendar_pnl_unit TEXT DEFAULT 'amount')");
            $db->exec("CREATE TABLE accounts (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, account_number TEXT NOT NULL, password TEXT, type TEXT NOT NULL, platform TEXT, state TEXT DEFAULT 'active', starting_capital REAL NOT NULL, current_capital REAL NOT NULL, prop_firm TEXT, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)");
            $db->exec("CREATE TABLE trades (id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL, user_id INTEGER NOT NULL, date TEXT NOT NULL, instrument TEXT NOT NULL, outcome TEXT NOT NULL, risk_amount REAL DEFAULT 0, pnl_amount REAL DEFAULT 0, direction TEXT, type TEXT, screenshot_link TEXT, notes TEXT, FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)");
            $admin_email = 'admin@mail.com'; $admin_codename = 'Admin'; $admin_password = password_hash('admin1412', PASSWORD_DEFAULT);
            $stmt = $db->prepare("INSERT INTO users (email, codename, password, is_admin) VALUES (?, ?, ?, 1)");
            $stmt->execute([$admin_email, $admin_codename, $admin_password]);
        } else {
            $user_cols = array_column($db->query("PRAGMA table_info(users)")->fetchAll(), 'name');
            if (in_array('risk_display_unit', $user_cols)) { $db->exec("ALTER TABLE users RENAME COLUMN risk_display_unit TO pnl_display_unit"); }
            if (!in_array('pnl_display_unit', $user_cols)) { $db->exec("ALTER TABLE users ADD COLUMN pnl_display_unit TEXT DEFAULT 'amount'"); }
            if (!in_array('calendar_pnl_unit', $user_cols)) { $db->exec("ALTER TABLE users ADD COLUMN calendar_pnl_unit TEXT DEFAULT 'amount'"); }
        }
        $db->commit();
    } catch (Exception $e) { $db->rollBack(); die("Database initialization failed: " . $e->getMessage()); }
}

// ========== ROUTER ==========
initDB();
$action = $_GET['action'] ?? 'show_page';
$method = $_SERVER['REQUEST_METHOD'];
switch ($action) {
    case 'show_page': main_page_router(); break; case 'login': if ($method === 'POST') handle_login(); break; case 'signup': if ($method === 'POST') handle_signup(); break; case 'logout': handle_logout(); break;
    case 'add_account': if ($method === 'POST') handle_add_account(); break; case 'get_account_details': if ($method === 'GET') handle_get_account_details(); break; case 'update_account': if ($method === 'POST') handle_update_account(); break; case 'delete_account': if ($method === 'POST') handle_delete_account(); break;
    case 'add_trade': if ($method === 'POST') handle_add_trade(); break; case 'get_trade_details': if ($method === 'GET') handle_get_trade_details(); break; case 'update_trade': if ($method === 'POST') handle_update_trade(); break; case 'delete_trade': if ($method === 'POST') handle_delete_trade(); break;
    case 'set_account_filter': if ($method === 'POST') handle_set_account_filter(); break; case 'get_calendar': if ($method === 'GET') handle_get_calendar(); break; case 'get_accounts_table': if ($method === 'GET') handle_get_accounts_table(); break; case 'get_trades_table': if ($method === 'GET') handle_get_trades_table(); break;
    case 'get_equity_data': if ($method === 'GET' && is_logged_in()) handle_get_equity_data(); break;
    case 'change_password': if ($method === 'POST') handle_change_password(); break; case 'change_codename': if ($method === 'POST') handle_change_codename(); break; case 'save_preferences': if ($method === 'POST') handle_save_preferences(); break;
    // Admin Routes
    case 'get_admin_users_table': if ($method === 'GET' && is_admin()) handle_get_admin_users_table(); break;
    case 'delete_user': if ($method === 'POST' && is_admin()) handle_delete_user(); break;
    case 'toggle_user_role': if ($method === 'POST' && is_admin()) handle_toggle_user_role(); break;
    default: http_response_code(404); echo "404 - Action not found."; break;
}

// ========== PAGE ROUTER ==========
function main_page_router() { if (is_logged_in()) { render_app_view(); } else { render_login_view(); } }

// ========== AUTHENTICATION HANDLERS ==========
function handle_login() { validate_csrf_token(); $db = getDB(); $stmt = $db->prepare("SELECT * FROM users WHERE email = ?"); $stmt->execute([$_POST['email']]); $user = $stmt->fetch(); if ($user && password_verify($_POST['password'], $user['password'])) { session_regenerate_id(true); $_SESSION['user_id'] = $user['id']; $_SESSION['codename'] = $user['codename']; $_SESSION['is_admin'] = (bool)$user['is_admin']; $_SESSION['selected_account_id'] = 'all'; } else { $_SESSION['error_message'] = 'Invalid email or password.'; } header('Location: index.php'); exit(); }
function handle_signup() { validate_csrf_token(); $email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL); if (!filter_var($email, FILTER_VALIDATE_EMAIL) || !str_ends_with(strtolower($email), '@gmail.com')) { $_SESSION['error_message'] = 'Invalid email format or not a Gmail account.'; header('Location: index.php'); exit(); } $db = getDB(); $hashed_password = password_hash($_POST['password'], PASSWORD_DEFAULT); $stmt = $db->prepare("INSERT INTO users (codename, email, password) VALUES (?, ?, ?)"); $stmt->execute([$_POST['codename'], $email, $hashed_password]); $_SESSION['user_id'] = $db->lastInsertId(); $_SESSION['codename'] = $_POST['codename']; $_SESSION['is_admin'] = false; $_SESSION['selected_account_id'] = 'all'; header('Location: index.php'); exit(); }
function handle_logout() { session_destroy(); header('Location: index.php'); exit(); }

// ========== SETTINGS HANDLERS ==========
function handle_change_password() { if (!is_logged_in()) exit('Unauthorized'); validate_csrf_token(); $db = getDB(); $user_id = $_SESSION['user_id']; $stmt = $db->prepare("SELECT password FROM users WHERE id = ?"); $stmt->execute([$user_id]); $user = $stmt->fetch(); if (!$user || !password_verify($_POST['current_password'], $user['password'])) { header('HX-Trigger: {"showToast":{"message":"Error: Current password is incorrect."}}'); http_response_code(400); exit; } if ($_POST['new_password'] !== $_POST['confirm_password']) { header('HX-Trigger: {"showToast":{"message":"Error: New passwords do not match."}}'); http_response_code(400); exit; } $new_hash = password_hash($_POST['new_password'], PASSWORD_DEFAULT); $stmt = $db->prepare("UPDATE users SET password = ? WHERE id = ?"); $stmt->execute([$new_hash, $user_id]); header('HX-Trigger: {"showToast":{"message":"Password changed successfully!"}}'); http_response_code(204); }
function handle_change_codename() { if (!is_logged_in()) exit('Unauthorized'); validate_csrf_token(); $db = getDB(); $user_id = $_SESSION['user_id']; $new_codename = trim($_POST['new_codename'] ?? ''); if (empty($new_codename)) { header('HX-Trigger: {"showToast":{"message":"Error: Codename cannot be empty."}}'); http_response_code(400); exit; } $stmt = $db->prepare("UPDATE users SET codename = ? WHERE id = ?"); $stmt->execute([$new_codename, $user_id]); $_SESSION['codename'] = $new_codename; header('HX-Trigger: {"showToast":{"message":"Codename updated successfully!"}, "reload-page":{}}'); http_response_code(204); }
function handle_save_preferences() {
    if (!is_logged_in()) exit('Unauthorized'); validate_csrf_token();
    $db = getDB(); $user_id = $_SESSION['user_id'];
    $pnl_unit = in_array($_POST['pnl_display_unit'], ['amount', 'percent', 'rr']) ? $_POST['pnl_display_unit'] : 'amount';
    $calendar_pnl_unit = in_array($_POST['calendar_pnl_unit'], ['amount', 'percent', 'rr']) ? $_POST['calendar_pnl_unit'] : 'amount';
    $stmt = $db->prepare("UPDATE users SET pnl_display_unit = ?, calendar_pnl_unit = ? WHERE id = ?");
    $stmt->execute([$pnl_unit, $calendar_pnl_unit, $user_id]);
    header('HX-Trigger: {"showToast":{"message":"Preferences saved!"}, "reload-page":{}}'); http_response_code(204);
}

// ========== ADMIN HANDLERS ==========
function handle_delete_user() {
    validate_csrf_token();
    $user_id_to_delete = (int)($_POST['user_id'] ?? 0);
    if ($user_id_to_delete === $_SESSION['user_id']) {
        header('HX-Trigger: {"showToast":{"message":"Error: You cannot delete your own account."}}');
        http_response_code(403);
    } else if ($user_id_to_delete > 0) {
        $db = getDB();
        $stmt = $db->prepare("DELETE FROM users WHERE id = ?");
        $stmt->execute([$user_id_to_delete]);
        header('HX-Trigger: {"showToast":{"message":"User deleted successfully!"}}');
    }
    echo handle_get_admin_users_table(false);
    exit;
}
function handle_toggle_user_role() {
    validate_csrf_token();
    $user_id_to_toggle = (int)($_POST['user_id'] ?? 0);
    if ($user_id_to_toggle === $_SESSION['user_id']) {
        header('HX-Trigger: {"showToast":{"message":"Error: You cannot change your own role."}}');
        http_response_code(403);
    } else if ($user_id_to_toggle > 0) {
        $db = getDB();
        $new_role = isset($_POST['is_admin']) ? 1 : 0;
        $stmt = $db->prepare("UPDATE users SET is_admin = ? WHERE id = ?");
        $stmt->execute([$new_role, $user_id_to_toggle]);
        header('HX-Trigger: {"showToast":{"message":"User role updated!"}}');
    }
    echo handle_get_admin_users_table(false);
    exit;
}

// ========== CRUD HANDLERS ==========
function handle_add_account() { if (!is_logged_in()) exit('Unauthorized'); validate_csrf_token(); $db = getDB(); $stmt = $db->prepare("INSERT INTO accounts (user_id, account_number, password, type, platform, state, starting_capital, current_capital, prop_firm) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"); $stmt->execute([$_SESSION['user_id'], $_POST['account_number'], $_POST['password'], $_POST['type'], $_POST['platform'], $_POST['state'], (float)($_POST['starting_capital'] ?? 0), (float)($_POST['starting_capital'] ?? 0), ($_POST['type'] !== 'personal' ? $_POST['prop_firm'] : null)]); header('HX-Trigger: {"showToast":{"message":"Account added successfully!"}, "reload-page": {}}'); http_response_code(204); }
function handle_get_account_details() { if (!is_logged_in()) exit(json_encode(['error' => 'Unauthorized'])); $db = getDB(); $stmt = $db->prepare("SELECT * FROM accounts WHERE id = ? AND user_id = ?"); $stmt->execute([$_GET['id'], $_SESSION['user_id']]); $account = $stmt->fetch(); header('Content-Type: application/json'); echo json_encode($account ?: null); }
function handle_update_account() { if (!is_logged_in()) exit('Unauthorized'); validate_csrf_token(); $db = getDB(); $stmt = $db->prepare("UPDATE accounts SET account_number = ?, password = ?, type = ?, platform = ?, state = ?, starting_capital = ?, prop_firm = ? WHERE id = ? AND user_id = ?"); $stmt->execute([$_POST['account_number'], $_POST['password'], $_POST['type'], $_POST['platform'], $_POST['state'], (float)($_POST['starting_capital'] ?? 0), ($_POST['type'] !== 'personal' ? $_POST['prop_firm'] : null), $_POST['id'], $_SESSION['user_id']]); header('HX-Trigger: {"showToast":{"message":"Account updated successfully!"}, "reload-page": {}}'); http_response_code(204); }
function handle_delete_account() { if (!is_logged_in()) exit('Unauthorized'); validate_csrf_token(); $account_id = $_POST['id'] ?? 0; if ($account_id > 0) { $db = getDB(); $stmt = $db->prepare("DELETE FROM accounts WHERE id = ? AND user_id = ?"); $stmt->execute([$account_id, $_SESSION['user_id']]); if ($_SESSION['selected_account_id'] == $account_id) { $_SESSION['selected_account_id'] = 'all'; } } header('HX-Trigger: {"showToast":{"message":"Account deleted successfully!"}, "reload-page": {}}'); http_response_code(204); }
function handle_add_trade() { if (!is_logged_in()) exit('Unauthorized'); validate_csrf_token(); $db = getDB(); $pnl = (float)$_POST['pnl_amount']; $risk = (float)$_POST['risk_amount']; $sql = "INSERT INTO trades (user_id, account_id, date, instrument, outcome, risk_amount, pnl_amount, direction, type, screenshot_link, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"; $stmt = $db->prepare($sql); $stmt->execute([$_SESSION['user_id'], $_POST['account_id'], $_POST['date'], $_POST['instrument'], $_POST['outcome'], $risk, $pnl, $_POST['direction'], $_POST['type'], $_POST['screenshot_link'], $_POST['notes']]); $db->prepare("UPDATE accounts SET current_capital = current_capital + ? WHERE id = ?")->execute([$pnl, $_POST['account_id']]); header('HX-Trigger: {"showToast":{"message":"Trade logged successfully!"}, "reload-page":{}}'); http_response_code(204); }
function handle_get_trade_details() { if (!is_logged_in()) exit(json_encode(['error' => 'Unauthorized'])); $db = getDB(); $stmt = $db->prepare("SELECT * FROM trades WHERE id = ? AND user_id = ?"); $stmt->execute([$_GET['id'], $_SESSION['user_id']]); $trade = $stmt->fetch(); header('Content-Type: application/json'); echo json_encode($trade ?: null); }
function handle_update_trade() { if (!is_logged_in()) exit('Unauthorized'); validate_csrf_token(); $db = getDB(); $trade_id = $_POST['id']; $db->beginTransaction(); try { $stmt = $db->prepare("SELECT pnl_amount, account_id FROM trades WHERE id = ? AND user_id = ?"); $stmt->execute([$trade_id, $_SESSION['user_id']]); if (!($old_trade = $stmt->fetch())) { throw new Exception("Trade not found."); } $pnl_diff = (float)$_POST['pnl_amount'] - $old_trade['pnl_amount']; $sql = "UPDATE trades SET date=?, instrument=?, outcome=?, risk_amount=?, pnl_amount=?, direction=?, type=?, screenshot_link=?, notes=?, account_id=? WHERE id=?"; $db->prepare($sql)->execute([$_POST['date'], $_POST['instrument'], $_POST['outcome'], (float)$_POST['risk_amount'], (float)$_POST['pnl_amount'], $_POST['direction'], $_POST['type'], $_POST['screenshot_link'], $_POST['notes'], $_POST['account_id'], $trade_id]); if ($old_trade['account_id'] != $_POST['account_id']) { $db->prepare("UPDATE accounts SET current_capital = current_capital - ? WHERE id = ?")->execute([$old_trade['pnl_amount'], $old_trade['account_id']]); $db->prepare("UPDATE accounts SET current_capital = current_capital + ? WHERE id = ?")->execute([(float)$_POST['pnl_amount'], $_POST['account_id']]); } else { $db->prepare("UPDATE accounts SET current_capital = current_capital + ? WHERE id = ?")->execute([$pnl_diff, $_POST['account_id']]); } $db->commit(); } catch (Exception $e) { $db->rollBack(); http_response_code(500); exit($e->getMessage()); } header('HX-Trigger: {"showToast":{"message":"Trade updated successfully!"}, "reload-page":{}}'); http_response_code(204); }
function handle_delete_trade() { if (!is_logged_in()) exit('Unauthorized'); validate_csrf_token(); $db = getDB(); $trade_id = $_POST['id']; $db->beginTransaction(); try { $stmt = $db->prepare("SELECT pnl_amount, account_id FROM trades WHERE id = ? AND user_id = ?"); $stmt->execute([$trade_id, $_SESSION['user_id']]); if ($trade = $stmt->fetch()) { $db->prepare("UPDATE accounts SET current_capital = current_capital - ? WHERE id = ?")->execute([$trade['pnl_amount'], $trade['account_id']]); $db->prepare("DELETE FROM trades WHERE id = ?")->execute([$trade_id]); } $db->commit(); } catch (Exception $e) { $db->rollBack(); http_response_code(500); exit($e->getMessage()); } header('HX-Trigger: {"showToast":{"message":"Trade deleted successfully!"}, "reload-page":{}}'); http_response_code(204); }

// ========== HTMX PARTIAL HANDLERS ==========
function handle_set_account_filter() { if (!is_logged_in()) exit('Unauthorized'); validate_csrf_token(); $_SESSION['selected_account_id'] = $_POST['account_id'] ?? 'all'; header('HX-Trigger: {"reload-page": {}}'); http_response_code(204); }
function handle_get_calendar() { if (!is_logged_in()) exit('Unauthorized'); $month = (int)($_GET['month'] ?? date('m')); $year = (int)($_GET['year'] ?? date('Y')); echo get_calendar_html_fragment($month, $year); }
function handle_get_accounts_table($echo = true) {
    if (!is_logged_in()) exit('Unauthorized');
    $db = getDB();
    $page = (int)($_GET['page'] ?? 1);
    $offset = ($page - 1) * PER_PAGE;
    $filters = ['type' => $_GET['type'] ?? 'all', 'state' => $_GET['state'] ?? 'all'];

    $where_clauses = ["user_id = ?"];
    $params = [$_SESSION['user_id']];
    if ($filters['type'] !== 'all') { $where_clauses[] = "type = ?"; $params[] = $filters['type']; }
    if ($filters['state'] !== 'all') { $where_clauses[] = "state = ?"; $params[] = $filters['state']; }
    $where_sql = implode(" AND ", $where_clauses);

    $count_stmt = $db->prepare("SELECT COUNT(*) FROM accounts WHERE {$where_sql}");
    $count_stmt->execute($params);
    $total_items = $count_stmt->fetchColumn();
    $total_pages = ceil($total_items / PER_PAGE);

    $data_stmt = $db->prepare("SELECT * FROM accounts WHERE {$where_sql} ORDER BY id DESC LIMIT ? OFFSET ?");
    $data_stmt->execute(array_merge($params, [PER_PAGE, $offset]));
    $accounts = $data_stmt->fetchAll();

    $fragment = get_accounts_html_fragment(generate_csrf_token(), $accounts, $page, $total_pages, $filters);
    if ($echo) { echo $fragment; }
    return $fragment;
}
function handle_get_trades_table($echo = true) {
    if (!is_logged_in()) exit('Unauthorized');
    $db = getDB();
    $page = (int)($_GET['page'] ?? 1);
    $offset = ($page - 1) * PER_PAGE;
    $filters = [
        'outcome' => $_GET['outcome'] ?? 'all', 'direction' => $_GET['direction'] ?? 'all',
        'type' => $_GET['type'] ?? 'all', 'date_start' => $_GET['date_start'] ?? '', 'date_end' => $_GET['date_end'] ?? ''
    ];

    $where_clauses = ["t.user_id = ?"];
    $params = [$_SESSION['user_id']];
    
    $selected_account_id = $_SESSION['selected_account_id'] ?? 'all';
    if ($selected_account_id !== 'all') {
        $where_clauses[] = "t.account_id = ?";
        $params[] = $selected_account_id;
    }
    
    if ($filters['outcome'] !== 'all') { $where_clauses[] = "t.outcome = ?"; $params[] = $filters['outcome']; }
    if ($filters['direction'] !== 'all') { $where_clauses[] = "t.direction = ?"; $params[] = $filters['direction']; }
    if ($filters['type'] !== 'all') { $where_clauses[] = "t.type = ?"; $params[] = $filters['type']; }
    if (!empty($filters['date_start'])) { $where_clauses[] = "t.date >= ?"; $params[] = $filters['date_start']; }
    if (!empty($filters['date_end'])) { $where_clauses[] = "t.date <= ?"; $params[] = $filters['date_end']; }
    $where_sql = implode(" AND ", $where_clauses);

    $count_stmt = $db->prepare("SELECT COUNT(*) FROM trades t WHERE {$where_sql}");
    $count_stmt->execute($params);
    $total_items = $count_stmt->fetchColumn();
    $total_pages = ceil($total_items / PER_PAGE);

    $data_sql = "SELECT t.*, a.account_number, a.starting_capital FROM trades t JOIN accounts a ON t.account_id = a.id WHERE {$where_sql} ORDER BY t.date DESC, t.id DESC LIMIT ? OFFSET ?";
    $data_stmt = $db->prepare($data_sql);
    $data_stmt->execute(array_merge($params, [PER_PAGE, $offset]));
    $trades = $data_stmt->fetchAll();

    $fragment = get_trades_html_fragment(generate_csrf_token(), $trades, $page, $total_pages, $filters);
    if ($echo) { echo $fragment; }
    return $fragment;
}
function handle_get_admin_users_table($echo = true) {
    if (!is_admin()) exit('Unauthorized');
    $db = getDB();
    $page = (int)($_GET['page'] ?? 1);
    $offset = ($page - 1) * PER_PAGE;
    $filters = ['q' => trim($_GET['q'] ?? ''), 'admin_filter' => $_GET['admin_filter'] ?? 'all'];

    $where_clauses = []; $params = [];
    if (!empty($filters['q'])) { $where_clauses[] = "(codename LIKE ? OR email LIKE ?)"; $params[] = '%' . $filters['q'] . '%'; $params[] = '%' . $filters['q'] . '%'; }
    if ($filters['admin_filter'] === 'admin') { $where_clauses[] = "is_admin = 1"; }
    $where_sql = empty($where_clauses) ? '1' : implode(" AND ", $where_clauses);

    $count_stmt = $db->prepare("SELECT COUNT(*) FROM users WHERE {$where_sql}");
    $count_stmt->execute($params);
    $total_items = $count_stmt->fetchColumn();
    $total_pages = ceil($total_items / PER_PAGE);

    $data_stmt = $db->prepare("SELECT id, codename, email, is_admin FROM users WHERE {$where_sql} ORDER BY id ASC LIMIT ? OFFSET ?");
    $data_stmt->execute(array_merge($params, [PER_PAGE, $offset]));
    $users = $data_stmt->fetchAll();

    $fragment = get_admin_users_html_fragment(generate_csrf_token(), $users, $page, $total_pages, $filters);
    if ($echo) { echo $fragment; }
    return $fragment;
}
function handle_get_equity_data() {
    $db = getDB();
    $filter = $_SESSION['selected_account_id'] ?? 'all';
    $params = [$_SESSION['user_id']];
    $account_where = "WHERE user_id = ?";
    if ($filter !== 'all') {
        $account_where .= " AND id = ?";
        $params[] = $filter;
    }

    $capital_stmt = $db->prepare("SELECT SUM(starting_capital) as total_starting_capital FROM accounts {$account_where}");
    $capital_stmt->execute($params);
    $starting_capital = (float)($capital_stmt->fetchColumn() ?? 0);
    
    $trade_where = "WHERE user_id = ?";
    $trade_params = [$_SESSION['user_id']];
    if ($filter !== 'all') {
        $trade_where .= " AND account_id = ?";
        $trade_params[] = $filter;
    }
    
    $trades_stmt = $db->prepare("SELECT pnl_amount FROM trades {$trade_where} ORDER BY date ASC, id ASC");
    $trades_stmt->execute($trade_params);
    $trades = $trades_stmt->fetchAll();

    $labels = ["Start"];
    $data_amount = [$starting_capital];
    $data_percent = [0.0];

    $running_balance = $starting_capital;
    $trade_count = 0;
    foreach ($trades as $trade) {
        $trade_count++;
        $running_balance += (float)$trade['pnl_amount'];
        
        $labels[] = "Trade #" . $trade_count;
        $data_amount[] = round($running_balance, 2);

        if ($starting_capital > 0) {
            $percent_growth = (($running_balance / $starting_capital) - 1) * 100;
            $data_percent[] = round($percent_growth, 2);
        } else {
            $data_percent[] = 0.0;
        }
    }
    
    header('Content-Type: application/json');
    echo json_encode([
        'labels' => $labels, 
        'data_amount' => $data_amount,
        'data_percent' => $data_percent
    ]);
    exit;
}

// ========== HTML RENDERING FUNCTIONS ==========
function render_login_view() {
    $error_message = $_SESSION['error_message'] ?? '';
    unset($_SESSION['error_message']);
    $csrf_token = generate_csrf_token();
    $alpine_init_data = json_encode(['currentView' => 'login']);
    
    $replacements = [
        '<!--ALPINE_INIT_DATA-->' => $alpine_init_data,
        '<!--APP_CONTENT-->' => file_get_contents('template.html'),
        '<!--ERROR_MESSAGE-->' => $error_message ? "<div class='p-3 my-2 text-sm text-red-100 bg-red-200/20 border border-red-500/30 rounded-md'>$error_message</div>" : '',
        '<!--DASHBOARD_CONTENT-->' => '',
        '<!--TRADES_CONTENT-->' => '',
        '<!--ACCOUNTS_CONTENT-->' => '',
        '<!--ADMIN_CONTENT-->' => '',
        '<!--NAVBAR_ACCOUNT_OPTIONS-->' => '',
        '<!--MODAL_ACCOUNT_OPTIONS-->' => '',
        '<!--CODENAME-->' => 'Guest',
        '<!--CSRF_TOKEN_FIELD-->' => "<input type='hidden' name='csrf_token' value='$csrf_token'>"
    ];
    echo str_replace(array_keys($replacements), array_values($replacements), get_main_layout());
}
function render_app_view() {
    $db = getDB(); $stmt = $db->prepare("SELECT COUNT(*) FROM accounts WHERE user_id = ?"); $stmt->execute([$_SESSION['user_id']]); $has_accounts = $stmt->fetchColumn() > 0;
    $user_data_stmt = $db->prepare("SELECT codename, pnl_display_unit, calendar_pnl_unit FROM users WHERE id = ?"); $user_data_stmt->execute([$_SESSION['user_id']]); $user_data = $user_data_stmt->fetch();
    $csrf_token = generate_csrf_token(); $alpine_init_data = json_encode(['currentView' => 'app', 'isAdmin' => is_admin(), 'hasAccounts' => $has_accounts, 'userData' => $user_data]);
    $replacements = ['<!--ALPINE_INIT_DATA-->' => $alpine_init_data, '<!--APP_CONTENT-->' => file_get_contents('template.html'), '<!--ERROR_MESSAGE-->' => '', '<!--DASHBOARD_CONTENT-->' => get_dashboard_html_fragment(), '<!--TRADES_CONTENT-->' => handle_get_trades_table(false), '<!--ACCOUNTS_CONTENT-->' => handle_get_accounts_table(false), '<!--ADMIN_CONTENT-->' => is_admin() ? handle_get_admin_users_table(false) : '', '<!--NAVBAR_ACCOUNT_OPTIONS-->' => get_accounts_options_html(true), '<!--MODAL_ACCOUNT_OPTIONS-->' => get_accounts_options_html(false), '<!--CODENAME-->' => htmlspecialchars($user_data['codename']), '<!--CSRF_TOKEN_FIELD-->' => "<input type='hidden' name='csrf_token' value='$csrf_token'>"];
    echo str_replace(array_keys($replacements), array_values($replacements), get_main_layout());
}

// ========== HTML FRAGMENT HELPERS ==========
function get_main_layout() { return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Cyberia Log</title><link rel="stylesheet" href="style.css"><script src="https://cdn.tailwindcss.com"></script><script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script><script src="https://unpkg.com/htmx.org@1.9.10"></script><script src="https://cdn.jsdelivr.net/npm/chart.js"></script><style>[x-cloak] { display: none !important; }</style></head><body class="bg-slate-900 text-slate-300"><div id="app-wrapper" x-data="app()" @open-edit-modal.window="openEditModal($event.detail)" @open-edit-trade-modal.window="openEditTradeModal($event.detail)" @open-note-modal.window="openNoteModal($event.detail)" @reload-page.window="window.location.reload()" x-cloak><!--APP_CONTENT--></div><div x-data="{ show: false, message: \'\' }" @showToast.window="message = $event.detail.message; show = true; setTimeout(() => show = false, 4000)" x-show="show" x-transition:enter="transition ease-out duration-300" x-transition:enter-start="opacity-0 transform translate-y-2" x-transition:enter-end="opacity-100 transform translate-y-0" x-transition:leave="transition ease-in duration-300" x-transition:leave-start="opacity-100 transform translate-y-0" x-transition:leave-end="opacity-0 transform translate-y-2" class="fixed bottom-5 right-5 px-4 py-3 text-white bg-cyan-600 rounded-lg shadow-lg z-50 font-medium" style="display: none;"><p x-text="message"></p></div><script type="application/json" id="alpine-init-data"><!--ALPINE_INIT_DATA--></script></body></html>'; }

function get_dashboard_html_fragment() {
    $db = getDB();
    $filter = $_SESSION['selected_account_id'] ?? 'all';
    $params = [$_SESSION['user_id']];
    $account_where = "WHERE user_id = ?";
    if ($filter !== 'all') {
        $account_where .= " AND id = ?";
        $params[] = $filter;
    }

    $capital_stmt = $db->prepare("SELECT SUM(starting_capital) as total_starting_capital, SUM(current_capital) as total_current_capital FROM accounts {$account_where}");
    $capital_stmt->execute($params);
    $capital_data = $capital_stmt->fetch();
    $starting_capital = $capital_data['total_starting_capital'] ?? 0;
    $current_capital = $capital_data['total_current_capital'] ?? 0;

    $trade_where = "WHERE user_id = ?";
    $trade_params = [$_SESSION['user_id']];
    if ($filter !== 'all') {
        $trade_where .= " AND account_id = ?";
        $trade_params[] = $filter;
    }
    $stats_stmt = $db->prepare("SELECT COUNT(*) as total_trades, SUM(CASE WHEN pnl_amount > 0 THEN 1 ELSE 0 END) as wins, SUM(pnl_amount) as total_pnl FROM trades {$trade_where}");
    $stats_stmt->execute($trade_params);
    $stats = $stats_stmt->fetch();
    
    $total_pnl = $stats['total_pnl'] ?? 0;
    $total_trades = $stats['total_trades'] ?? 0;
    $wins = $stats['wins'] ?? 0;
    $win_rate = ($total_trades > 0) ? round(($wins / $total_trades) * 100) : 0;
    $profit_percent = ($starting_capital > 0) ? ($total_pnl / $starting_capital) * 100 : 0;

    ob_start();
?>
<div class="grid grid-cols-1 gap-5 mb-8 sm:grid-cols-2 lg:grid-cols-4">
    <div class="p-5 bg-slate-800 rounded-lg shadow">
        <div class="text-sm font-medium text-slate-400">Capital</div>
        <div class="mt-1 text-3xl font-semibold text-slate-100">$<?= number_format($current_capital, 2) ?></div>
    </div>
    <div class="p-5 bg-slate-800 rounded-lg shadow">
        <div class="text-sm font-medium text-slate-400">Total PnL</div>
        <div class="mt-1 text-3xl font-semibold <?= $total_pnl >= 0 ? 'text-green-400' : 'text-red-400' ?>">
            $<?= number_format($total_pnl, 2) ?></div>
    </div>
    <div class="p-5 bg-slate-800 rounded-lg shadow">
        <div class="text-sm font-medium text-slate-400">Profit %</div>
        <div class="mt-1 text-3xl font-semibold <?= $profit_percent >= 0 ? 'text-green-400' : 'text-red-400' ?>">
            <?= number_format($profit_percent, 2) ?>%</div>
    </div>
    <div class="p-5 bg-slate-800 rounded-lg shadow">
        <div class="text-sm font-medium text-slate-400">Win Rate</div>
        <div class="mt-1 text-3xl font-semibold text-slate-100">
            <span title="Winning Trades"><?= $wins ?></span> / <span title="Total Trades"><?= $total_trades ?></span>
            <span class="text-lg ml-2">(<?= $win_rate ?>%)</span>
        </div>
    </div>
</div>
<div id="calendar-wrapper"><?= get_calendar_html_fragment() ?></div>
<?php
    return ob_get_clean();
}

function get_calendar_html_fragment($month = null, $year = null) {
    $db = getDB();
    $user_prefs_stmt = $db->prepare("SELECT calendar_pnl_unit FROM users WHERE id = ?"); $user_prefs_stmt->execute([$_SESSION['user_id']]); $prefs = $user_prefs_stmt->fetch();
    $month = $month ?? (int)date('m'); $year = $year ?? (int)date('Y'); $filter = $_SESSION['selected_account_id'] ?? 'all';
    $params = [$_SESSION['user_id'], sprintf('%d-%02d', $year, $month)];
    $where_clause = "WHERE t.user_id = ? AND strftime('%Y-%m', t.date) = ?";
    if ($filter !== 'all') { $where_clause .= " AND t.account_id = ?"; $params[] = $filter; }
    $sql = "SELECT t.date, SUM(t.pnl_amount) as daily_pnl, SUM(t.risk_amount) as daily_risk, a.starting_capital as account_capital FROM trades t JOIN accounts a ON t.account_id = a.id {$where_clause} GROUP BY t.date, a.starting_capital";
    $stmt = $db->prepare($sql); $stmt->execute($params); $daily_data = $stmt->fetchAll();
    $pnl_by_day = [];
    foreach ($daily_data as $data) {
        $pnl_by_day[$data['date']] = [ 'pnl' => ($pnl_by_day[$data['date']]['pnl'] ?? 0) + $data['daily_pnl'], 'risk' => ($pnl_by_day[$data['date']]['risk'] ?? 0) + $data['daily_risk'], 'capital' => $data['account_capital'] ];
    }
    $date = new DateTimeImmutable("$year-$month-01"); $days_in_month = (int)$date->format('t'); $first_day_of_month = (int)$date->format('N'); $prev_month_date = $date->modify('-1 month'); $next_month_date = $date->modify('+1 month');
    ob_start(); ?><div id="calendar-container" class="p-5 bg-slate-800 rounded-lg shadow">
    <div class="flex items-center justify-between mb-4"><button
            hx-get="index.php?action=get_calendar&month=<?= $prev_month_date->format('m') ?>&year=<?= $prev_month_date->format('Y') ?>"
            hx-target="#calendar-container" hx-swap="outerHTML"
            class="px-2 py-1 text-slate-300 hover:bg-slate-700 rounded">
            < Prev</button>
                <h3 class="text-lg font-semibold text-center text-slate-100"><?= $date->format('F Y') ?></h3><button
                    hx-get="index.php?action=get_calendar&month=<?= $next_month_date->format('m') ?>&year=<?= $next_month_date->format('Y') ?>"
                    hx-target="#calendar-container" hx-swap="outerHTML"
                    class="px-2 py-1 text-slate-300 hover:bg-slate-700 rounded">Next ></button></div>
    <div class="grid grid-cols-7 gap-2 text-center text-xs">
        <div class="font-bold text-slate-400">Mon</div>
        <div class="font-bold text-slate-400">Tue</div>
        <div class="font-bold text-slate-400">Wed</div>
        <div class="font-bold text-slate-400">Thu</div>
        <div class="font-bold text-slate-400">Fri</div>
        <div class="font-bold text-slate-400">Sat</div>
        <div class="font-bold text-slate-400">Sun</div><?php for ($i = 1; $i < $first_day_of_month; $i++): ?><div></div>
        <?php endfor; ?><?php for ($day = 1; $day <= $days_in_month; $day++): $current_date = sprintf('%d-%02d-%02d', $year, $month, $day); $day_data = $pnl_by_day[$current_date] ?? null; $pnl = $day_data['pnl'] ?? null;
    $display_value = '';
    if ($pnl !== null) {
        switch($prefs['calendar_pnl_unit']) {
            case 'percent': $display_value = ($day_data['capital'] > 0) ? number_format(($pnl / $day_data['capital']) * 100, 2) . '%' : 'N/A'; break;
            case 'rr': $display_value = ($day_data['risk'] > 0) ? number_format($pnl / $day_data['risk'], 2) . 'R' : 'N/A'; break;
            default: $display_value = '$' . number_format($pnl, 2); break;
        }
    }
    $class = 'flex flex-col items-center justify-center h-20 border border-slate-700 rounded'; if ($pnl !== null) {$class .= ($pnl >= 0) ? ' bg-green-500/10 text-green-400' : ' bg-red-500/10 text-red-400';} else {$class .= ' bg-slate-700/50';} ?>
        <div class="<?= $class ?>"><span
                class="font-bold text-slate-300"><?= $day ?></span><?php if ($pnl !== null): ?><span
                class="text-sm mt-1"><?= $display_value ?></span><?php endif; ?></div><?php endfor; ?>
    </div>
</div><?php return ob_get_clean();
}

function get_trades_html_fragment($csrf_token, $trades, $current_page, $total_pages, $filters) {
    $db = getDB(); $user_stmt = $db->prepare("SELECT pnl_display_unit FROM users WHERE id = ?"); $user_stmt->execute([$_SESSION['user_id']]); $prefs = $user_stmt->fetch();
    ob_start(); ?>
<div class="overflow-x-auto bg-slate-800 rounded-lg shadow">
    <table class="min-w-full divide-y divide-slate-700">
        <thead class="bg-slate-900">
            <tr>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Date</th>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Instrument
                </th>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Outcome</th>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Risk</th>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">PnL</th>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Direction
                </th>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Type</th>
                <th class="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Actions</th>
            </tr>
        </thead>
        <tbody class="bg-slate-800 divide-y divide-slate-700"><?php if (empty($trades)): ?><tr>
                <td colspan="8" class="py-4 text-center text-slate-400">No trades found.</td>
            </tr><?php else: foreach ($trades as $trade): ?>
            <?php
        $risk = $trade['risk_amount']; $pnl = $trade['pnl_amount']; $capital = $trade['starting_capital'];
        switch($prefs['pnl_display_unit']) {
            case 'percent': $risk_display = ($capital > 0) ? number_format(($risk / $capital) * 100, 2) . '%' : 'N/A'; $pnl_display = ($capital > 0) ? number_format(($pnl / $capital) * 100, 2) . '%' : 'N/A'; break;
            case 'rr': $risk_display = ($risk > 0) ? '1R' : '0R'; $pnl_display = ($risk > 0) ? number_format($pnl / $risk, 2) . 'R' : 'N/A'; break;
            default: $risk_display = '$' . number_format($risk, 2); $pnl_display = '$' . number_format($pnl, 2); break;
        }
    ?>
            <tr class="text-sm">
                <td class="px-4 py-4 whitespace-nowrap"><?= htmlspecialchars($trade['date']) ?></td>
                <td class="px-4 py-4 whitespace-nowrap font-semibold"><?= htmlspecialchars($trade['instrument']) ?></td>
                <td
                    class="px-4 py-4 whitespace-nowrap font-bold <?= $trade['outcome'] === 'win' ? 'text-green-400' : ($trade['outcome'] === 'loss' ? 'text-red-400' : 'text-slate-400') ?>">
                    <?= htmlspecialchars(strtoupper($trade['outcome'])) ?></td>
                <td class="px-4 py-4 whitespace-nowrap"><?= $risk_display ?></td>
                <td class="px-4 py-4 whitespace-nowrap"><?= $pnl_display ?></td>
                <td class="px-4 py-4 whitespace-nowrap"><?= htmlspecialchars(ucfirst($trade['direction'])) ?></td>
                <td class="px-4 py-4 whitespace-nowrap"><?= htmlspecialchars(ucfirst($trade['type'])) ?></td>
                <td class="px-4 py-4 whitespace-nowrap text-sm font-medium space-x-4">
                    <?php if(!empty($trade['screenshot_link'])): ?><a
                        href="<?= htmlspecialchars($trade['screenshot_link']) ?>" target="_blank"
                        class="text-cyan-400 hover:text-cyan-300">Image</a><?php endif; ?>
                    <?php if(!empty($trade['notes'])): ?><button
                        @click="$dispatch('open-note-modal', `<?= htmlspecialchars(addslashes($trade['notes'])) ?>`)"
                        class="text-slate-400 hover:text-slate-200">Note</button><?php endif; ?>
                    <button @click="$dispatch('open-edit-trade-modal', <?= $trade['id'] ?>)"
                        class="text-cyan-400 hover:text-cyan-300">Edit</button>
                    <form hx-post="index.php?action=delete_trade" hx-confirm="Are you sure?" class="inline"><input
                            type="hidden" name="id" value="<?= $trade['id'] ?>"><input type="hidden" name="csrf_token"
                            value="<?= $csrf_token ?>"><button type="submit"
                            class="font-medium text-red-500 hover:text-red-400">Delete</button></form>
                </td>
            </tr><?php endforeach; endif; ?>
        </tbody>
    </table>
</div>
<?= get_pagination_html('index.php?action=get_trades_table', $total_pages, $current_page, $filters, '#trades-table-container') ?>
<?php return ob_get_clean();
}

function get_accounts_html_fragment($csrf_token, $accounts, $current_page, $total_pages, $filters) { ob_start(); ?>
<div class="overflow-x-auto bg-slate-800 rounded-lg shadow">
    <table class="min-w-full divide-y divide-slate-700">
        <thead class="bg-slate-900">
            <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Account #
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Password
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Type</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Platform
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">State</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Capital</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Prop Firm
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Actions</th>
            </tr>
        </thead>
        <tbody class="bg-slate-800 divide-y divide-slate-700"><?php if (empty($accounts)): ?><tr>
                <td colspan="8" class="py-4 text-center text-slate-400">No accounts found.</td>
            </tr><?php else: foreach ($accounts as $account): ?><tr x-data="{ show: false }">
                <td class="px-6 py-4 whitespace-nowrap"><?= htmlspecialchars($account['account_number']) ?></td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <div class="flex items-center space-x-2"><span
                            x-text="show ? '<?= htmlspecialchars($account['password']) ?>' : '••••••••'"></span><button
                            @click="show = !show" class="text-xs text-cyan-400 hover:text-cyan-300"
                            x-text="show ? 'Hide' : 'Show'"></button></div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap"><?= htmlspecialchars(ucfirst($account['type'])) ?></td>
                <td class="px-6 py-4 whitespace-nowrap"><?= htmlspecialchars($account['platform']) ?></td>
                <td class="px-6 py-4 whitespace-nowrap"><span
                        class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full <?= get_state_bg_color($account['state']) ?>"><?= htmlspecialchars(ucfirst($account['state'])) ?></span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">$<?= number_format($account['current_capital'], 2) ?></td>
                <td class="px-6 py-4 whitespace-nowrap"><?= htmlspecialchars($account['prop_firm'] ?? 'N/A') ?></td>
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium"><button
                        @click="$dispatch('open-edit-modal', <?= $account['id'] ?>)"
                        class="text-cyan-400 hover:text-cyan-300">Edit</button>
                    <form hx-post="index.php?action=delete_account" hx-confirm="Are you sure?" class="inline ml-4">
                        <input type="hidden" name="id" value="<?= $account['id'] ?>"><input type="hidden"
                            name="csrf_token" value="<?= $csrf_token ?>"><button type="submit"
                            class="font-medium text-red-500 hover:text-red-400">Delete</button>
                    </form>
                </td>
            </tr><?php endforeach; endif; ?></tbody>
    </table>
</div>
<?= get_pagination_html('index.php?action=get_accounts_table', $total_pages, $current_page, $filters, '#accounts-table-container') ?>
<?php return ob_get_clean(); }

function get_admin_users_html_fragment($csrf_token, $users, $current_page, $total_pages, $filters) {
    ob_start(); ?>
<div class="overflow-x-auto bg-slate-800 rounded-lg shadow">
    <table class="min-w-full divide-y divide-slate-700">
        <thead class="bg-slate-900">
            <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Codename
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Email</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Role</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Actions</th>
            </tr>
        </thead>
        <tbody class="bg-slate-800 divide-y divide-slate-700">
            <?php if (empty($users)): ?><tr>
                <td colspan="4" class="py-4 text-center text-slate-400">No users found.</td>
            </tr>
            <?php else: foreach ($users as $user): $is_current_user = $user['id'] === $_SESSION['user_id']; ?>
            <tr class="text-sm">
                <td class="px-6 py-4 whitespace-nowrap font-semibold"><?= htmlspecialchars($user['codename']) ?></td>
                <td class="px-6 py-4 whitespace-nowrap"><?= htmlspecialchars($user['email']) ?></td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <?php if ($is_current_user): ?>
                    <div class="flex items-center text-slate-400 cursor-not-allowed"
                        title="You cannot change your own role."><svg xmlns="http://www.w3.org/2000/svg"
                            class="h-4 w-4 mr-2" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd"
                                d="M10 1a4.5 4.5 0 00-4.5 4.5V9H5a2 2 0 00-2 2v6a2 2 0 002 2h10a2 2 0 002-2v-6a2 2 0 00-2-2h-.5V5.5A4.5 4.5 0 0010 1zm3 8V5.5a3 3 0 10-6 0V9h6z"
                                clip-rule="evenodd" />
                        </svg><span><?= $user['is_admin'] ? 'Admin' : 'User' ?></span></div>
                    <?php else: ?>
                    <form hx-post="index.php?action=toggle_user_role" hx-trigger="change"
                        hx-target="#admin-users-table-container" hx-swap="innerHTML"
                        hx-include="[name='q'],[name='admin_filter']">
                        <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>"><input type="hidden"
                            name="user_id" value="<?= $user['id'] ?>">
                        <label class="relative inline-flex items-center cursor-pointer">
                            <input type="checkbox" name="is_admin" value="1" class="sr-only peer"
                                <?= $user['is_admin'] ? 'checked' : '' ?>>
                            <div
                                class="w-11 h-6 bg-slate-600 rounded-full peer peer-focus:ring-2 peer-focus:ring-cyan-500 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-0.5 after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-600">
                            </div>
                            <span
                                class="ml-3 text-sm font-medium text-slate-300"><?= $user['is_admin'] ? 'Admin' : 'User' ?></span>
                        </label>
                    </form>
                    <?php endif; ?>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <?php if ($is_current_user): ?>
                    <button class="flex items-center text-red-500/30 cursor-not-allowed" disabled
                        title="You cannot delete yourself."><svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1"
                            viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd"
                                d="M10 1a4.5 4.5 0 00-4.5 4.5V9H5a2 2 0 00-2 2v6a2 2 0 002 2h10a2 2 0 002-2v-6a2 2 0 00-2-2h-.5V5.5A4.5 4.5 0 0010 1zm3 8V5.5a3 3 0 10-6 0V9h6z"
                                clip-rule="evenodd" />
                        </svg>Locked</button>
                    <?php else: ?>
                    <form hx-post="index.php?action=delete_user"
                        hx-confirm="Are you sure you want to delete this user? This is irreversible."
                        hx-target="#admin-users-table-container" hx-swap="innerHTML"
                        hx-include="[name='q'],[name='admin_filter']" class="inline">
                        <input type="hidden" name="user_id" value="<?= $user['id'] ?>"><input type="hidden"
                            name="csrf_token" value="<?= $csrf_token ?>">
                        <button type="submit" class="font-medium text-red-500 hover:text-red-400">Delete</button>
                    </form>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; endif; ?>
        </tbody>
    </table>
</div>
<?= get_pagination_html('index.php?action=get_admin_users_table', $total_pages, $current_page, $filters, '#admin-users-table-container') ?>
<?php return ob_get_clean();
}

function get_pagination_html($base_url, $total_pages, $current_page, $filters, $target_id) {
    if ($total_pages <= 1) return '';
    $query_params = http_build_query(array_filter($filters));
    $base_url .= '?' . $query_params;

    ob_start(); ?>
<div class="flex items-center justify-between mt-4 px-2">
    <div class="flex-1 flex justify-between sm:hidden">
        <!-- Mobile pagination (simple prev/next) -->
    </div>
    <div class="hidden sm:flex-1 sm:flex sm:items-center sm:justify-center">
        <nav class="relative z-0 inline-flex rounded-md shadow-sm -space-x-px" aria-label="Pagination">
            <?php if ($current_page > 1): ?>
            <button hx-get="<?= $base_url ?>&page=<?= $current_page - 1 ?>" hx-target="<?= $target_id ?>"
                hx-swap="innerHTML"
                class="relative inline-flex items-center px-2 py-2 rounded-l-md border border-slate-700 bg-slate-800 text-sm font-medium text-slate-400 hover:bg-slate-700">Prev</button>
            <?php endif; ?>

            <?php for ($i = 1; $i <= $total_pages; $i++):
                    $is_current = $i == $current_page;
                    $class = $is_current
                        ? 'z-10 bg-cyan-600 border-cyan-500 text-white'
                        : 'bg-slate-800 border-slate-700 text-slate-400 hover:bg-slate-700';
                ?>
            <button hx-get="<?= $base_url ?>&page=<?= $i ?>" hx-target="<?= $target_id ?>" hx-swap="innerHTML"
                aria-current="<?= $is_current ? 'page' : 'false' ?>"
                class="relative inline-flex items-center px-4 py-2 border text-sm font-medium <?= $class ?>"><?= $i ?></button>
            <?php endfor; ?>

            <?php if ($current_page < $total_pages): ?>
            <button hx-get="<?= $base_url ?>&page=<?= $current_page + 1 ?>" hx-target="<?= $target_id ?>"
                hx-swap="innerHTML"
                class="relative inline-flex items-center px-2 py-2 rounded-r-md border border-slate-700 bg-slate-800 text-sm font-medium text-slate-400 hover:bg-slate-700">Next</button>
            <?php endif; ?>
        </nav>
    </div>
</div>
<?php
    return ob_get_clean();
}

function get_accounts_options_html($include_all = false) { $db = getDB(); $sql = "SELECT id, account_number, type FROM accounts WHERE user_id = ?"; $params = [$_SESSION['user_id']]; if ($include_all) { $sql .= " AND state = 'active'"; } $sql .= " ORDER BY id DESC"; $stmt = $db->prepare($sql); $stmt->execute($params); $accounts = $stmt->fetchAll(); $selected_id = $_SESSION['selected_account_id'] ?? 'all'; $html = ''; if ($include_all) { $selected = ($selected_id === 'all') ? 'selected' : ''; $html .= "<option value=\"all\" {$selected}>All Accounts</option>"; } if (empty($accounts) && !$include_all) { return '<option value="" disabled>Please add an account first</option>'; } foreach ($accounts as $acc) { $selected = ($selected_id == $acc['id']) ? 'selected' : ''; $label = htmlspecialchars("#{$acc['account_number']} ({$acc['type']})"); $html .= "<option value=\"{$acc['id']}\" {$selected}>{$label}</option>"; } return $html; }
function get_state_bg_color($state) { switch ($state) { case 'active': return 'bg-blue-100 text-blue-800'; case 'passed': case 'funded': return 'bg-green-100 text-green-800'; case 'failed': return 'bg-red-100 text-red-800'; case 'disabled': return 'bg-yellow-100 text-yellow-800'; default: return 'bg-gray-100 text-gray-800'; } }