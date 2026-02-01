package main

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
	"sync"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)


//go:embed templates/* static/*
var embedFS embed.FS

// Websocket support
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type Client struct {
	conn   *websocket.Conn
	send   chan []byte
	listID int
	orgID  int
}

var (
	clients   = make(map[*Client]bool)
	broadcast = make(chan BroadcastMessage)
	mutex     sync.RWMutex
)

type BroadcastMessage struct {
	Type   string      `json:"type"`
	ListID int         `json:"list_id"`
	Data   interface{} `json:"data,omitempty"`
}

// Other Variables
var store *sessions.CookieStore
var db *sql.DB
var tmpl *template.Template
var appTitle string

func init() {
	sessionKey := os.Getenv("SESSION_KEY")
	if sessionKey == "" {
		sessionKey = "dev-secret-change-me-to-something-random"
	}

	store = sessions.NewCookieStore([]byte(sessionKey))
	
	// Check if we're behind HTTPS proxy
	isSecure := os.Getenv("HTTPS") == "true" || os.Getenv("ENV") == "production"
	
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 30, // 30 days
		HttpOnly: true,
		Secure:   isSecure, // Only set Secure flag if using HTTPS
		SameSite: http.SameSiteLaxMode,
	}
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        if os.Getenv("HTTPS") == "true" {
            w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        }
        next.ServeHTTP(w, r)
    })
}

// --- DATA MODELS ---
type Organization struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type SignupRequest struct {
	OrgName  string `json:"org_name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type ShoppingItem struct {
	ID        int       `json:"id"`
	ListID    int       `json:"list_id"`
	Name      string    `json:"name"`
	Quantity  string    `json:"quantity"`
	Category  string    `json:"category"`
	Purchased bool      `json:"purchased"`
	AddedBy   string    `json:"added_by"`
	CreatedAt time.Time `json:"created_at"`
}

type CreateItemRequest struct {
	Name     string `json:"name"`
	ListID   int    `json:"list_id"` 
	Quantity string `json:"quantity"`
	Category string `json:"category"`
	AddedBy  string `json:"added_by"`
}

type UpdateItemRequest struct {
	Name      *string `json:"name,omitempty"`
	Quantity  *string `json:"quantity,omitempty"`
	Category  *string `json:"category,omitempty"`
	Purchased *bool   `json:"purchased,omitempty"`
}

type Category struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type List struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

type User struct {
	ID           int       `json:"id"`
	OrgID        int       `json:"org_id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// --- MAIN ---
func main() {
	var err error
	tmpl = template.Must(template.ParseFS(embedFS, "templates/*.html"))
	appTitle = os.Getenv("APP_TITLE")

	dbPath := "./shopping.db"
	if stat, statErr := os.Stat("/app/data"); statErr == nil && stat.IsDir() {
		dbPath = "/app/data/shopping.db"
	}

	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	createTable()
	createUserTable()

	// Start WebSocket hub
	go handleBroadcasts()

	r := mux.NewRouter()
	r.Use(securityHeadersMiddleware)

	staticFS, err := fs.Sub(embedFS, "static")
	if err != nil {
		log.Fatal(err)
	}

	r.PathPrefix("/static/").Handler(
		http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))),
	)

	// Serve favicon.ico from container root
	r.Handle("/favicon.ico", http.FileServer(http.Dir("./")))

	// WebSocket
	r.HandleFunc("/ws", wsHandler)

	// UI
	r.HandleFunc("/", homeHandler).Methods("GET")

	// Debug
	r.Handle("/api/debug/database", requireLogin(requireAdmin(http.HandlerFunc(debugDatabaseHandler)))).Methods("GET")

	// Lists
	r.Handle("/api/lists", requireLogin(http.HandlerFunc(getListsHandler))).Methods("GET")
	r.Handle("/api/lists", requireLogin(http.HandlerFunc(createListHandler))).Methods("POST")
	r.Handle("/api/lists/{id}", requireLogin(http.HandlerFunc(updateListHandler))).Methods("PUT")
	r.Handle("/api/lists/{id}", requireLogin(http.HandlerFunc(deleteListHandler))).Methods("DELETE")

	// Items
	r.Handle("/api/items", requireLogin(http.HandlerFunc(getItemsHandler))).Methods("GET") // Will use ?list_id=X
	r.Handle("/api/items/unchecked", requireLogin(http.HandlerFunc(getUncheckedItemsHandler))).Methods("GET")
	r.Handle("/api/items", requireLogin(http.HandlerFunc(createItemHandler))).Methods("POST")
	r.Handle("/api/items/{id}", requireLogin(http.HandlerFunc(updateItemHandler))).Methods("PUT")
	r.Handle("/api/items/{id}", requireLogin(http.HandlerFunc(deleteItemHandler))).Methods("DELETE")
	r.Handle("/api/items/{id}/toggle", requireLogin(http.HandlerFunc(toggleItemHandler))).Methods("POST")

	// Categories
	r.Handle("/api/categories", requireLogin(http.HandlerFunc(getCategoriesHandler))).Methods("GET")
	r.Handle("/api/categories", requireLogin(requireAdmin(http.HandlerFunc(createCategoryHandler)))).Methods("POST")
	r.Handle("/api/categories/{id}", requireLogin(requireAdmin(http.HandlerFunc(updateCategoryHandler)))).Methods("PUT")
	r.Handle("/api/categories/{id}", requireLogin(requireAdmin(http.HandlerFunc(deleteCategoryHandler)))).Methods("DELETE")

	// Auth
	r.HandleFunc("/api/signup", signupHandler).Methods("POST")
	r.HandleFunc("/api/login", loginHandler).Methods("POST")
	r.HandleFunc("/api/logout", logoutHandler).Methods("POST")

	// Me
	r.Handle("/api/me", requireLogin(http.HandlerFunc(meHandler))).Methods("GET")
	r.Handle("/api/me/password", requireLogin(http.HandlerFunc(changePasswordHandler))).Methods("PUT")

	// Organization (admin only)
	r.Handle("/api/organization", requireLogin(requireAdmin(http.HandlerFunc(deleteOrganizationHandler)))).Methods("DELETE")

	// Connections
	r.Handle("/api/connections", requireLogin(http.HandlerFunc(connectionsHandler))).Methods("GET")

	// Users (admin only)
	r.Handle("/api/users", requireLogin(requireAdmin(http.HandlerFunc(listUsersHandler)))).Methods("GET")
	r.Handle("/api/users", requireLogin(requireAdmin(http.HandlerFunc(createUserHandler)))).Methods("POST")
	r.Handle("/api/users/{id}", requireLogin(requireAdmin(http.HandlerFunc(deleteUserHandler)))).Methods("DELETE")
	r.Handle("/api/users/{id}", requireLogin(requireAdmin(http.HandlerFunc(updateUserHandler)))).Methods("PUT")

	fmt.Println("Server running on http://0.0.0.0:8888")
	log.Fatal(http.ListenAndServe(":8888", r))
}

// --- WEBSOCKET CONNECTIONS ---
func getConnectionCount() int {
	mutex.RLock()
	defer mutex.RUnlock()
	return len(clients)
}

// --- TABLES ---
func createTable() {
	// Create lists table first
	db.Exec(`CREATE TABLE IF NOT EXISTS lists (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		org_id INTEGER NOT NULL DEFAULT 1,
		name TEXT NOT NULL,
		created_by TEXT DEFAULT 'Unknown',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
	);`)

	// Ensure default list exists
	var listCount int
	defaultList := os.Getenv("DEFAULT_LIST")
	adminUsername := os.Getenv("DEFAULT_ADMIN_USERNAME")
	db.QueryRow("SELECT COUNT(*) FROM lists").Scan(&listCount)
	if listCount == 0 {
		db.Exec("INSERT INTO lists (name, created_by) VALUES (?, ?)", defaultList, adminUsername)
	}

	// Check if items table exists
	var tableExists int
	db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='items'").Scan(&tableExists)
	
	if tableExists == 0 {
		// Fresh install - create with list_id
		db.Exec(`CREATE TABLE items (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			list_id INTEGER NOT NULL DEFAULT 1,
			name TEXT NOT NULL,
			quantity TEXT DEFAULT '1',
			category TEXT DEFAULT 'Other',
			purchased BOOLEAN DEFAULT 0,
			added_by TEXT DEFAULT 'Unknown',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (list_id) REFERENCES lists(id) ON DELETE CASCADE
		);`)
	} else {
		// Migration - check if list_id column exists
		var colExists int
		db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('items') WHERE name='list_id'").Scan(&colExists)
		
		if colExists == 0 {
			// Add list_id column to existing table
			db.Exec("ALTER TABLE items ADD COLUMN list_id INTEGER NOT NULL DEFAULT 1")
		}
	}

	// Create organizations table
	db.Exec(`CREATE TABLE IF NOT EXISTS organizations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`)

	// Ensure default org exists
	var orgCount int
	defaultOrganization := os.Getenv("DEFAULT_ORGANIZATION")
	db.QueryRow("SELECT COUNT(*) FROM organizations").Scan(&orgCount)
	if orgCount == 0 {
		db.Exec("INSERT INTO organizations (name) VALUES (?)", defaultOrganization)
	}

	// Create Categories table
	db.Exec(`CREATE TABLE IF NOT EXISTS categories (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    org_id INTEGER NOT NULL DEFAULT 1,
	    name TEXT NOT NULL,
	    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	    UNIQUE(org_id, name),
	    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
	);`)

	// Default categories
	db.Exec(`INSERT OR IGNORE INTO categories (org_id, name) VALUES
    	(1, 'Groceries'),(1, 'Produce'),(1, 'Dairy'),(1, 'Meat'),(1, 'Bakery'),(1, 'Household'),(1, 'Other');`)
}

func createUserTable() {
    db.Exec(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL DEFAULT 1,
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(org_id, username),
        FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
    );`)

    var count int
    db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'Admin'").Scan(&count)
    if count == 0 {
		defaultOrganization := os.Getenv("DEFAULT_ORGANIZATION")
        adminUsername := os.Getenv("DEFAULT_ADMIN_USERNAME")
        adminPassword := os.Getenv("DEFAULT_ADMIN_PASSWORD")
        hash, _ := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
        db.Exec("INSERT INTO users (org_id, username, password_hash, role) VALUES (?, ?, ?, ?)", 1, adminUsername, string(hash), "Admin")
        fmt.Printf("Created default admin user: organization/username='%s/%s', password='%s'\n", defaultOrganization, adminUsername, adminPassword)
    }
}

// --- HANDLERS ---
// Signup
func signupHandler(w http.ResponseWriter, r *http.Request) {
	var req SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", 400)
		return
	}
	
	if req.OrgName == "" || req.Username == "" || req.Password == "" {
		http.Error(w, "Organization name, username and password required", 400)
		return
	}

	// Check for existing organization by name
	var existingOrgID int
	err := db.QueryRow("SELECT id FROM organizations WHERE name = ?", req.OrgName).Scan(&existingOrgID)
	if err == nil {
		http.Error(w, "Organization name already exists", 409)
		return
	}

	// Create organization
	result, err := db.Exec("INSERT INTO organizations (name) VALUES (?)", req.OrgName)
	if err != nil {
		http.Error(w, "Failed to create organization", 500)
		return
	}
	orgID, _ := result.LastInsertId()

	// Create admin user for org
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	_, err = db.Exec("INSERT INTO users (org_id, username, password_hash, role) VALUES (?, ?, ?, ?)", 
		orgID, req.Username, string(hash), "Admin")
	if err != nil {
		db.Exec("DELETE FROM organizations WHERE id = ?", orgID) // Rollback
		http.Error(w, "Username already exists", 409)
		return
	}

	// Create default list for org
	defaultList := os.Getenv("DEFAULT_LIST")
	result, err = db.Exec("INSERT INTO lists (org_id, name, created_by) VALUES (?, ?, ?)", 
	    orgID, defaultList, req.Username)
	if err != nil {
	    log.Printf("Failed to create default list: %v", err)
	}

	// Create default categories for org
	db.Exec(`INSERT INTO categories (org_id, name) VALUES
	    (?, 'Groceries'),(?, 'Produce'),(?, 'Dairy'),(?, 'Meat'),(?, 'Bakery'),(?, 'Household'),(?, 'Other')`,
	    orgID, orgID, orgID, orgID, orgID, orgID, orgID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "org_id": fmt.Sprint(orgID)})
}

func deleteOrganizationHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	orgID, _ := session.Values["org_id"].(int)
	
	// Delete all data in cascade
	db.Exec("DELETE FROM items WHERE list_id IN (SELECT id FROM lists WHERE org_id = ?)", orgID)
	db.Exec("DELETE FROM lists WHERE org_id = ?", orgID)
	db.Exec("DELETE FROM users WHERE org_id = ?", orgID)
	db.Exec("DELETE FROM organizations WHERE id = ?", orgID)
	
	// Log out user
	session.Options.MaxAge = -1
	session.Save(r, w)
	
	w.WriteHeader(http.StatusNoContent)
}

// Auth

var (
    loginAttempts = make(map[string][]time.Time)
    loginMutex    sync.RWMutex
)

func checkRateLimit(ip string) bool {
    loginMutex.Lock()
    defer loginMutex.Unlock()
    
    now := time.Now()
    cutoff := now.Add(-15 * time.Minute)
    
    // Clean old attempts
    attempts := loginAttempts[ip]
    var validAttempts []time.Time
    for _, t := range attempts {
        if t.After(cutoff) {
            validAttempts = append(validAttempts, t)
        }
    }
    
    // Allow max 5 attempts per 15 minutes
    if len(validAttempts) >= 5 {
        return false
    }
    
    loginAttempts[ip] = append(validAttempts, now)
    return true
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    ip := r.RemoteAddr
    if !checkRateLimit(ip) {
        http.Error(w, "Too many login attempts. Try again later.", 429)
        return
    }

	// Parse organization/username or plain username
	username := req.Username
	var orgID int
	
	if strings.Contains(username, "/") {
		parts := strings.Split(username, "/")
		orgName := parts[0]
		username = parts[1]
		
		err := db.QueryRow("SELECT id FROM organizations WHERE name = ?", orgName).Scan(&orgID)
		if err != nil {
			http.Error(w, "Invalid organization", 401)
			return
		}
	}

	var user User
	query := "SELECT id, org_id, username, password_hash, role FROM users WHERE username = ?"
	args := []interface{}{username}
	
	if orgID > 0 {
		query += " AND org_id = ?"
		args = append(args, orgID)
	}
	
	err := db.QueryRow(query, args...).Scan(&user.ID, &user.OrgID, &user.Username, &user.PasswordHash, &user.Role)
	if err != nil {
		http.Error(w, "Invalid username or password", 401)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid username or password", 401)
		return
	}

	session, _ := store.Get(r, "session")
	session.Values["user_id"] = user.ID
	session.Values["org_id"] = user.OrgID
	session.Values["username"] = user.Username
	session.Values["role"] = user.Role

	// Get organization name
	var orgName string
	db.QueryRow("SELECT name FROM organizations WHERE id = ?", user.OrgID).Scan(&orgName)
	session.Values["org_name"] = orgName
	
	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session: %v", err)
		http.Error(w, "Session error", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok", 
		"username": user.Username,
		"org_id": user.OrgID,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	session.Options.MaxAge = -1
	session.Save(r, w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func requireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")
		if err != nil {
			log.Printf("Session error: %v", err)
			http.Error(w, "Unauthorized", 401)
			return
		}
		
		if session.Values["user_id"] == nil {
			http.Error(w, "Unauthorized", 401)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		if session.Values["role"] != "Admin" {
			http.Error(w, "Forbidden", 403)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Users
func createUserHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	orgID, _ := session.Values["org_id"].(int)
	
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", 400)
		return
	}
	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password required", 400)
		return
	}
	
	if len(req.Password) < 6 {
		http.Error(w, "Password must be at least 6 characters", 400)
		return
	}
	
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (org_id, username, password_hash, role) VALUES (?, ?, ?, ?)", 
		orgID, req.Username, string(hash), req.Role)
	if err != nil {
		http.Error(w, "Username already exists in organization", 409)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"])
	db.Exec("DELETE FROM users WHERE id = ?", id)
	w.WriteHeader(http.StatusNoContent)
}

func listUsersHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	orgID, _ := session.Values["org_id"].(int)
	
	rows, _ := db.Query("SELECT id, username, role, created_at FROM users WHERE org_id = ? ORDER BY created_at DESC", orgID)
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt)
		users = append(users, u)
	}
	json.NewEncoder(w).Encode(users)
}

func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"])
	var req struct {
		Username *string `json:"username,omitempty"`
		Password *string `json:"password,omitempty"`
		Role     *string `json:"role,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Username != nil {
		db.Exec("UPDATE users SET username=? WHERE id=?", *req.Username, id)
	}
	if req.Password != nil {
		hash, _ := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		db.Exec("UPDATE users SET password_hash=? WHERE id=?", hash, id)
	}
	if req.Role != nil {
		db.Exec("UPDATE users SET role=? WHERE id=?", *req.Role, id)
	}
	var user User
	db.QueryRow("SELECT id, username, role FROM users WHERE id=?", id).Scan(&user.ID, &user.Username, &user.Role)
	json.NewEncoder(w).Encode(user)
}

func meHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session")
    userID, ok := session.Values["user_id"].(int)
    if !ok {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    orgID, _ := session.Values["org_id"].(int)
    orgName, _ := session.Values["org_name"].(string)
    username, _ := session.Values["username"].(string)
    role, _ := session.Values["role"].(string)

    json.NewEncoder(w).Encode(map[string]interface{}{
        "id":       userID,
        "org_id":   orgID,
        "org_name": orgName,
        "username": username,
        "role":     role,
    })
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	userID, _ := session.Values["user_id"].(int)
	
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", 400)
		return
	}
	
	if req.CurrentPassword == "" || req.NewPassword == "" {
		http.Error(w, "Both passwords required", 400)
		return
	}
	
	if len(req.NewPassword) < 6 {
		http.Error(w, "Password must be at least 6 characters", 400)
		return
	}
	
	// Verify current password
	var currentHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&currentHash)
	if err != nil {
		http.Error(w, "User not found", 404)
		return
	}
	
	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.CurrentPassword)); err != nil {
		http.Error(w, "Current password incorrect", 401)
		return
	}
	
	// Update password
	newHash, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(newHash), userID)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// Home/UI
func homeHandler(w http.ResponseWriter, r *http.Request) { 
	tmpl.ExecuteTemplate(w, "index.html", map[string]string{"Title": appTitle})
}

// API Handlers
func getItemsHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	orgID, _ := session.Values["org_id"].(int)
	
	listID := r.URL.Query().Get("list_id")
	if listID == "" {
		listID = "1"
	}
	
	rows, err := db.Query(`
		SELECT i.id, i.list_id, i.name, i.quantity, i.category, i.purchased, i.added_by, i.created_at 
		FROM items i
		JOIN lists l ON i.list_id = l.id
		WHERE i.list_id = ? AND l.org_id = ?
		ORDER BY i.purchased ASC, i.created_at DESC
	`, listID, orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var items []ShoppingItem
	for rows.Next() {
		var item ShoppingItem
		if err := rows.Scan(&item.ID, &item.ListID, &item.Name, &item.Quantity, &item.Category, &item.Purchased, &item.AddedBy, &item.CreatedAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		items = append(items, item)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

func getUncheckedItemsHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	orgID, _ := session.Values["org_id"].(int)
	
	listID := r.URL.Query().Get("list_id")
	if listID == "" {
		listID = "1"
	}
	
	rows, err := db.Query(`
		SELECT i.id, i.list_id, i.name, i.quantity, i.category, i.purchased, i.added_by, i.created_at 
		FROM items i
		JOIN lists l ON i.list_id = l.id
		WHERE i.purchased = 0 AND i.list_id = ? AND l.org_id = ?
		ORDER BY i.category, i.name
	`, listID, orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var items []ShoppingItem
	for rows.Next() {
		var item ShoppingItem
		if err := rows.Scan(&item.ID, &item.ListID, &item.Name, &item.Quantity, &item.Category, &item.Purchased, &item.AddedBy, &item.CreatedAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		items = append(items, item)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

func createItemHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session")
    orgID, _ := session.Values["org_id"].(int)
    
    var req CreateItemRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if req.Name == "" {
        http.Error(w, "Name is required", http.StatusBadRequest)
        return
    }
    if req.Quantity == "" {
        req.Quantity = "1"
    }
    if req.Category == "" {
        req.Category = "Other"
    }
	if req.ListID == 0 {
		req.ListID = 1 // default
	}
	if len(req.Name) > 200 {
    http.Error(w, "Name too long (max 200 chars)", http.StatusBadRequest)
    return
	}
	if len(req.Quantity) > 50 {
	    http.Error(w, "Quantity too long (max 50 chars)", http.StatusBadRequest)
	    return
	}
	if len(req.Category) > 100 {
	    http.Error(w, "Category too long (max 100 chars)", http.StatusBadRequest)
	    return
	}

    // Verify the list belongs to the user's org
    var listOrgID int
    err := db.QueryRow("SELECT org_id FROM lists WHERE id = ?", req.ListID).Scan(&listOrgID)
    if err != nil || listOrgID != orgID {
        http.Error(w, "List not found or access denied", http.StatusForbidden)
        return
    }

    // Get logged-in user from session
    addedBy, ok := session.Values["username"].(string)
    if !ok || addedBy == "" {
        addedBy = "Unknown"
    }
		
	result, err := db.Exec(`
		INSERT INTO items (list_id, name, quantity, category, added_by, purchased)
		VALUES (?, ?, ?, ?, ?, 0)
	`, req.ListID, req.Name, req.Quantity, req.Category, addedBy)

    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    id, _ := result.LastInsertId()
    newItem := ShoppingItem{
        ID:        int(id),
        ListID:    req.ListID,
        Name:      req.Name,
        Quantity:  req.Quantity,
        Category:  req.Category,
        AddedBy:   addedBy,
        Purchased: false,
        CreatedAt: time.Now(),
    }

    notifyClients("item_created", req.ListID, newItem)
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(newItem)
}

func updateItemHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	orgID, _ := session.Values["org_id"].(int)
	
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	var req UpdateItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if item exists and belongs to user's org
	var exists bool
	err = db.QueryRow(`
		SELECT EXISTS(SELECT 1 FROM items i JOIN lists l ON i.list_id = l.id WHERE i.id = ? AND l.org_id = ?)
	`, id, orgID).Scan(&exists)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}

	// Update fields
	if req.Name != nil {
		db.Exec("UPDATE items SET name = ? WHERE id = ?", *req.Name, id)
	}
	if req.Quantity != nil {
		db.Exec("UPDATE items SET quantity = ? WHERE id = ?", *req.Quantity, id)
	}
	if req.Category != nil {
		db.Exec("UPDATE items SET category = ? WHERE id = ?", *req.Category, id)
	}
	if req.Purchased != nil {
		db.Exec("UPDATE items SET purchased = ? WHERE id = ?", *req.Purchased, id)
	}

	// Fetch updated item
	var item ShoppingItem
	err = db.QueryRow(`
		SELECT id, list_id, name, quantity, category, purchased, added_by, created_at 
		FROM items WHERE id = ?
	`, id).Scan(&item.ID, &item.ListID, &item.Name, &item.Quantity, &item.Category, 
		&item.Purchased, &item.AddedBy, &item.CreatedAt)
	
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	notifyClients("item_updated", item.ListID, item)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(item)
}

func toggleItemHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	orgID, _ := session.Values["org_id"].(int)
	
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	var listID int
	err = db.QueryRow(`
		SELECT l.id FROM lists l 
		JOIN items i ON i.list_id = l.id 
		WHERE i.id = ? AND l.org_id = ?
	`, id, orgID).Scan(&listID)
	if err != nil {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}
	
	_, err = db.Exec("UPDATE items SET purchased = NOT purchased WHERE id = ?", id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	notifyClients("item_toggled", listID, map[string]int{"id": id})

	w.WriteHeader(http.StatusOK)
}

func deleteItemHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	orgID, _ := session.Values["org_id"].(int)
	
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	// Get list_id BEFORE deleting, verify org
	var listID int
	err = db.QueryRow(`
		SELECT l.id FROM lists l 
		JOIN items i ON i.list_id = l.id 
		WHERE i.id = ? AND l.org_id = ?
	`, id, orgID).Scan(&listID)
	if err != nil {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}

	result, err := db.Exec("DELETE FROM items WHERE id = ?", id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}

	notifyClients("item_deleted", listID, map[string]int{"id": id})
	w.WriteHeader(http.StatusNoContent)
}

func getCategoriesHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session")
    orgID, _ := session.Values["org_id"].(int)
    
    rows, err := db.Query("SELECT id, name FROM categories WHERE org_id = ? ORDER BY name ASC", orgID)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    defer rows.Close()

    var cats []Category
    for rows.Next() {
        var c Category
        rows.Scan(&c.ID, &c.Name)
        cats = append(cats, c)
    }

    json.NewEncoder(w).Encode(cats)
}

func createCategoryHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session")
    orgID, _ := session.Values["org_id"].(int)
    
    var body struct {
        Name string `json:"name"`
    }
    json.NewDecoder(r.Body).Decode(&body)

    if body.Name == "" {
        http.Error(w, "Name required", 400)
        return
    }

    _, err := db.Exec("INSERT INTO categories (org_id, name) VALUES (?, ?)", orgID, body.Name)
    if err != nil {
        http.Error(w, err.Error(), 400)
        return
    }

    w.WriteHeader(http.StatusCreated)
}

func updateCategoryHandler(w http.ResponseWriter, r *http.Request) {
    id, _ := strconv.Atoi(mux.Vars(r)["id"])

    var body struct {
        Name string `json:"name"`
    }
    json.NewDecoder(r.Body).Decode(&body)

    if body.Name == "" {
        http.Error(w, "Name required", 400)
        return
    }

    // Update category
    db.Exec("UPDATE categories SET name = ? WHERE id = ?", body.Name, id)

    // Update existing items using this category
    db.Exec(`
        UPDATE items
        SET category = ?
        WHERE category = (
            SELECT name FROM categories WHERE id = ?
        )
    `, body.Name, id)

    w.WriteHeader(http.StatusOK)
}

func deleteCategoryHandler(w http.ResponseWriter, r *http.Request) {
    id, _ := strconv.Atoi(mux.Vars(r)["id"])

    var name string
    err := db.QueryRow("SELECT name FROM categories WHERE id = ?", id).Scan(&name)
    if err != nil {
        http.Error(w, "Not found", 404)
        return
    }

    // Reassign items to "Other"
    db.Exec("UPDATE items SET category = 'Other' WHERE category = ?", name)

    db.Exec("DELETE FROM categories WHERE id = ?", id)
    w.WriteHeader(http.StatusNoContent)
}

func getListsHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	orgID, _ := session.Values["org_id"].(int)
	
	rows, _ := db.Query("SELECT id, name, created_by, created_at FROM lists WHERE org_id = ? ORDER BY created_at ASC", orgID)
	defer rows.Close()
	var lists []List
	for rows.Next() {
		var l List
		rows.Scan(&l.ID, &l.Name, &l.CreatedBy, &l.CreatedAt)
		lists = append(lists, l)
	}
	json.NewEncoder(w).Encode(lists)
}

func createListHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	orgID, _ := session.Values["org_id"].(int)
	createdBy, _ := session.Values["username"].(string)
	
	var req struct {
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	
	result, _ := db.Exec("INSERT INTO lists (org_id, name, created_by) VALUES (?, ?, ?)", orgID, req.Name, createdBy)
	id, _ := result.LastInsertId()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{"id": id})
}

func updateListHandler(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"])
	var req struct {
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	db.Exec("UPDATE lists SET name = ? WHERE id = ?", req.Name, id)
	w.WriteHeader(http.StatusOK)
}

func deleteListHandler(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"])
	db.Exec("DELETE FROM items WHERE list_id = ?", id)
	db.Exec("DELETE FROM lists WHERE id = ?", id)
	w.WriteHeader(http.StatusNoContent)
}

// === WEBSOCKET ===
func wsHandler(w http.ResponseWriter, r *http.Request) {
	// Get orgID from session
	session, err := store.Get(r, "session")
	if err != nil || session.Values["org_id"] == nil {
		http.Error(w, "Unauthorized", 401)
		return
	}
	orgID, _ := session.Values["org_id"].(int)

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade failed:", err)
		return
	}

	listID := 1
	if lid := r.URL.Query().Get("list_id"); lid != "" {
		listID, _ = strconv.Atoi(lid)
	}

	client := &Client{
		conn:   conn,
		send:   make(chan []byte, 256),
		listID: listID,
		orgID:  orgID,
	}

	mutex.Lock()
	clients[client] = true
	count := getOrgConnectionCount(orgID)
	mutex.Unlock()

	// Notify clients in same org of new count
	notifyClientsInOrg("connection_count", 0, map[string]int{"count": count}, orgID)

	go client.writePump()
	go client.readPump()
}

func getOrgConnectionCount(orgID int) int {
	count := 0
	for client := range clients {
		if client.orgID == orgID {
			count++
		}
	}
	return count
}

func notifyClientsInOrg(msgType string, listID int, data interface{}, orgID int) {
	msg := BroadcastMessage{
		Type:   msgType,
		ListID: listID,
		Data:   data,
	}
	msgData, _ := json.Marshal(msg)
	
	mutex.RLock()
	for client := range clients {
		if client.orgID == orgID {
			select {
			case client.send <- msgData:
			default:
				close(client.send)
				delete(clients, client)
			}
		}
	}
	mutex.RUnlock()
}

func (c *Client) readPump() {
	defer func() {
	    orgID := c.orgID
	    mutex.Lock()
	    delete(clients, c)
	    count := getOrgConnectionCount(orgID)
	    mutex.Unlock()
	    
	    // Notify remaining clients in same org
	    notifyClientsInOrg("connection_count", 0, map[string]int{"count": count}, orgID)
	    c.conn.Close()
	}()

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
		// Handle list switching
		var msg map[string]interface{}
		if err := json.Unmarshal(message, &msg); err == nil {
			if newListID, ok := msg["list_id"].(float64); ok {
				c.listID = int(newListID)
			}
		}
	}
}

func (c *Client) writePump() {
	defer c.conn.Close()
	for message := range c.send {
		if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
			break
		}
	}
}

func handleBroadcasts() {
	for msg := range broadcast {
		data, _ := json.Marshal(msg)
		mutex.RLock()
		for client := range clients {
			// Broadcast connection_count to all clients in any org (will be filtered by notifyClientsInOrg)
			// For other messages, check list_id match
			if msg.Type == "connection_count" || client.listID == msg.ListID {
				select {
				case client.send <- data:
				default:
					close(client.send)
					delete(clients, client)
				}
			}
		}
		mutex.RUnlock()
	}
}

func notifyClients(msgType string, listID int, data interface{}) {
	broadcast <- BroadcastMessage{
		Type:   msgType,
		ListID: listID,
		Data:   data,
	}
}

func connectionsHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	orgID, _ := session.Values["org_id"].(int)
	
	mutex.RLock()
	count := getOrgConnectionCount(orgID)
	mutex.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"count": count})
}

func debugDatabaseHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	orgID, _ := session.Values["org_id"].(int)
	
	result := map[string]interface{}{}
	
	// Organizations
	rows, _ := db.Query("SELECT id, name, created_at FROM organizations")
	var orgs []Organization
	for rows.Next() {
		var o Organization
		rows.Scan(&o.ID, &o.Name, &o.CreatedAt)
		orgs = append(orgs, o)
	}
	rows.Close()
	result["organizations"] = orgs
	
	// Users (filtered by org)
	rows, _ = db.Query("SELECT id, org_id, username, role, created_at FROM users WHERE org_id = ?", orgID)
	var users []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.OrgID, &u.Username, &u.Role, &u.CreatedAt)
		users = append(users, u)
	}
	rows.Close()
	result["users"] = users
	
	// Lists (filtered by org)
	rows, _ = db.Query("SELECT id, name, created_by, created_at FROM lists WHERE org_id = ?", orgID)
	var lists []List
	for rows.Next() {
		var l List
		rows.Scan(&l.ID, &l.Name, &l.CreatedBy, &l.CreatedAt)
		lists = append(lists, l)
	}
	rows.Close()
	result["lists"] = lists
	
	// Items (for all lists in org)
	rows, _ = db.Query(`
		SELECT i.id, i.list_id, i.name, i.quantity, i.category, i.purchased, i.added_by, i.created_at
		FROM items i
		JOIN lists l ON i.list_id = l.id
		WHERE l.org_id = ?
	`, orgID)
	var items []ShoppingItem
	for rows.Next() {
		var item ShoppingItem
		rows.Scan(&item.ID, &item.ListID, &item.Name, &item.Quantity, &item.Category, &item.Purchased, &item.AddedBy, &item.CreatedAt)
		items = append(items, item)
	}
	rows.Close()
	result["items"] = items
	
	// Categories (filtered by org)
	rows, _ = db.Query("SELECT id, name FROM categories WHERE org_id = ?", orgID)
	var cats []Category
	for rows.Next() {
	    var c Category
	    rows.Scan(&c.ID, &c.Name)
	    cats = append(cats, c)
	}
	rows.Close()
	result["categories"] = cats
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}