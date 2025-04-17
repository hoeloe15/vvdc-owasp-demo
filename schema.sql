DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS comments;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,  -- VULNERABILITY: Passwords stored in plaintext
    email TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0  -- 0 = regular user, 1 = admin
);

CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    content TEXT NOT NULL,   -- VULNERABILITY: No sanitization of content, allowing XSS
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Insert some sample users
INSERT INTO users (username, password, email, is_admin) VALUES ('admin', 'admin123', 'admin@example.com', 1);
INSERT INTO users (username, password, email, is_admin) VALUES ('john', 'password123', 'john@example.com', 0);
INSERT INTO users (username, password, email, is_admin) VALUES ('user', 'welcome123', 'sarah@example.com', 0);
INSERT INTO users (username, password, email, is_admin) VALUES ('boer', 'vivat', 'boer@example.com', 0);

-- Insert some sample comments
INSERT INTO comments (user_id, content) VALUES (1, 'Welcome to our vulnerable demo application!');
INSERT INTO comments (user_id, content) VALUES (2, 'This is a sample comment.');
INSERT INTO comments (user_id, content) VALUES (3, 'I love this insecure application!'); 