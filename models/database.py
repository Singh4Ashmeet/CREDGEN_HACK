import sqlite3
import hashlib
import secrets
import os
from datetime import datetime
from typing import Optional, List, Dict
from cryptography.fernet import Fernet

class CredentialDatabase:
    """SQLite database handler for CREDGEN credential management"""
    
    def __init__(self, db_path: str = "data/credentials.db"):
        """Initialize database connection"""
        self.db_path = db_path
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        self.connection = None
        self.cursor = None
        self._encryption_key = self._get_or_create_key()
        self._cipher_suite = Fernet(self._encryption_key)
        self._connect()
        self._create_tables()
    
    def _get_or_create_key(self) -> bytes:
        """Get or create encryption key for password storage"""
        key_file = "data/.key"
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key
    
    def _connect(self):
        """Establish database connection"""
        try:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
            self.cursor = self.connection.cursor()
            print(f"✓ Database connected: {self.db_path}")
        except sqlite3.Error as e:
            print(f"✗ Database connection error: {e}")
            raise
    
    def _create_tables(self):
        """Create necessary tables"""
        try:
            # Credentials table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_name TEXT NOT NULL,
                    username TEXT NOT NULL,
                    email TEXT,
                    password_encrypted TEXT NOT NULL,
                    password_strength TEXT,
                    notes TEXT,
                    category TEXT DEFAULT 'General',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_accessed TIMESTAMP,
                    UNIQUE(service_name, username)
                )
            ''')
            
            # Password generation history
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    credential_id INTEGER,
                    password_encrypted TEXT NOT NULL,
                    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
                )
            ''')
            
            # Generation settings/preferences
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS generation_settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT DEFAULT 'default',
                    default_length INTEGER DEFAULT 16,
                    include_uppercase INTEGER DEFAULT 1,
                    include_lowercase INTEGER DEFAULT 1,
                    include_numbers INTEGER DEFAULT 1,
                    include_symbols INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            self.connection.commit()
            print("✓ Database tables created/verified")
        except sqlite3.Error as e:
            print(f"✗ Table creation error: {e}")
            raise
    
    def _encrypt_password(self, password: str) -> str:
        """Encrypt password"""
        return self._cipher_suite.encrypt(password.encode()).decode()
    
    def _decrypt_password(self, encrypted_password: str) -> str:
        """Decrypt password"""
        return self._cipher_suite.decrypt(encrypted_password.encode()).decode()
    
    def _calculate_password_strength(self, password: str) -> str:
        """Calculate password strength"""
        score = 0
        if len(password) >= 12: score += 1
        if len(password) >= 16: score += 1
        if any(c.isupper() for c in password): score += 1
        if any(c.islower() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password): score += 1
        
        if score >= 5: return "Strong"
        elif score >= 3: return "Medium"
        else: return "Weak"
    
    def add_credential(self, service_name: str, username: str, password: str,
                      email: Optional[str] = None, notes: Optional[str] = None,
                      category: str = "General") -> Dict:
        """Add new credential"""
        try:
            encrypted_pwd = self._encrypt_password(password)
            strength = self._calculate_password_strength(password)
            
            self.cursor.execute('''
                INSERT INTO credentials 
                (service_name, username, email, password_encrypted, password_strength, notes, category)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (service_name, username, email, encrypted_pwd, strength, notes, category))
            
            credential_id = self.cursor.lastrowid
            
            # Add to password history
            self.cursor.execute('''
                INSERT INTO password_history (credential_id, password_encrypted)
                VALUES (?, ?)
            ''', (credential_id, encrypted_pwd))
            
            self.connection.commit()
            
            return {
                "success": True,
                "message": f"Credential saved: {service_name}",
                "id": credential_id
            }
        except sqlite3.IntegrityError:
            return {
                "success": False,
                "message": f"Credential already exists: {service_name} - {username}"
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Error saving credential: {str(e)}"
            }
    
    def get_all_credentials(self, decrypt_passwords: bool = False) -> List[Dict]:
        """Get all credentials"""
        try:
            self.cursor.execute('''
                SELECT id, service_name, username, email, password_encrypted,
                       password_strength, notes, category, created_at, updated_at
                FROM credentials
                ORDER BY service_name, username
            ''')
            
            results = []
            for row in self.cursor.fetchall():
                cred = dict(row)
                if decrypt_passwords:
                    cred['password'] = self._decrypt_password(cred['password_encrypted'])
                del cred['password_encrypted']
                results.append(cred)
            
            return results
        except Exception as e:
            print(f"✗ Error retrieving credentials: {e}")
            return []
    
    def get_credential_by_id(self, credential_id: int) -> Optional[Dict]:
        """Get specific credential"""
        try:
            self.cursor.execute('''
                UPDATE credentials SET last_accessed = CURRENT_TIMESTAMP WHERE id = ?
            ''', (credential_id,))
            
            self.cursor.execute('''
                SELECT * FROM credentials WHERE id = ?
            ''', (credential_id,))
            
            result = self.cursor.fetchone()
            self.connection.commit()
            
            if result:
                cred = dict(result)
                cred['password'] = self._decrypt_password(cred['password_encrypted'])
                del cred['password_encrypted']
                return cred
            return None
        except Exception as e:
            print(f"✗ Error retrieving credential: {e}")
            return None
    
    def update_credential(self, credential_id: int, **kwargs) -> Dict:
        """Update credential"""
        try:
            update_fields = []
            params = []
            
            if 'password' in kwargs:
                encrypted_pwd = self._encrypt_password(kwargs['password'])
                strength = self._calculate_password_strength(kwargs['password'])
                update_fields.extend(['password_encrypted = ?', 'password_strength = ?'])
                params.extend([encrypted_pwd, strength])
                
                # Add to history
                self.cursor.execute('''
                    INSERT INTO password_history (credential_id, password_encrypted)
                    VALUES (?, ?)
                ''', (credential_id, encrypted_pwd))
            
            for key in ['service_name', 'username', 'email', 'notes', 'category']:
                if key in kwargs:
                    update_fields.append(f"{key} = ?")
                    params.append(kwargs[key])
            
            if update_fields:
                update_fields.append("updated_at = CURRENT_TIMESTAMP")
                params.append(credential_id)
                
                query = f'''
                    UPDATE credentials SET {", ".join(update_fields)}
                    WHERE id = ?
                '''
                
                self.cursor.execute(query, params)
                self.connection.commit()
                
                return {"success": True, "message": "Credential updated"}
            
            return {"success": False, "message": "No updates provided"}
        except Exception as e:
            return {"success": False, "message": f"Update error: {str(e)}"}
    
    def delete_credential(self, credential_id: int) -> Dict:
        """Delete credential"""
        try:
            self.cursor.execute('DELETE FROM credentials WHERE id = ?', (credential_id,))
            
            if self.cursor.rowcount > 0:
                self.connection.commit()
                return {"success": True, "message": "Credential deleted"}
            else:
                return {"success": False, "message": "Credential not found"}
        except Exception as e:
            return {"success": False, "message": f"Delete error: {str(e)}"}
    
    def search_credentials(self, search_term: str) -> List[Dict]:
        """Search credentials"""
        try:
            pattern = f"%{search_term}%"
            self.cursor.execute('''
                SELECT id, service_name, username, email, password_strength, category
                FROM credentials
                WHERE service_name LIKE ? OR username LIKE ? OR email LIKE ? OR category LIKE ?
                ORDER BY service_name
            ''', (pattern, pattern, pattern, pattern))
            
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            print(f"✗ Search error: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        try:
            stats = {}
            
            # Total credentials
            self.cursor.execute('SELECT COUNT(*) as total FROM credentials')
            stats['total_credentials'] = self.cursor.fetchone()['total']
            
            # By category
            self.cursor.execute('''
                SELECT category, COUNT(*) as count
                FROM credentials
                GROUP BY category
            ''')
            stats['by_category'] = {row['category']: row['count'] for row in self.cursor.fetchall()}
            
            # By strength
            self.cursor.execute('''
                SELECT password_strength, COUNT(*) as count
                FROM credentials
                GROUP BY password_strength
            ''')
            stats['by_strength'] = {row['password_strength']: row['count'] for row in self.cursor.fetchall()}
            
            return stats
        except Exception as e:
            print(f"✗ Statistics error: {e}")
            return {}
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            print("✓ Database connection closed")
