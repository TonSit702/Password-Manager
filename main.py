import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
import os
import hashlib
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Password Manager")
        self.root.geometry("800x600")
        self.root.resizable(False, False)
        
        # Security variables
        self.master_password = None
        self.cipher_suite = None
        self.db_path = "passwords.db"
        
        # Initialize database
        self.init_database()
        
        # Check if master password exists
        if self.master_password_exists():
            self.show_login_screen()
        else:
            self.show_setup_screen()
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        password_bytes = password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create master password table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt BLOB NOT NULL
            )
        ''')
        
        # Create credentials table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                password BLOB NOT NULL,
                notes TEXT,
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def master_password_exists(self):
        """Check if master password is already set"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM master_password")
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0
    
    def hash_password(self, password: str, salt: bytes = None) -> tuple:
        """Hash password with salt"""
        if salt is None:
            salt = os.urandom(32)
        
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return pwdhash, salt
    
    def verify_master_password(self, password: str) -> bool:
        """Verify master password"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM master_password WHERE id = 1")
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return False
        
        stored_hash, salt = result
        test_hash, _ = self.hash_password(password, salt)
        return test_hash == stored_hash
    
    def set_master_password(self, password: str):
        """Set new master password"""
        password_hash, salt = self.hash_password(password)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO master_password (id, password_hash, salt) VALUES (1, ?, ?)",
                      (password_hash, salt))
        conn.commit()
        conn.close()
        
        # Initialize encryption
        self.master_password = password
        key = self.derive_key(password, salt)
        self.cipher_suite = Fernet(key)
    
    def show_setup_screen(self):
        """Show master password setup screen"""
        self.clear_window()
        
        setup_frame = ttk.Frame(self.root, padding="20")
        setup_frame.pack(expand=True, fill='both')
        
        ttk.Label(setup_frame, text="Welcome to Password Manager", 
                 font=('Arial', 18, 'bold')).pack(pady=20)
        
        ttk.Label(setup_frame, text="Create a strong master password to secure your data:",
                 font=('Arial', 12)).pack(pady=10)
        
        ttk.Label(setup_frame, text="Master Password:").pack(anchor='w', pady=(20, 5))
        self.master_pwd_entry = ttk.Entry(setup_frame, show="*", width=30, font=('Arial', 12))
        self.master_pwd_entry.pack(pady=5)
        
        ttk.Label(setup_frame, text="Confirm Password:").pack(anchor='w', pady=(10, 5))
        self.confirm_pwd_entry = ttk.Entry(setup_frame, show="*", width=30, font=('Arial', 12))
        self.confirm_pwd_entry.pack(pady=5)
        
        ttk.Button(setup_frame, text="Create Master Password", 
                  command=self.create_master_password).pack(pady=20)
        
        # Password strength indicator
        self.strength_label = ttk.Label(setup_frame, text="", foreground="gray")
        self.strength_label.pack(pady=5)
        
        self.master_pwd_entry.bind('<KeyRelease>', self.check_password_strength)
    
    def check_password_strength(self, event=None):
        """Check password strength"""
        password = self.master_pwd_entry.get()
        
        if len(password) < 8:
            self.strength_label.config(text="Password too short (minimum 8 characters)", foreground="red")
        elif len(password) < 12:
            self.strength_label.config(text="Weak password", foreground="orange")
        elif any(c.isupper() for c in password) and any(c.islower() for c in password) and any(c.isdigit() for c in password):
            self.strength_label.config(text="Strong password", foreground="green")
        else:
            self.strength_label.config(text="Medium password", foreground="blue")
    
    def create_master_password(self):
        """Create master password"""
        password = self.master_pwd_entry.get()
        confirm = self.confirm_pwd_entry.get()
        
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long!")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        self.set_master_password(password)
        messagebox.showinfo("Success", "Master password created successfully!")
        self.show_main_screen()
    
    def show_login_screen(self):
        """Show login screen"""
        self.clear_window()
        
        login_frame = ttk.Frame(self.root, padding="20")
        login_frame.pack(expand=True, fill='both')
        
        ttk.Label(login_frame, text="Password Manager", 
                 font=('Arial', 18, 'bold')).pack(pady=20)
        
        ttk.Label(login_frame, text="Enter your master password:",
                 font=('Arial', 12)).pack(pady=10)
        
        self.login_entry = ttk.Entry(login_frame, show="*", width=30, font=('Arial', 12))
        self.login_entry.pack(pady=10)
        self.login_entry.bind('<Return>', lambda e: self.login())
        
        ttk.Button(login_frame, text="Login", command=self.login).pack(pady=10)
        
        self.login_entry.focus()
    
    def login(self):
        """Login with master password"""
        password = self.login_entry.get()
        
        if self.verify_master_password(password):
            # Initialize encryption
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT salt FROM master_password WHERE id = 1")
            salt = cursor.fetchone()[0]
            conn.close()
            
            self.master_password = password
            key = self.derive_key(password, salt)
            self.cipher_suite = Fernet(key)
            
            self.show_main_screen()
        else:
            messagebox.showerror("Error", "Invalid master password!")
            self.login_entry.delete(0, tk.END)
    
    def show_main_screen(self):
        """Show main application screen"""
        self.clear_window()
        
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill='both', expand=True)
        
        # Title
        ttk.Label(main_frame, text="Password Manager", 
                 font=('Arial', 16, 'bold')).pack(pady=10)
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=10)
        
        ttk.Button(button_frame, text="Add Password", 
                  command=self.show_add_password_dialog).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Generate Password", 
                  command=self.generate_password).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Search", 
                  command=self.search_passwords).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Refresh", 
                  command=self.refresh_list).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Logout", 
                  command=self.logout).pack(side='right', padx=5)
        
        # Search frame
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill='x', pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side='left')
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side='left', fill='x', expand=True, padx=(5, 0))
        self.search_var.trace('w', lambda *args: self.filter_passwords())
        
        # Treeview for displaying passwords
        self.tree_frame = ttk.Frame(main_frame)
        self.tree_frame.pack(fill='both', expand=True, pady=10)
        
        self.tree = ttk.Treeview(self.tree_frame, columns=('Website', 'Username', 'Notes', 'Date'), show='tree headings')
        self.tree.heading('#0', text='ID')
        self.tree.heading('Website', text='Website')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Notes', text='Notes')
        self.tree.heading('Date', text='Created')
        
        self.tree.column('#0', width=50)
        self.tree.column('Website', width=200)
        self.tree.column('Username', width=150)
        self.tree.column('Notes', width=200)
        self.tree.column('Date', width=150)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(self.tree_frame, orient='vertical', command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(self.tree_frame, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.tree.pack(side='left', fill='both', expand=True)
        v_scrollbar.pack(side='right', fill='y')
        h_scrollbar.pack(side='bottom', fill='x')
        
        # Context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="View Password", command=self.view_password)
        self.context_menu.add_command(label="Copy Password", command=self.copy_password)
        self.context_menu.add_command(label="Edit", command=self.edit_password)
        self.context_menu.add_command(label="Delete", command=self.delete_password)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", self.view_password)
        
        self.load_passwords()
    
    def show_context_menu(self, event):
        """Show context menu"""
        item = self.tree.selection()[0] if self.tree.selection() else None
        if item:
            self.context_menu.post(event.x_root, event.y_root)
    
    def show_add_password_dialog(self):
        """Show add password dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Password")
        dialog.geometry("400x300")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill='both', expand=True)
        
        ttk.Label(frame, text="Website:").pack(anchor='w')
        website_entry = ttk.Entry(frame, width=40)
        website_entry.pack(fill='x', pady=(0, 10))
        
        ttk.Label(frame, text="Username:").pack(anchor='w')
        username_entry = ttk.Entry(frame, width=40)
        username_entry.pack(fill='x', pady=(0, 10))
        
        ttk.Label(frame, text="Password:").pack(anchor='w')
        password_frame = ttk.Frame(frame)
        password_frame.pack(fill='x', pady=(0, 10))
        password_entry = ttk.Entry(password_frame, show="*", width=30)
        password_entry.pack(side='left', fill='x', expand=True)
        ttk.Button(password_frame, text="Generate", 
                  command=lambda: self.generate_password_for_entry(password_entry)).pack(side='right', padx=(5, 0))
        
        ttk.Label(frame, text="Notes (optional):").pack(anchor='w')
        notes_entry = tk.Text(frame, height=4, width=40)
        notes_entry.pack(fill='x', pady=(0, 10))
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill='x')
        
        ttk.Button(button_frame, text="Save", 
                  command=lambda: self.save_password(website_entry.get(), username_entry.get(), 
                                                   password_entry.get(), notes_entry.get(1.0, tk.END).strip(), dialog)).pack(side='right', padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", 
                  command=dialog.destroy).pack(side='right')
        
        website_entry.focus()
    
    def generate_password_for_entry(self, entry_widget):
        """Generate password and insert into entry widget"""
        password = self.generate_secure_password()
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, password)
    
    def generate_secure_password(self, length=16):
        """Generate a secure random password"""
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password
    
    def generate_password(self):
        """Show password generator dialog"""
        password = self.generate_secure_password()
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Generated Password")
        dialog.geometry("400x200")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill='both', expand=True)
        
        ttk.Label(frame, text="Generated Password:", font=('Arial', 12, 'bold')).pack(pady=10)
        
        password_var = tk.StringVar(value=password)
        password_entry = ttk.Entry(frame, textvariable=password_var, width=40, font=('Arial', 11))
        password_entry.pack(pady=10)
        password_entry.select_range(0, tk.END)
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Copy to Clipboard", 
                  command=lambda: self.copy_to_clipboard(password)).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Generate New", 
                  command=lambda: password_var.set(self.generate_secure_password())).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Close", 
                  command=dialog.destroy).pack(side='left', padx=5)
    
    def save_password(self, website, username, password, notes, dialog):
        """Save password to database"""
        if not website or not username or not password:
            messagebox.showerror("Error", "Website, username, and password are required!")
            return
        
        # Encrypt password
        encrypted_password = self.cipher_suite.encrypt(password.encode())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO credentials (website, username, password, notes) VALUES (?, ?, ?, ?)",
                      (website, username, encrypted_password, notes))
        conn.commit()
        conn.close()
        
        messagebox.showinfo("Success", "Password saved successfully!")
        dialog.destroy()
        self.load_passwords()
    
    def load_passwords(self):
        """Load passwords from database"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, website, username, notes, created_date FROM credentials ORDER BY website")
        
        for row in cursor.fetchall():
            id_val, website, username, notes, created_date = row
            # Format date
            date_str = created_date.split()[0] if created_date else ""
            self.tree.insert("", "end", text=str(id_val), 
                           values=(website, username, notes[:50] + "..." if len(notes) > 50 else notes, date_str))
        
        conn.close()
    
    def filter_passwords(self):
        """Filter passwords based on search term"""
        search_term = self.search_var.get().lower()
        
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, website, username, notes, created_date FROM credentials ORDER BY website")
        
        for row in cursor.fetchall():
            id_val, website, username, notes, created_date = row
            # Check if search term matches website, username, or notes
            if (search_term in website.lower() or 
                search_term in username.lower() or 
                search_term in notes.lower()):
                
                date_str = created_date.split()[0] if created_date else ""
                self.tree.insert("", "end", text=str(id_val), 
                               values=(website, username, notes[:50] + "..." if len(notes) > 50 else notes, date_str))
        
        conn.close()
    
    def view_password(self, event=None):
        """View selected password"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password to view!")
            return
        
        item = selection[0]
        password_id = self.tree.item(item, "text")
        
        # Get password from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT website, username, password, notes FROM credentials WHERE id = ?", (password_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            messagebox.showerror("Error", "Password not found!")
            return
        
        website, username, encrypted_password, notes = result
        
        # Decrypt password
        try:
            decrypted_password = self.cipher_suite.decrypt(encrypted_password).decode()
        except:
            messagebox.showerror("Error", "Failed to decrypt password!")
            return
        
        # Show password dialog
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Password for {website}")
        dialog.geometry("450x300")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill='both', expand=True)
        
        ttk.Label(frame, text="Website:", font=('Arial', 10, 'bold')).pack(anchor='w')
        ttk.Label(frame, text=website, font=('Arial', 10)).pack(anchor='w', pady=(0, 10))
        
        ttk.Label(frame, text="Username:", font=('Arial', 10, 'bold')).pack(anchor='w')
        ttk.Label(frame, text=username, font=('Arial', 10)).pack(anchor='w', pady=(0, 10))
        
        ttk.Label(frame, text="Password:", font=('Arial', 10, 'bold')).pack(anchor='w')
        password_frame = ttk.Frame(frame)
        password_frame.pack(fill='x', pady=(0, 10))
        
        self.show_password_var = tk.BooleanVar()
        password_entry = ttk.Entry(password_frame, width=30, font=('Arial', 10))
        password_entry.pack(side='left', fill='x', expand=True)
        password_entry.insert(0, decrypted_password)
        password_entry.config(show="*")
        
        def toggle_password():
            if self.show_password_var.get():
                password_entry.config(show="")
            else:
                password_entry.config(show="*")
        
        ttk.Checkbutton(password_frame, text="Show", variable=self.show_password_var, 
                       command=toggle_password).pack(side='right', padx=(5, 0))
        
        if notes:
            ttk.Label(frame, text="Notes:", font=('Arial', 10, 'bold')).pack(anchor='w')
            notes_text = tk.Text(frame, height=4, width=40, font=('Arial', 9))
            notes_text.pack(fill='x', pady=(0, 10))
            notes_text.insert(1.0, notes)
            notes_text.config(state='disabled')
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill='x')
        
        ttk.Button(button_frame, text="Copy Password", 
                  command=lambda: self.copy_to_clipboard(decrypted_password)).pack(side='left', padx=(0, 5))
        ttk.Button(button_frame, text="Close", 
                  command=dialog.destroy).pack(side='right')
    
    def copy_password(self):
        """Copy selected password to clipboard"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password to copy!")
            return
        
        item = selection[0]
        password_id = self.tree.item(item, "text")
        
        # Get password from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM credentials WHERE id = ?", (password_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            messagebox.showerror("Error", "Password not found!")
            return
        
        encrypted_password = result[0]
        
        # Decrypt password
        try:
            decrypted_password = self.cipher_suite.decrypt(encrypted_password).decode()
            self.copy_to_clipboard(decrypted_password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        except:
            messagebox.showerror("Error", "Failed to decrypt password!")
    
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
    
    def edit_password(self):
        """Edit selected password"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password to edit!")
            return
        
        item = selection[0]
        password_id = self.tree.item(item, "text")
        
        # Get current data
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT website, username, password, notes FROM credentials WHERE id = ?", (password_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            messagebox.showerror("Error", "Password not found!")
            return
        
        website, username, encrypted_password, notes = result
        
        # Decrypt password
        try:
            decrypted_password = self.cipher_suite.decrypt(encrypted_password).decode()
        except:
            messagebox.showerror("Error", "Failed to decrypt password!")
            return
        
        # Show edit dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Password")
        dialog.geometry("400x300")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill='both', expand=True)
        
        ttk.Label(frame, text="Website:").pack(anchor='w')
        website_entry = ttk.Entry(frame, width=40)
        website_entry.pack(fill='x', pady=(0, 10))
        website_entry.insert(0, website)
        
        ttk.Label(frame, text="Username:").pack(anchor='w')
        username_entry = ttk.Entry(frame, width=40)
        username_entry.pack(fill='x', pady=(0, 10))
        username_entry.insert(0, username)
        
        ttk.Label(frame, text="Password:").pack(anchor='w')
        password_frame = ttk.Frame(frame)
        password_frame.pack(fill='x', pady=(0, 10))
        password_entry = ttk.Entry(password_frame, show="*", width=30)
        password_entry.pack(side='left', fill='x', expand=True)
        password_entry.insert(0, decrypted_password)
        ttk.Button(password_frame, text="Generate", 
                  command=lambda: self.generate_password_for_entry(password_entry)).pack(side='right', padx=(5, 0))
        
        ttk.Label(frame, text="Notes (optional):").pack(anchor='w')
        notes_entry = tk.Text(frame, height=4, width=40)
        notes_entry.pack(fill='x', pady=(0, 10))
        notes_entry.insert(1.0, notes)
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill='x')
        
        def update_password():
            new_website = website_entry.get()
            new_username = username_entry.get()
            new_password = password_entry.get()
            new_notes = notes_entry.get(1.0, tk.END).strip()
            
            if not new_website or not new_username or not new_password:
                messagebox.showerror("Error", "Website, username, and password are required!")
                return
            
            # Encrypt new password
            encrypted_new_password = self.cipher_suite.encrypt(new_password.encode())
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("UPDATE credentials SET website=?, username=?, password=?, notes=? WHERE id=?",
                          (new_website, new_username, encrypted_new_password, new_notes, password_id))
            conn.commit()
            conn.close()
            
            messagebox.showinfo("Success", "Password updated successfully!")
            dialog.destroy()
            self.load_passwords()
        
        ttk.Button(button_frame, text="Update", command=update_password).pack(side='right', padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side='right')
    
    def delete_password(self):
        """Delete selected password"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password to delete!")
            return
        
        item = selection[0]
        password_id = self.tree.item(item, "text")
        website = self.tree.item(item, "values")[0]
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the password for {website}?"):
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM credentials WHERE id = ?", (password_id,))
            conn.commit()
            conn.close()
            
            messagebox.showinfo("Success", "Password deleted successfully!")
            self.load_passwords()
    
    def search_passwords(self):
        """Focus on search entry"""
        self.search_entry.focus()
    
    def refresh_list(self):
        """Refresh password list"""
        self.search_var.set("")
        self.load_passwords()
    
    def logout(self):
        """Logout and return to login screen"""
        self.master_password = None
        self.cipher_suite = None
        self.show_login_screen()
    
    def clear_window(self):
        """Clear all widgets from window"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

def main():
    """Main function to run the password manager"""
    try:
        app = PasswordManager()
        app.run()
    except Exception as e:
        print(f"An error occurred: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
